"""`session`: start -> hold -> stop, rollback on every failure, stop and panic.

Nothing here touches the system: FakeBackend, a fake tunnel, a fake kill
switch, a fake audit, a fake clock, and a journal under tmp_path. The only
real modules exercised are the journal, the detection logic and the config
validator (against made-up config files from documentation address ranges).
"""
import os
import signal
import subprocess
import types
from pathlib import Path

import pytest

from rotator import cli, detect, journal, killswitch, session, state, tunnel
from rotator.backends.base import BackendError
from tests.fakes import FakeBackend

ORIGINAL_MAC = "aa:bb:cc:dd:ee:ff"
ORIGINAL_NAMES = {"ComputerName": "Real Mac", "LocalHostName": "Real-Mac", "HostName": None}
ORIGINAL_INBOUND = {"global": False, "blockall": False, "stealth": False}
GATEWAY = "192.168.1.1"
GATEWAY_MAC = "02:00:00:00:00:01"
FAKE_KEY = "A" * 43 + "="
TUNNEL_IF = "utun7"

CONFIG = """[Interface]
PrivateKey = {key}
Address = 10.0.0.2/32, fd00::2/128
DNS = 10.64.0.1

[Peer]
PublicKey = {key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint}
PersistentKeepalive = 25
"""

# Newest change first. The kill switch went up first, so it comes down last:
# the tunnel, address and names are put back while it still blocks traffic.
UNDO_ALL = [
    "tunnel.down:nir-fallback", "tunnel.down:nir", "undo:mac", "undo:hostname",
    "undo:inbound", "undo:pf_token", "undo:killswitch",
]


class Boom(BackendError):
    pass


class World:
    """Everything a session touches, faked, with one shared event log."""

    def __init__(self):
        self.events: list[str] = []
        self.journal_at: dict[str, list[str]] = {}
        self.fail_on: set[str] = set()
        self.notes: list[tuple[str, str]] = []
        self.now = 1000.0
        self.ticks = 0
        self.on_tick = lambda n: None
        self.enter_calls: list[float] = []
        self.pending_at_audit: list[dict] = []
        self.audit_ok = True
        self.audit_contexts: list = []
        self.audit_killswitch = None

    def act(self, name: str) -> None:
        """Log a step, note what the journal held when it ran, maybe fail."""
        self.events.append(name)
        self.journal_at.setdefault(name, [e["kind"] for e in reversed(journal.pending())])
        if name in self.fail_on:
            self.fail_on.discard(name)
            raise Boom(f"boom at {name}")

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.ticks += 1
        self.on_tick(self.ticks)

    def notifier(self, title: str, message: str) -> None:
        self.notes.append((title, message))

    def wait_enter(self, seconds, clock, sleep) -> bool:
        self.enter_calls.append(seconds)
        self.act("portal_wait")
        return True

    def undone(self) -> list[str]:
        return [e for e in self.events if e.startswith(("undo:", "tunnel.down"))]


class RecBackend(FakeBackend):
    def __init__(self, world: World, **kwargs):
        kwargs.setdefault("mac", ORIGINAL_MAC)
        kwargs.setdefault("gateway_ip", GATEWAY)
        kwargs.setdefault("neigh", {GATEWAY: {GATEWAY_MAC}})
        kwargs.setdefault("dns", [GATEWAY])
        super().__init__(**kwargs)
        self.world = world
        self.fail_neighbours = False

    def harden_inbound(self):
        self.world.act("harden")
        return super().harden_inbound()

    def restore_inbound(self, previous):
        self.world.act("undo:inbound")
        super().restore_inbound(previous)

    def set_hostname(self, names):
        self.world.act("undo:hostname" if names == ORIGINAL_NAMES else "hostname")
        super().set_hostname(names)

    def set_mac(self, m):
        self.world.act("undo:mac" if m == ORIGINAL_MAC else "mac")
        super().set_mac(m)

    def neighbours(self):
        if self.fail_neighbours:
            self.fail_neighbours = False
            raise Boom("boom at baseline")
        return super().neighbours()


class _FakeRules:
    def __init__(self, world: World):
        self.world = world
        self.loaded = False
        self.loads: list[tuple[str, dict | None]] = []
        self.unloaded_with: list[dict] = []
        self.released: list[str] = []

    def build_rules(self, iface, tunnel_if, endpoints, allow_portal, *, silent=False):
        if silent:
            return f"iface={iface} SILENT"
        return f"iface={iface} tunnel={tunnel_if} endpoints={sorted(endpoints)} portal={allow_portal}"

    def load(self, rules, undo=None):
        self.loads.append((rules, undo))
        self.world.act(f"ks.load#{len(self.loads)}")
        self.loaded = True
        return self.undo_info()

    def unload(self, undo):
        self.unloaded_with.append(dict(undo))
        self.world.act("undo:killswitch")
        self.loaded = False
        return []

    def is_loaded(self):
        return self.loaded


class FakeKillSwitch(_FakeRules):
    """Shaped like the macOS module: an anchor and a pf enable token."""
    ANCHOR = "test/anchor"

    def undo_info(self):
        return {"anchor": self.ANCHOR, "token": "42"}

    def release_token(self, token):
        self.released.append(token)
        self.world.act("undo:pf_token")
        return []

    def drop_states(self, iface):
        self.world.act(f"ks.drop_states:{iface}")


class FakeTableKillSwitch(_FakeRules):
    """Shaped like the Linux module: a table, no enable token."""
    TABLE = "test_table"

    def undo_info(self):
        return {"table": self.TABLE}


class FakeTunnel:
    def __init__(self, world: World):
        self.world = world
        self.up: set[str] = set()
        self.handshake = True
        self.use_fallback = False
        self.up_calls: list[tuple] = []

    def up_with_fallback(self, primary, fallback=None, timeout=15):
        self.up_calls.append((primary, fallback))
        self.world.act("tunnel.up")
        used = fallback if self.use_fallback else primary
        self.up.add(used)
        return used, TUNNEL_IF

    def down(self, config_path):
        name = Path(config_path).stem
        self.world.act(f"tunnel.down:{name}")
        if config_path not in self.up:
            raise BackendError(f"`wg-quick down {config_path}` failed: wg-quick: `{name}' is not a WireGuard interface")
        self.up.discard(config_path)

    def is_up(self, tunnel_if, max_age=180):
        return bool(self.up) and self.handshake


@pytest.fixture
def world(tmp_path, monkeypatch):
    w = World()
    w.tmp = tmp_path
    monkeypatch.setattr(journal, "journal_path", lambda: tmp_path / "db" / "journal.jsonl")
    monkeypatch.setattr(journal, "_UNDO", dict(journal._UNDO))
    monkeypatch.setattr(state, "_state_path", lambda: tmp_path / "state.json")
    for var in ("SUDO_USER", "SUDO_UID", "SUDO_GID", "STRICT", "STRICT_ON"):
        monkeypatch.delenv(var, raising=False)

    w.backend = RecBackend(w)
    w.factory = lambda interface: {"en0": w.backend}[interface]

    w.ks = FakeKillSwitch(w)
    monkeypatch.setattr(killswitch, "platform_module", lambda: w.ks)

    w.tunnel = FakeTunnel(w)
    monkeypatch.setattr(tunnel, "up_with_fallback", w.tunnel.up_with_fallback)
    monkeypatch.setattr(tunnel, "down", w.tunnel.down)
    monkeypatch.setattr(tunnel, "is_up", w.tunnel.is_up)
    monkeypatch.setattr(session, "_tunnel_present", lambda path: False)

    def run_checks(ctx, *, runner=None, killswitch=None):
        w.audit_contexts.append(ctx)
        w.audit_killswitch = killswitch
        w.pending_at_audit = journal.pending()
        w.act("audit")
        return [("everything", w.audit_ok)]

    fake_audit = types.SimpleNamespace(
        AuditContext=lambda **kwargs: types.SimpleNamespace(**kwargs),
        run_checks=run_checks,
        format_table=lambda results: "AUDIT TABLE",
        all_ok=lambda results: w.audit_ok,
    )
    monkeypatch.setattr(session, "_audit_module", lambda: fake_audit)

    monkeypatch.setattr(session, "_is_root", lambda: True)
    monkeypatch.setattr(session, "_have", lambda command: True)
    monkeypatch.setattr(session, "default_route_tunnel", lambda physical, runner=None: None)

    w.config = _write_config(tmp_path / "nir.conf", "192.0.2.10:51820")
    w.fallback = _write_config(tmp_path / "nir-fallback.conf", "192.0.2.20:443")
    return w


def _write_config(path: Path, endpoint: str, mode: int = 0o600) -> str:
    path.write_text(CONFIG.format(key=FAKE_KEY, endpoint=endpoint))
    path.chmod(mode)
    return str(path)


def options(world, **overrides) -> session.Options:
    values = dict(interface="en0", duration=9.0, config=world.config, fallback=world.fallback, poll=3.0)
    values.update(overrides)
    return session.Options(**values)


def start(world, **overrides) -> int:
    return session.start(
        options(world, **overrides), backend_factory=world.factory, notifier=world.notifier,
        clock=world.clock, sleep=world.sleep, wait_enter=world.wait_enter, environ={})


def assert_restored(world) -> None:
    assert journal.pending() == []
    assert not journal.journal_path().exists()
    assert world.backend.mac == ORIGINAL_MAC
    assert world.backend.hostnames == ORIGINAL_NAMES
    assert world.backend.inbound == ORIGINAL_INBOUND
    assert world.ks.loaded is False
    assert world.tunnel.up == set()
    assert not session.status_path().exists()
    assert session.running_pid() is None


# ------------------------------------------------------------ (a) happy path

def test_happy_path_order_of_operations(world):
    assert start(world) == 0
    setup = world.events[:world.events.index("audit") + 1]
    assert setup == ["ks.load#1", "harden", "hostname", "mac", "tunnel.up", "ks.load#2", "audit"]
    assert world.undone() == UNDO_ALL
    assert world.events[-len(UNDO_ALL):] == UNDO_ALL
    assert_restored(world)


def test_happy_path_kill_switch_rules(world):
    start(world)
    (first, first_undo), (second, second_undo) = world.ks.loads
    # Before the tunnel exists: no tunnel interface, both endpoints, no portal.
    assert "tunnel=None" in first and "portal=False" in first
    assert "('192.0.2.10', 51820)" in first and "('192.0.2.20', 443)" in first
    assert first_undo is None
    # Reload with the real interface, reusing the first load's undo (and token).
    assert f"tunnel={TUNNEL_IF}" in second and "portal=False" in second
    assert second_undo == {"anchor": "test/anchor", "token": "42"}
    assert world.tunnel.up_calls == [(world.config, world.fallback)]


def test_happy_path_journal_contents(world):
    start(world)
    oldest_first = list(reversed(world.pending_at_audit))
    assert [(e["kind"], e["undo"]) for e in oldest_first] == [
        ("killswitch", {"platform_undo": {"anchor": "test/anchor"}}),
        ("pf_token", {"anchor": "test/anchor", "token": "42"}),
        ("inbound", {"interface": "en0", "previous": ORIGINAL_INBOUND}),
        ("hostname", {"interface": "en0", "names": ORIGINAL_NAMES}),
        ("mac", {"interface": "en0", "mac": ORIGINAL_MAC}),
        ("tunnel", {"config_path": world.config}),
        ("tunnel", {"config_path": world.fallback}),
    ]


def test_every_step_is_journaled_before_it_acts(world):
    start(world)
    at = world.journal_at
    assert at["ks.load#1"] == ["killswitch"]  # nothing else changed yet, and no token yet
    assert at["harden"] == ["killswitch", "pf_token", "inbound"]
    assert at["hostname"] == ["killswitch", "pf_token", "inbound", "hostname"]
    assert at["mac"] == ["killswitch", "pf_token", "inbound", "hostname", "mac"]
    assert at["tunnel.up"][-3:] == ["mac", "tunnel", "tunnel"]


def test_kill_switch_undo_never_gets_the_token(world):
    start(world)
    assert world.ks.unloaded_with == [{"anchor": "test/anchor"}]
    assert world.ks.released == ["42"]


def test_session_changes_identity_and_passes_audit_context(world):
    seen = {}
    world.on_tick = lambda n: seen.update(
        mac=world.backend.mac, names=dict(world.backend.hostnames), inbound=dict(world.backend.inbound))
    start(world)
    assert seen["mac"] != ORIGINAL_MAC
    assert seen["names"]["ComputerName"] != "Real Mac" and seen["names"]["HostName"] is None
    assert seen["inbound"] == {"global": True, "blockall": True, "stealth": True}
    (ctx,) = world.audit_contexts
    assert ctx.backend is world.backend
    assert ctx.tunnel_if == TUNNEL_IF
    assert ctx.tunnel_dns == ("10.64.0.1",)
    assert ctx.original_mac == ORIGINAL_MAC
    assert ctx.original_hostnames == ORIGINAL_NAMES
    assert ctx.manage_inbound is True
    assert world.audit_killswitch is world.ks


def test_output_never_shows_key_or_original_identity(world, capsys):
    start(world)
    out = "".join(capsys.readouterr())
    assert "MAC address is now" in out and "AUDIT TABLE" in out
    for secret in (FAKE_KEY, ORIGINAL_MAC, "Real Mac", "Real-Mac"):
        assert secret not in out


def test_fallback_dns_and_single_config(world):
    world.tunnel.use_fallback = True
    assert start(world) == 0
    assert_restored(world)

    world.events.clear()
    world.tunnel.use_fallback = False
    assert start(world, fallback=None) == 0
    assert world.tunnel.up_calls[-1] == (world.config, None)
    assert [e for e in world.undone() if e.startswith("tunnel.down")] == ["tunnel.down:nir"]


def test_table_style_kill_switch_records_no_token(world, monkeypatch):
    world.ks = FakeTableKillSwitch(world)
    assert start(world) == 0
    kinds = [e["kind"] for e in world.pending_at_audit]
    assert "killswitch" in kinds and "pf_token" not in kinds
    assert world.ks.unloaded_with == [{"table": "test_table"}]
    assert_restored(world)


# -------------------------------------------------- (b) failure at each step

FAILURES = [
    # step that fails,       undo events expected, newest change first
    ("ks.load#1", UNDO_ALL[6:]),  # first load: no token recorded yet
    ("harden", UNDO_ALL[4:]),
    ("hostname", UNDO_ALL[3:]),
    ("mac", UNDO_ALL[2:]),
    ("network", UNDO_ALL[2:]),
    ("ks.load#2", UNDO_ALL[2:]),  # opening the portal window
    ("portal_wait", UNDO_ALL[2:]),
    ("ks.load#3", UNDO_ALL[2:]),  # the strict reload that closes the portal window
    ("tunnel.up", UNDO_ALL),
    ("ks.load#4", UNDO_ALL),  # reload with the real tunnel interface
    ("baseline", UNDO_ALL),
    ("audit", UNDO_ALL),
]


@pytest.mark.parametrize("step,expected", FAILURES, ids=[f[0] for f in FAILURES])
def test_failure_at_each_step_rolls_everything_back(world, step, expected):
    if step == "network":
        world.backend.gateway_ip = None
        error = session.SessionError
    elif step == "baseline":
        world.backend.fail_neighbours = True
        error = Boom
    else:
        world.fail_on.add(step)
        error = Boom

    with pytest.raises(error):
        start(world, portal=True)

    # Each recorded change was undone exactly once, newest first.
    assert world.undone() == expected
    assert world.fail_on == set()
    if step == "network":
        world.backend.gateway_ip = GATEWAY
    assert_restored(world)
    # The kill switch is always the last thing removed, and exactly once.
    assert world.events[-1] == "undo:killswitch"
    assert world.ks.unloaded_with == [{"anchor": "test/anchor"}]


@pytest.mark.parametrize("step", ["ks.load#1", "tunnel.up", "ks.load#2"])
def test_failure_without_portal_rolls_back(world, step):
    world.fail_on.add(step)
    with pytest.raises(Boom):
        start(world)
    assert_restored(world)
    assert world.undone() == (UNDO_ALL[6:] if step == "ks.load#1" else UNDO_ALL)


def test_ctrl_c_during_setup_rolls_back_and_propagates(world):
    def interrupted(seconds, clock, sleep):
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        session.start(options(world, portal=True), backend_factory=world.factory,
                      notifier=world.notifier, clock=world.clock, sleep=world.sleep,
                      wait_enter=interrupted, environ={})
    assert world.undone() == UNDO_ALL[2:]
    assert_restored(world)


# ------------------------------------------------------------ (c) audit fails

def test_audit_failure_rolls_back(world, capsys):
    world.audit_ok = False
    with pytest.raises(session.SessionError, match="audit"):
        start(world)
    assert world.undone() == UNDO_ALL
    assert_restored(world)
    assert "AUDIT TABLE" in capsys.readouterr().out
    assert world.ticks == 0  # never reached the hold loop


# ----------------------------------------------------------------- portal

def test_portal_window_then_strict_rules(world, capsys):
    assert start(world, portal=True, portal_seconds=45) == 0
    setup = world.events[:world.events.index("audit") + 1]
    assert setup == ["ks.load#1", "harden", "hostname", "mac", "ks.load#2", "portal_wait",
                     "ks.load#3", "tunnel.up", "ks.load#4", "audit"]
    rules = [r for r, _ in world.ks.loads]
    # Strict until the new identity is in place; the exception only for the window.
    assert "portal=False" in rules[0] and "tunnel=None" in rules[0]
    assert "portal=True" in rules[1] and "tunnel=None" in rules[1]
    assert "portal=False" in rules[2] and "tunnel=None" in rules[2]
    assert "portal=False" in rules[3] and f"tunnel={TUNNEL_IF}" in rules[3]
    assert world.enter_calls == [45]
    assert "NOT protected" in capsys.readouterr().out
    assert_restored(world)


def test_portal_strict_rules_reloaded_even_when_window_fails(world):
    world.fail_on.add("portal_wait")
    with pytest.raises(Boom):
        start(world, portal=True)
    assert "portal=True" in world.ks.loads[1][0]
    assert "portal=False" in world.ks.loads[2][0]
    assert world.events.index("ks.load#3") < world.events.index("undo:killswitch")
    assert "tunnel.up" not in world.events


def test_wait_for_enter_times_out_without_a_terminal(world, monkeypatch):
    monkeypatch.setattr(session.sys, "stdin", None)
    assert session.wait_for_enter(5, world.clock, world.sleep) is False
    assert world.now == 1005.0


# -------------------------------------------------------------- (d) go silent

def spoof_gateway(world, at_tick: int, stop_at: int):
    def on_tick(n):
        if n == at_tick:
            world.backend.neigh[GATEWAY] = {"02:00:00:00:00:99"}
        if n == stop_at:
            raise KeyboardInterrupt
    world.on_tick = on_tick


def test_strict_finding_stops_tunnel_but_keeps_kill_switch(world):
    snapshots = {}

    def on_tick(n):
        if n == 2:
            world.backend.neigh[GATEWAY] = {"02:00:00:00:00:99"}
        if n == 8:
            snapshots["status"] = session.status()
            snapshots["loaded"] = world.ks.loaded
            snapshots["tunnel"] = set(world.tunnel.up)
            snapshots["pending"] = [e["kind"] for e in journal.pending()]
        if n == 10:
            raise KeyboardInterrupt
    world.on_tick = on_tick

    assert start(world, duration=9.0) == 0  # duration ends at tick 3, long before tick 10
    # Poll 2 warns, poll 3 (second consecutive sighting) goes silent.
    assert len(world.notes) == 2
    assert detect.ARP_SPOOF_SUSPECTED in world.notes[0][1] and "Warning" in world.notes[0][1]
    assert "Strict mode" in world.notes[1][1]
    # While silent: tunnel down, kill switch still loaded, nothing rolled back,
    # and the session outlived its duration instead of reopening the network.
    assert snapshots["tunnel"] == set()
    assert snapshots["loaded"] is True
    assert "killswitch" in snapshots["pending"] and "mac" in snapshots["pending"]
    assert snapshots["status"]["silent"] is True
    assert snapshots["status"]["ends_at"] is None
    assert snapshots["status"]["tunnel_up"] is False
    assert snapshots["status"]["findings"] == [detect.ARP_SPOOF_SUSPECTED]
    down = world.events.index("tunnel.down:nir")
    assert down < world.events.index("undo:killswitch")
    assert "undo:killswitch" not in world.events[:down]
    # Right after the tunnel: the silent rules (no tunnel, no endpoints), same
    # token, and the states the old rules created are dropped.
    assert world.events[down + 1:down + 3] == ["ks.load#3", "ks.drop_states:en0"]
    rules, undo = world.ks.loads[2]
    assert rules == "iface=en0 SILENT"
    assert undo == {"anchor": "test/anchor", "token": "42"}
    # The stop afterwards still undoes everything; the dead tunnel is not an error.
    assert world.undone() == ["tunnel.down:nir"] + UNDO_ALL
    assert_restored(world)


def test_go_silent_reloads_kill_switch_even_when_tunnel_down_fails(world, capsys):
    def on_tick(n):
        if n == 1:
            world.backend.neigh[GATEWAY] = {"02:00:00:00:00:99"}
            world.fail_on.add("tunnel.down:nir")
        if n == 5:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    assert start(world, duration=3600.0) == 0
    down = world.events.index("tunnel.down:nir")
    assert world.events[down + 1:down + 3] == ["ks.load#3", "ks.drop_states:en0"]
    assert world.ks.loads[2][0] == "iface=en0 SILENT"
    assert "Could not stop the tunnel" in capsys.readouterr().out
    assert_restored(world)  # the stop afterwards takes the tunnel down for real


def test_go_silent_survives_a_failed_reload(world):
    def on_tick(n):
        if n == 1:
            world.backend.neigh[GATEWAY] = {"02:00:00:00:00:99"}
            world.fail_on.add("ks.load#3")
        if n == 5:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    assert start(world, duration=3600.0) == 0
    assert any("Could not tighten the kill switch" in m for _, m in world.notes)
    assert_restored(world)


def test_no_strict_only_warns(world):
    spoof_gateway(world, at_tick=1, stop_at=99)
    assert start(world, strict=False, duration=12.0) == 0
    assert len(world.notes) == 1 and "Warning" in world.notes[0][1]
    assert world.undone() == UNDO_ALL  # the tunnel was never stopped early


def test_strict_from_environment(world):
    spoof_gateway(world, at_tick=1, stop_at=99)
    code = session.start(options(world, duration=12.0), backend_factory=world.factory,
                         notifier=world.notifier, clock=world.clock, sleep=world.sleep,
                         wait_enter=world.wait_enter, environ={"STRICT": "0"})
    assert code == 0 and len(world.notes) == 1


def test_bad_strict_setting_refuses_before_any_change(world):
    with pytest.raises(session.SessionError, match="STRICT"):
        session.start(options(world), backend_factory=world.factory, notifier=world.notifier,
                      clock=world.clock, sleep=world.sleep, environ={"STRICT": "maybe"})
    assert world.events == []


def test_tunnel_down_warns_once_and_stays_closed(world):
    def on_tick(n):
        if n == 2:
            world.tunnel.handshake = False
    world.on_tick = on_tick
    assert start(world, duration=18.0) == 0
    down_notes = [m for _, m in world.notes if "tunnel is down" in m]
    assert len(down_notes) == 1
    assert world.events.count("undo:killswitch") == 1  # only at the final stop


def test_kill_switch_loss_is_reported(world):
    def on_tick(n):
        if n == 1:
            world.ks.loaded = False
    world.on_tick = on_tick
    start(world, duration=9.0)
    assert sum("kill switch rules are no longer loaded" in m for _, m in world.notes) == 1


def test_notifier_failure_does_not_end_the_session(world):
    def broken(title, message):
        raise RuntimeError("no display")
    spoof_gateway(world, at_tick=1, stop_at=99)
    code = session.start(options(world, strict=False), backend_factory=world.factory,
                         notifier=broken, clock=world.clock, sleep=world.sleep, environ={})
    assert code == 0
    assert_restored(world)


# ------------------------------------------------- (e) duration end / SIGTERM

def test_duration_end_rolls_back(world, capsys):
    assert start(world, duration=9.0, poll=3.0) == 0
    assert session.STOP_NOTICE in capsys.readouterr().out
    assert world.ticks == 3
    assert world.undone() == UNDO_ALL
    assert_restored(world)


def test_stop_notice_wording():
    assert session.STOP_NOTICE == (
        "Restoring your real hardware address and hostname. If you are still connected to "
        "the public network, it will see them: leave the network or turn Wi-Fi off first "
        "if that matters.")


def test_stop_notice_comes_before_the_first_undo(world, capsys, monkeypatch):
    printed = []
    monkeypatch.setattr(session, "_say", lambda message: printed.append(
        (message, len(world.undone()))))
    world.on_tick = lambda n: (_ for _ in ()).throw(KeyboardInterrupt)
    assert start(world, duration=3600.0) == 0
    assert (session.STOP_NOTICE, 0) in printed


def test_sigterm_rolls_back(world, capsys):
    before = signal.getsignal(signal.SIGTERM)

    def on_tick(n):
        if n == 2:
            os.kill(os.getpid(), signal.SIGTERM)
    world.on_tick = on_tick
    assert start(world, duration=3600.0) == 0
    assert world.ticks < 10  # ended on the signal, not after an hour of polls
    assert session.STOP_NOTICE in capsys.readouterr().out
    assert world.undone() == UNDO_ALL
    assert_restored(world)
    assert signal.getsignal(signal.SIGTERM) is before


def test_ctrl_c_in_hold_rolls_back(world):
    def on_tick(n):
        raise KeyboardInterrupt
    world.on_tick = on_tick
    assert start(world, duration=3600.0) == 0
    assert world.undone() == UNDO_ALL
    assert_restored(world)


def test_failed_undo_at_stop_is_reported_and_kept(world, capsys):
    world.on_tick = lambda n: world.fail_on.add("undo:mac") if n == 1 else None
    assert start(world) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out and "panic" in out and ORIGINAL_MAC not in out
    # Everything else was still undone; the failed entry waits for panic.
    assert [e["kind"] for e in journal.pending()] == ["mac"]
    assert world.events.count("undo:hostname") == 1 and world.events.count("undo:inbound") == 1
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert_restored(world)


# -------------------------------------------------------------- status file

def test_status_file_written_each_poll(world):
    seen = []

    def on_tick(n):
        path = session.status_path()
        seen.append((oct(path.stat().st_mode & 0o777), session.status()))
    world.on_tick = on_tick
    start(world, duration=9.0)
    modes, statuses = zip(*seen)
    assert set(modes) == {"0o600"}
    first = statuses[0]
    assert first["pid"] == os.getpid()
    assert first["started_at"] == 1000.0 and first["ends_at"] == 1009.0
    assert first["tunnel_if"] == TUNNEL_IF and first["tunnel_up"] is True
    assert first["silent"] is False and first["findings"] == []
    assert statuses[-1]["killswitch"] is True
    text = session.format_status(first, now=1003.0)
    assert "0h 00m 06s" in text and f"{TUNNEL_IF} up" in text and "loaded" in text
    assert FAKE_KEY not in str(statuses) and ORIGINAL_MAC not in str(statuses)


def test_status_reports_no_session(world):
    assert session.status() is None
    # A status file left by a dead process is not a running session.
    session.status_path().parent.mkdir(parents=True, exist_ok=True)
    session.status_path().write_text('{"pid": 99999999, "silent": false}')
    assert session.status() is None
    assert session.running_pid() is None


def test_format_status_states():
    silent = session.format_status({"pid": 1, "silent": True, "tunnel_if": "utun7"}, 0)
    assert "session stop" in silent and "blocked" in silent
    down = session.format_status(
        {"pid": 1, "ends_at": 7300, "tunnel_if": "utun7", "tunnel_up": False,
         "killswitch": False, "findings": ["arp_conflict"]}, 0)
    assert "2h 01m 40s" in down and "DOWN" in down and "NOT LOADED" in down and "arp_conflict" in down


def test_second_session_is_refused_while_one_runs(world):
    refused = []

    def on_tick(n):
        if n == 1:
            with pytest.raises(session.SessionError, match="already running"):
                start(world)
            refused.append(session.running_pid())
    world.on_tick = on_tick
    assert start(world) == 0
    assert refused == [os.getpid()]
    assert world.events.count("mac") == 1


# ---------------------------------------------------------- (f) stop / panic

def leave_crashed_session(world) -> None:
    """The journal and machine state a killed session would leave behind."""
    journal.record("killswitch", {"platform_undo": {"anchor": "test/anchor"}})
    journal.record("pf_token", {"anchor": "test/anchor", "token": "42"})
    world.ks.loaded = True
    journal.record("inbound", {"interface": "en0", "previous": ORIGINAL_INBOUND})
    world.backend.inbound = {key: True for key in ORIGINAL_INBOUND}
    journal.record("hostname", {"interface": "en0", "names": ORIGINAL_NAMES})
    world.backend.hostnames = {"ComputerName": "iPad", "LocalHostName": "iPad", "HostName": None}
    journal.record("mac", {"interface": "en0", "mac": ORIGINAL_MAC})
    world.backend.mac = "02:11:22:33:44:55"
    journal.record("tunnel", {"config_path": world.config})
    journal.record("tunnel", {"config_path": world.fallback})
    world.tunnel.up = {world.config}


def test_panic_after_crash_restores_everything(world, capsys):
    leave_crashed_session(world)
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert world.undone() == UNDO_ALL
    assert_restored(world)
    out = capsys.readouterr().out
    assert out.count("restored") == 7
    assert ORIGINAL_MAC not in out and "Real" not in out


def test_panic_keeps_going_past_a_failure_and_reports_it(world, capsys):
    leave_crashed_session(world)
    world.fail_on.add("undo:killswitch")
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 1
    # Everything older than the failed entry was still undone, once each.
    assert world.undone() == UNDO_ALL
    assert world.backend.mac == ORIGINAL_MAC
    assert world.backend.hostnames == ORIGINAL_NAMES
    assert world.backend.inbound == ORIGINAL_INBOUND
    assert [e["kind"] for e in journal.pending()] == ["killswitch"]
    out = capsys.readouterr().out
    assert "FAILED    kill switch rules: boom at undo:killswitch" in out
    assert out.count("restored") == 6
    # A second run finishes the job.
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert_restored(world)


def test_panic_with_nothing_to_undo(world, capsys):
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert "Nothing to undo" in capsys.readouterr().out


def test_panic_hides_original_identifiers_in_errors(world, capsys, monkeypatch):
    leave_crashed_session(world)

    def refuse(self, m):
        raise BackendError(f"en0 still reports 02:11:22:33:44:55 instead of {m}")
    monkeypatch.setattr(RecBackend, "set_mac", refuse)
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 1
    out = capsys.readouterr().out
    assert "instead of [original]" in out and ORIGINAL_MAC not in out


def test_panic_stops_a_live_session_first(world, monkeypatch):
    leave_crashed_session(world)
    alive = [4321, 4321, None]
    monkeypatch.setattr(session, "running_pid", lambda: alive.pop(0) if alive else None)
    sent = []
    code = session.panic(world.factory, kill=lambda pid, sig: sent.append((pid, sig)),
                         clock=world.clock, sleep=world.sleep)
    assert sent == [(4321, signal.SIGTERM)]
    assert code == 0 and journal.pending() == []


def test_panic_kills_a_session_that_will_not_stop(world, monkeypatch):
    leave_crashed_session(world)
    monkeypatch.setattr(session, "running_pid", lambda: 4321)
    sent = []
    code = session.panic(world.factory, kill=lambda pid, sig: sent.append((pid, sig)),
                         clock=world.clock, sleep=world.sleep, timeout=5)
    assert sent == [(4321, signal.SIGTERM), (4321, signal.SIGKILL)]
    assert code == 0 and journal.pending() == []


def test_stop_without_a_process_rolls_back_directly(world, capsys):
    leave_crashed_session(world)
    sent = []
    code = session.stop_running(world.factory, kill=lambda *a: sent.append(a),
                                clock=world.clock, sleep=world.sleep)
    assert code == 0 and sent == []
    assert session.STOP_NOTICE in capsys.readouterr().out
    assert world.undone() == UNDO_ALL
    assert_restored(world)


def test_stop_with_nothing_running_or_pending(world, capsys):
    assert session.stop_running(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert "nothing to undo" in capsys.readouterr().out
    assert world.events == []


def test_stop_signals_live_session_and_waits_for_its_rollback(world, monkeypatch):
    leave_crashed_session(world)
    alive = [4321, 4321, 4321]

    def running():
        if alive:
            return alive.pop(0)
        # The session process has finished its own rollback by now.
        for entry in journal.pending():
            journal.mark_undone(entry["id"])
        return None
    monkeypatch.setattr(session, "running_pid", running)
    sent = []
    code = session.stop_running(world.factory, kill=lambda pid, sig: sent.append((pid, sig)),
                                clock=world.clock, sleep=world.sleep)
    assert code == 0
    assert sent == [(4321, signal.SIGTERM)]
    assert world.events == []  # this process undid nothing itself


def test_stop_gives_up_after_timeout_without_touching_the_journal(world, monkeypatch, capsys):
    leave_crashed_session(world)
    monkeypatch.setattr(session, "running_pid", lambda: 4321)
    code = session.stop_running(world.factory, kill=lambda pid, sig: None,
                                clock=world.clock, sleep=world.sleep, timeout=30)
    assert code == 1
    assert world.now == pytest.approx(1030.0)
    assert world.events == [] and len(journal.pending()) == 7
    assert "panic" in capsys.readouterr().out


def test_stop_and_panic_need_root(world, monkeypatch):
    monkeypatch.setattr(session, "_is_root", lambda: False)
    for call in (session.stop_running, session.panic):
        with pytest.raises(session.SessionError, match="sudo"):
            call(world.factory)
    with pytest.raises(session.SessionError, match="sudo"):
        start(world)


# ------------------------------------------------------------- undo functions

def test_undo_kinds_are_registered():
    for kind in ("mac", "hostname", "inbound", "killswitch", "pf_token", "tunnel"):
        assert kind in journal._UNDO


def test_undo_functions_are_idempotent(world):
    leave_crashed_session(world)
    entries = journal.pending()
    for _ in range(2):  # a crash between undo and marker makes each run twice
        for entry in entries:
            journal.undo_entry(entry, world.factory)
    assert world.backend.mac == ORIGINAL_MAC
    assert world.backend.hostnames == ORIGINAL_NAMES
    assert world.backend.inbound == ORIGINAL_INBOUND
    assert world.ks.loaded is False and world.tunnel.up == set()


def test_undo_tunnel_tolerates_only_an_absent_tunnel(world, monkeypatch):
    def fails(config_path):
        raise BackendError("`wg-quick down x` failed: permission denied")
    monkeypatch.setattr(tunnel, "down", fails)
    session._undo_tunnel({"config_path": world.config}, world.factory)  # interface is gone
    monkeypatch.setattr(session, "_tunnel_present", lambda path: True)
    with pytest.raises(BackendError, match="permission denied"):
        session._undo_tunnel({"config_path": world.config}, world.factory)


def test_undo_killswitch_strips_a_token_and_pf_token_needs_support(world):
    session._undo_killswitch({"platform_undo": {"anchor": "a", "token": "7"}}, world.factory)
    assert world.ks.unloaded_with == [{"anchor": "a"}]
    world.ks = FakeTableKillSwitch(world)
    with pytest.raises(journal.JournalError):
        session._undo_pf_token({"anchor": "a", "token": "7"}, world.factory)


def test_go_silent_on_a_table_style_kill_switch_needs_no_state_drop(world):
    world.ks = FakeTableKillSwitch(world)

    def on_tick(n):
        if n == 1:
            world.backend.neigh[GATEWAY] = {"02:00:00:00:00:99"}
        if n == 5:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    assert start(world, duration=3600.0) == 0
    assert world.ks.loads[2][0] == "iface=en0 SILENT"
    assert not any("Could not tighten" in m for _, m in world.notes)


def test_macos_drop_states_touches_only_the_interface(monkeypatch):
    from rotator.killswitch import macos_pf
    calls = []

    def fake_run(cmd, **kwargs):
        assert isinstance(cmd, list) and not kwargs.get("shell")
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(macos_pf.subprocess, "run", fake_run)
    macos_pf.drop_states("en0")
    assert calls == [["pfctl", "-i", "en0", "-F", "states"]]
    with pytest.raises(ValueError):
        macos_pf.drop_states("en0 -F all")
    assert len(calls) == 1


def test_macos_release_token_releases_only_the_token(monkeypatch):
    from rotator.killswitch import macos_pf
    calls = []

    def fake_run(cmd, **kwargs):
        assert isinstance(cmd, list) and not kwargs.get("shell")
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1 if calls[-1][-1] == "999" else 0, "", "no such token")
    monkeypatch.setattr(macos_pf.subprocess, "run", fake_run)
    assert macos_pf.release_token("42") == []
    assert calls == [["pfctl", "-X", "42"]]
    (warning,) = macos_pf.release_token("999")  # already released: a warning, not an error
    assert "no such token" in warning
    with pytest.raises(BackendError):
        macos_pf.release_token("42; rm -rf /")
    assert len(calls) == 2


# ------------------------------------------------------------- (g) preflight

def test_preflight_refuses_with_pending_journal_entries(world):
    journal.record("mac", {"interface": "en0", "mac": ORIGINAL_MAC})
    with pytest.raises(session.SessionError, match="panic"):
        start(world)
    assert world.events == []  # nothing changed, and nothing was rolled back
    assert [e["kind"] for e in journal.pending()] == ["mac"]
    assert session.running_pid() is None


def test_preflight_refuses_without_wireguard_tools(world, monkeypatch):
    monkeypatch.setattr(session, "_have", lambda command: command != "wg-quick")
    with pytest.raises(session.SessionError, match="wg-quick"):
        start(world)
    assert world.events == []


@pytest.mark.parametrize("which", ["config", "fallback"])
def test_preflight_refuses_an_unsafe_config(world, which, capsys):
    path = Path(getattr(world, which))
    path.chmod(0o644)
    with pytest.raises(session.SessionError, match="0600") as raised:
        start(world)
    assert FAKE_KEY not in str(raised.value)
    assert world.events == [] and journal.pending() == []


def test_preflight_refuses_a_hostname_endpoint(world):
    world.config = _write_config(world.tmp / "host.conf", "vpn.example.net:51820")
    with pytest.raises(session.SessionError, match="IP literal"):
        start(world)
    assert world.events == []


def test_preflight_refuses_tunnel_dns_on_the_local_network(world):
    world.backend.gateway_ip = "10.64.0.1"  # same address as the config's DNS
    with pytest.raises(session.SessionError, match="local network"):
        start(world)
    assert world.events == []


def test_preflight_refuses_when_another_tunnel_has_the_default_route(world, monkeypatch):
    monkeypatch.setattr(session, "default_route_tunnel", lambda physical, runner=None: "utun4")
    with pytest.raises(session.SessionError, match="utun4"):
        start(world)
    assert world.events == []


def test_preflight_refuses_bad_numbers(world):
    for bad in ({"duration": 0}, {"poll": 0}, {"portal_seconds": -1}):
        with pytest.raises(session.SessionError):
            start(world, **bad)
    assert world.events == []


def test_default_route_parsing():
    macos = "   route to: default\n    gateway: 192.168.1.1\n  interface: utun4\n      flags: <UP>\n"
    assert session.parse_default_route_interfaces(macos, "darwin") == ["utun4"]
    linux = ("default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
             "default dev wg0 table 51820 scope link\n"
             "192.168.1.0/24 dev wlan0 proto kernel scope link\n")
    assert session.parse_default_route_interfaces(linux, "linux") == ["wlan0", "wg0"]
    assert session.parse_default_route_interfaces("", "linux") == []


def test_default_route_tunnel_detection(monkeypatch):
    def runner_for(route_iface, wg_interfaces=""):
        def runner(*args, check=True):
            if args[0] == "wg":
                return wg_interfaces
            return f"  interface: {route_iface}\n"
        return runner
    monkeypatch.setattr(session.sys, "platform", "darwin")
    assert session.default_route_tunnel("en0", runner_for("en0")) is None
    assert session.default_route_tunnel("en0", runner_for("utun4")) == "utun4"
    assert session.default_route_tunnel("en0", runner_for("en7")) is None
    assert session.default_route_tunnel("en0", runner_for("corp0", "corp0\n")) == "corp0"


# ---------------------------------------------------------- (h) opt-out flags

def test_keep_hostname_skips_that_step(world):
    assert start(world, keep_hostname=True) == 0
    assert "hostname" not in world.events and "undo:hostname" not in world.events
    assert "hostname" not in [e["kind"] for e in world.pending_at_audit]
    assert world.backend.hostname_calls == []
    assert world.audit_contexts[0].original_hostnames is None
    assert "harden" in world.events
    assert_restored(world)


def test_keep_firewall_skips_that_step(world):
    assert start(world, keep_firewall=True) == 0
    assert "harden" not in world.events and "undo:inbound" not in world.events
    assert "inbound" not in [e["kind"] for e in world.pending_at_audit]
    assert world.audit_contexts[0].manage_inbound is False
    assert world.backend.inbound_calls == []
    assert "hostname" in world.events
    assert_restored(world)


def test_backend_with_no_inbound_settings_records_nothing(world):
    world.backend.inbound = {}  # as on Linux, where the kill switch drops inbound
    assert start(world) == 0
    assert "harden" not in world.events
    assert "inbound" not in [e["kind"] for e in world.pending_at_audit]


# -------------------------------------------------------- (i) duration parsing

@pytest.mark.parametrize("text,seconds", [
    ("90s", 90), ("15m", 900), ("2h", 7200), ("1H", 3600), (" 45 m ", 2700)])
def test_parse_duration(text, seconds):
    assert session.parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "90", "h", "1.5h", "-5m", "0s", "2d", "1h30m", "ten", None])
def test_parse_duration_rejects(text):
    with pytest.raises(ValueError):
        session.parse_duration(text)


# ------------------------------------------------------- (j) notifier escaping

def test_notify_command_macos_escapes_quotes_and_backslashes():
    command = session.build_notify_command('say "hi"', 'a\\b" & do shell script "x"\nnext', "darwin")
    assert command[:2] == ["osascript", "-e"] and len(command) == 3
    assert command[2] == (
        'display notification "a\\\\b\\" & do shell script \\"x\\" next" '
        'with title "say \\"hi\\""')
    # No unescaped quote is left to close the string early.
    body = command[2].replace("\\\\", "").replace('\\"', "")
    assert body.count('"') == 4


def test_notify_command_linux_and_unsupported():
    with_tool = session.build_notify_command("-t", "msg", "linux", which=lambda name: "/usr/bin/" + name)
    assert with_tool == ["notify-send", "--", "-t", "msg"]
    assert session.build_notify_command("t", "m", "linux", which=lambda name: None) is None
    assert session.build_notify_command("t", "m", "win32") is None


def test_notify_runs_without_a_shell_and_never_raises(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        raise OSError("no display")
    monkeypatch.setattr(session.subprocess, "run", fake_run)
    monkeypatch.setattr(session.sys, "platform", "darwin")
    session.notify("title", 'mess"age')  # must not raise
    (command, kwargs), = calls
    assert isinstance(command, list) and not kwargs.get("shell")


# ------------------------------------------------------------------------ CLI

def parse(*argv):
    return cli.build_parser().parse_args(list(argv))


def test_cli_session_start_defaults():
    args = parse("session", "start", "--duration", "2h")
    assert (args.command, args.session_command) == ("session", "start")
    assert args.duration == 7200
    assert args.portal is False and args.portal_seconds == 120
    assert args.strict is None
    assert args.keep_hostname is False and args.keep_firewall is False
    assert args.poll == 3


def test_cli_session_start_flags():
    args = parse("-i", "en1", "session", "start", "--duration", "15m", "--portal",
                 "--portal-seconds", "60", "--no-strict", "--keep-hostname", "--keep-firewall",
                 "--poll", "5")
    assert args.interface == "en1" and args.duration == 900
    assert args.portal is True and args.portal_seconds == 60
    assert args.strict is False and args.poll == 5
    assert args.keep_hostname is True and args.keep_firewall is True
    assert parse("session", "start", "--duration", "90s", "--strict").strict is True


def test_cli_session_start_requires_a_valid_duration(capsys):
    for argv in (["session", "start"], ["session", "start", "--duration", "soon"], ["session"]):
        with pytest.raises(SystemExit) as raised:
            parse(*argv)
        assert raised.value.code == 2
    assert "90s, 15m or 2h" in capsys.readouterr().err


def test_cli_other_new_subcommands():
    assert parse("session", "stop").session_command == "stop"
    assert parse("session", "status").session_command == "status"
    assert parse("audit").command == "audit"
    assert parse("panic").command == "panic"
    assert set(cli.COMMANDS) == {"status", "rotate", "restore", "watch", "session", "audit", "panic"}


def test_cli_existing_commands_unchanged():
    assert parse("rotate", "--mac", "02:00:00:00:00:01").mac == "02:00:00:00:00:01"
    assert parse("restore", "--hardware").hardware is True
    assert parse("watch", "--rotate-now").rotate_now is True


def test_cli_session_options_from_environment():
    args = parse("session", "start", "--duration", "2h", "--portal", "--no-strict")
    opts = cli.session_options(args, {"WG_CONFIG": " /etc/wireguard/nir.conf ", "WG_CONFIG_FALLBACK": ""})
    assert opts == session.Options(
        interface=args.interface, duration=7200.0, config="/etc/wireguard/nir.conf", fallback=None,
        portal=True, portal_seconds=120, strict=False, keep_hostname=False, keep_firewall=False, poll=3)
    opts = cli.session_options(args, {"WG_CONFIG": "/a/nir.conf", "WG_CONFIG_FALLBACK": "/a/nir2.conf"})
    assert opts.fallback == "/a/nir2.conf"


def test_cli_session_start_refuses_without_wg_config():
    args = parse("session", "start", "--duration", "2h")
    with pytest.raises(SystemExit) as raised:
        cli.session_options(args, {})
    assert "WG_CONFIG is not set" in str(raised.value.code)


def test_cli_session_start_runs_session(world, monkeypatch):
    monkeypatch.setattr(cli, "require_root", lambda: None)
    monkeypatch.setenv("WG_CONFIG", world.config)
    monkeypatch.delenv("WG_CONFIG_FALLBACK", raising=False)
    seen = {}

    def fake_start(opts, **kwargs):
        seen.update(options=opts, kwargs=kwargs)
        return 1
    monkeypatch.setattr(session, "start", fake_start)
    with pytest.raises(SystemExit) as raised:
        cli.cmd_session(world.backend, parse("session", "start", "--duration", "15m"))
    assert raised.value.code == 1
    assert seen["options"].config == world.config and seen["options"].duration == 900
    assert set(seen["kwargs"]) == {"backend_factory", "notifier", "clock", "sleep"}

    def refuses(opts, **kwargs):
        raise session.SessionError("not today")
    monkeypatch.setattr(session, "start", refuses)
    with pytest.raises(SystemExit) as raised:
        cli.cmd_session(world.backend, parse("session", "start", "--duration", "15m"))
    assert raised.value.code == "Error: not today"


def test_cli_session_status_and_stop(world, monkeypatch, capsys):
    monkeypatch.setattr(cli, "require_root", lambda: None)
    cli.cmd_session(world.backend, parse("session", "status"))
    assert "No session is running." in capsys.readouterr().out

    journal.record("mac", {"interface": "en0", "mac": ORIGINAL_MAC})
    world.backend.mac = "02:11:22:33:44:55"
    cli.cmd_session(world.backend, parse("session", "status"))
    out = capsys.readouterr().out
    assert "1 change(s)" in out and "panic" in out and ORIGINAL_MAC not in out

    monkeypatch.setattr(session, "status", lambda: {"pid": 7, "ends_at": 0, "tunnel_if": "utun7"})
    cli.cmd_session(world.backend, parse("session", "status"))
    assert "running (pid 7" in capsys.readouterr().out

    monkeypatch.setattr(session, "stop_running", lambda factory: 1)
    with pytest.raises(SystemExit) as raised:
        cli.cmd_session(world.backend, parse("session", "stop"))
    assert raised.value.code == 1


def test_cli_panic_exit_status(world, monkeypatch):
    monkeypatch.setattr(cli, "require_root", lambda: None)
    monkeypatch.setattr(session, "panic", lambda factory: 0)
    cli.cmd_panic(world.backend, parse("panic"))  # no SystemExit on success
    monkeypatch.setattr(session, "panic", lambda factory: 1)
    with pytest.raises(SystemExit) as raised:
        cli.cmd_panic(world.backend, parse("panic"))
    assert raised.value.code == 1


def test_audit_context_from_journal_and_status(world, monkeypatch):
    journal.record("hostname", {"interface": "en0", "names": ORIGINAL_NAMES})
    journal.record("mac", {"interface": "en0", "mac": ORIGINAL_MAC})
    journal.record("mac", {"interface": "en0", "mac": "02:aa:aa:aa:aa:aa"})  # a later change
    journal.record("mac", {"interface": "en9", "mac": "02:bb:bb:bb:bb:bb"})  # another interface
    monkeypatch.setattr(session, "status",
                        lambda: {"pid": 7, "tunnel_if": "utun7", "tunnel_dns": ["10.64.0.1"]})
    ctx = session.audit_context(world.backend)
    assert ctx.original_mac == ORIGINAL_MAC and ctx.original_hostnames == ORIGINAL_NAMES
    assert ctx.tunnel_if == "utun7" and ctx.tunnel_dns == ("10.64.0.1",)

    assert ctx.manage_inbound is False  # no inbound entry: --keep-firewall was used

    monkeypatch.setattr(session, "status", lambda: None)
    journal.record("inbound", {"interface": "en0", "previous": ORIGINAL_INBOUND})
    ctx = session.audit_context(world.backend)
    assert ctx.tunnel_if is None and ctx.tunnel_dns == ()
    assert ctx.manage_inbound is True


def test_audit_context_on_a_backend_without_inbound_settings(world, monkeypatch):
    monkeypatch.setattr(session, "status", lambda: None)
    world.backend.inbound = {}  # Linux: the kill switch is the inbound block
    assert session.audit_context(world.backend).manage_inbound is True


def test_audit_inbound_check_passes_when_not_managed():
    from rotator import audit
    backend = FakeBackend(inbound={"global": False, "blockall": False, "stealth": False})
    base = dict(backend=backend, tunnel_if=None, tunnel_dns=(), original_mac=None,
                original_hostnames=None)
    assert audit.AuditContext(**base).manage_inbound is True  # default: existing callers unchanged
    managed = audit.check_inbound_blocked(audit.AuditContext(**base), platform="darwin")
    assert managed.ok is False
    for platform in ("darwin", "linux"):
        kept = audit.check_inbound_blocked(
            audit.AuditContext(**base, manage_inbound=False), platform=platform)
        assert (kept.name, kept.ok, kept.detail) == ("inbound_blocked", True, "not managed this session")


def test_state_file_is_private(tmp_path, monkeypatch):
    path = tmp_path / "cfg" / "net-interface-rotator" / "state.json"
    monkeypatch.setattr(state, "_state_path", lambda: path)
    for var in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
        monkeypatch.delenv(var, raising=False)
    old_umask = os.umask(0o022)
    try:
        state.remember_original("en0", ORIGINAL_MAC)
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
        # A file left world-readable by an older version is tightened on the next write.
        path.chmod(0o644)
        state.remember_original("en1", "02:00:00:00:00:02")
        assert path.stat().st_mode & 0o777 == 0o600
    finally:
        os.umask(old_umask)
    assert state.original_mac("en0") == ORIGINAL_MAC


def test_cli_audit_prints_table_and_exits_1_on_failure(world, monkeypatch, capsys):
    import sys
    monkeypatch.setattr(cli, "require_root", lambda: None)
    verdict = {"ok": True}
    seen = []
    fake_audit = types.ModuleType("rotator.audit")
    fake_audit.AuditContext = lambda **kwargs: types.SimpleNamespace(**kwargs)
    fake_audit.run_checks = lambda ctx, **kwargs: seen.append(ctx) or ["result"]
    fake_audit.format_table = lambda results: "CHECK  PASS"
    fake_audit.all_ok = lambda results: verdict["ok"]
    monkeypatch.setitem(sys.modules, "rotator.audit", fake_audit)
    import rotator
    monkeypatch.setattr(rotator, "audit", fake_audit, raising=False)
    monkeypatch.setattr(session, "_audit_module", lambda: fake_audit)

    cli.cmd_audit(world.backend, parse("audit"))
    assert "CHECK  PASS" in capsys.readouterr().out
    assert seen[0].backend is world.backend and seen[0].tunnel_if is None

    verdict["ok"] = False
    with pytest.raises(SystemExit) as raised:
        cli.cmd_audit(world.backend, parse("audit"))
    assert raised.value.code == 1
