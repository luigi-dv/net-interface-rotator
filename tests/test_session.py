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
# the tunnel, DNS settings, address and names are put back while it still
# blocks traffic.
UNDO_ALL = [
    "tunnel.down:nir-fallback", "tunnel.down:nir", "undo:dns", "undo:mac", "undo:hostname",
    "undo:inbound", "undo:pf_token", "undo:killswitch",
]
LOCKDOWN = "iface=en0 LOCKDOWN"
SILENT = "iface=en0 SILENT"
DNS_SETTINGS = {
    "Wi-Fi": {"servers": [], "search": []},
    "USB 10/100/1000 LAN": {"servers": ["192.0.2.53", "192.0.2.54"], "search": ["example.test"]},
}


def undo_from(first: str) -> list[str]:
    """The undo events expected when ``first`` was the newest recorded change."""
    return UNDO_ALL[UNDO_ALL.index(first):]


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
        # A session no longer ends by itself, so the fake clock "presses
        # Ctrl-C" on this tick. "default": two ticks into each ``start(world)``.
        # None: the test stops the session another way.
        self.stop_at: int | str | None = "default"
        self.rules_at: dict[str, str | None] = {}
        self.commands: list[tuple] = []
        self.dns_reads = 0
        self.enter_calls: list[float] = []
        self.pending_at_audit: list[dict] = []
        self.audit_ok = True
        self.audit_contexts: list = []
        self.audit_killswitch = None

    def act(self, name: str) -> None:
        """Log a step, note what the journal held when it ran, maybe fail."""
        self.events.append(name)
        try:
            kinds = [e["kind"] for e in reversed(journal.pending())]
        except journal.JournalCorrupt:
            kinds = ["<corrupt>"]
        self.journal_at.setdefault(name, kinds)
        loads = getattr(getattr(self, "ks", None), "loads", [])
        self.rules_at.setdefault(name, loads[-1][0] if loads else None)
        if name in self.fail_on:
            self.fail_on.discard(name)
            raise Boom(f"boom at {name}")

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.ticks += 1
        assert self.ticks < 500, "runaway session loop"
        self.on_tick(self.ticks)
        if isinstance(self.stop_at, int) and self.ticks >= self.stop_at:
            raise KeyboardInterrupt

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

        self.check_error: Exception | None = None

    def build_rules(self, iface, tunnel_if, endpoints, allow_portal, *, silent=False,
                    allow_dhcp=True):
        if silent:
            return f"iface={iface} " + ("SILENT" if allow_dhcp else "LOCKDOWN")
        assert allow_dhcp
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
        if self.check_error is not None:
            error, self.check_error = self.check_error, None
            raise error
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

    new_token = None  # set to a string: pf was disabled and had to be enabled again

    def ensure_enabled(self):
        token, self.new_token = self.new_token, None
        return token


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

    # DNS settings: as on macOS, whatever this test machine is. No command runs.
    w.dns = {name: {k: list(v) for k, v in saved.items()} for name, saved in DNS_SETTINGS.items()}

    def read_dns_settings(runner=None):
        w.dns_reads += 1
        w.act("dns.read")
        return {name: {k: list(v) for k, v in saved.items()} for name, saved in w.dns.items()}

    def fake_run(*args, check=True, input=None):
        w.commands.append(args)
        return ""

    def undo_dns(undo, backend_factory):
        w.act("undo:dns")
        session._undo_dns(undo, backend_factory)

    monkeypatch.setattr(session, "_manages_dns", lambda: True)
    monkeypatch.setattr(session, "read_dns_settings", read_dns_settings)
    monkeypatch.setattr(session, "run", fake_run)
    journal._UNDO["dns"] = undo_dns

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
    # Where preflight puts its validated copies; only these are used afterwards.
    w.staged = str(tmp_path / "db" / "configs" / "nir.conf")
    w.staged_fallback = str(tmp_path / "db" / "configs" / "nir-fallback.conf")
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
    default_stop = world.stop_at == "default"
    if default_stop:
        world.stop_at = world.ticks + 2
    try:
        return session.start(
            options(world, **overrides), backend_factory=world.factory, notifier=world.notifier,
            clock=world.clock, sleep=world.sleep, wait_enter=world.wait_enter, environ={})
    finally:
        if default_stop:
            world.stop_at = "default"


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
    assert not session.staging_dir().exists()  # the staged configs hold the key


# ------------------------------------------------------------ (a) happy path

def test_happy_path_order_of_operations(world):
    assert start(world) == 0
    setup = world.events[:world.events.index("audit") + 1]
    assert setup == ["ks.load#1", "harden", "hostname", "mac", "ks.load#2", "dns.read",
                     "tunnel.up", "ks.load#3", "audit"]
    assert world.undone() == UNDO_ALL
    assert world.events[-len(UNDO_ALL):] == UNDO_ALL
    assert_restored(world)


def test_happy_path_kill_switch_rules(world):
    start(world)
    (first, first_undo), (second, second_undo), (third, third_undo) = world.ks.loads
    # Lockdown first: nothing but loopback, not even DHCP.
    assert first == LOCKDOWN and first_undo is None
    # After the identity change: no tunnel interface, both endpoints, no portal.
    assert "tunnel=None" in second and "portal=False" in second
    assert "('192.0.2.10', 51820)" in second and "('192.0.2.20', 443)" in second
    # Reload with the real interface, reusing the first load's undo (and token).
    assert f"tunnel={TUNNEL_IF}" in third and "portal=False" in third
    assert second_undo == third_undo == {"anchor": "test/anchor", "token": "42"}
    assert world.tunnel.up_calls == [(world.staged, world.staged_fallback)]


def test_identity_changes_only_under_lockdown(world):
    """The host name and MAC address change while nothing but loopback can
    pass; DHCP opens only afterwards, under the new identity."""
    start(world)
    for step in ("harden", "hostname", "mac"):
        assert world.rules_at[step] == LOCKDOWN
    assert world.events.index("mac") < world.events.index("ks.load#2")
    assert "tunnel=None" in world.rules_at["dns.read"]
    assert "tunnel=None" in world.rules_at["tunnel.up"]
    assert f"tunnel={TUNNEL_IF}" in world.rules_at["audit"]


def test_happy_path_journal_contents(world):
    start(world)
    oldest_first = list(reversed(world.pending_at_audit))
    assert [(e["kind"], e["undo"]) for e in oldest_first] == [
        ("killswitch", {"platform_undo": {"anchor": "test/anchor"}}),
        ("pf_token", {"anchor": "test/anchor", "token": "42"}),
        ("inbound", {"interface": "en0", "previous": ORIGINAL_INBOUND}),
        ("hostname", {"interface": "en0", "names": ORIGINAL_NAMES}),
        ("mac", {"interface": "en0", "mac": ORIGINAL_MAC}),
        ("dns", {"services": DNS_SETTINGS}),
        ("tunnel", {"config_path": world.staged}),
        ("tunnel", {"config_path": world.staged_fallback}),
    ]


def test_every_step_is_journaled_before_it_acts(world):
    start(world)
    at = world.journal_at
    assert at["ks.load#1"] == ["killswitch"]  # nothing else changed yet, and no token yet
    assert at["harden"] == ["killswitch", "pf_token", "inbound"]
    assert at["hostname"] == ["killswitch", "pf_token", "inbound", "hostname"]
    assert at["mac"] == ["killswitch", "pf_token", "inbound", "hostname", "mac"]
    assert at["tunnel.up"][-4:] == ["mac", "dns", "tunnel", "tunnel"]


def test_only_the_staged_configs_are_used(world):
    """Preflight copies each config once; the user's own files are never
    read again, so swapping them afterwards changes nothing."""
    seen = {}

    def on_tick(n):
        seen["staged"] = sorted(p.name for p in session.staging_dir().iterdir())
        seen["modes"] = {oct(p.stat().st_mode & 0o777) for p in session.staging_dir().iterdir()}
        seen["dir"] = oct(session.staging_dir().stat().st_mode & 0o777)
        Path(world.config).unlink()  # the original is gone: nothing may still need it
    world.on_tick = on_tick
    world.stop_at = 1
    assert start(world) == 0
    assert seen == {"staged": ["nir-fallback.conf", "nir.conf"], "modes": {"0o600"}, "dir": "0o700"}
    paths = [e["undo"]["config_path"] for e in world.pending_at_audit if e["kind"] == "tunnel"]
    assert sorted(paths) == sorted([world.staged, world.staged_fallback])
    assert world.config not in str(world.pending_at_audit)
    assert_restored(world)


def test_preflight_tells_when_the_network_has_already_seen_the_device(world, capsys):
    start(world)
    out = capsys.readouterr().out
    assert out.count(session.SEEN_NOTICE) == 1
    assert out.index(session.SEEN_NOTICE) < out.index("Kill switch is up")
    # Not yet on a network at preflight: nothing to say. (It joins during the wait.)
    world.backend.gateway_ip = None
    world.stop_at = None
    world.ticks = 0

    def on_tick(n):
        world.backend.gateway_ip = GATEWAY
        if n >= 3:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    assert start(world) == 0
    assert session.SEEN_NOTICE not in capsys.readouterr().out


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
    assert world.tunnel.up_calls[-1] == (world.staged, None)
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
    ("ks.load#1", undo_from("undo:killswitch")),  # lockdown load: no token recorded yet
    ("harden", undo_from("undo:inbound")),
    ("hostname", undo_from("undo:hostname")),
    ("mac", undo_from("undo:mac")),
    ("ks.load#2", undo_from("undo:mac")),  # the strict reload after the identity change
    ("network", undo_from("undo:mac")),
    ("ks.load#3", undo_from("undo:mac")),  # opening the portal window
    ("portal_wait", undo_from("undo:mac")),
    ("ks.load#4", undo_from("undo:mac")),  # the strict reload that closes the portal window
    ("dns.read", undo_from("undo:mac")),  # nothing recorded: nothing was read
    ("tunnel.up", UNDO_ALL),
    ("ks.load#5", UNDO_ALL),  # reload with the real tunnel interface
    ("baseline", UNDO_ALL),
    ("audit", UNDO_ALL),
]


@pytest.mark.parametrize("step,expected", FAILURES, ids=[f[0] for f in FAILURES])
def test_failure_at_each_step_rolls_everything_back(world, step, expected, capsys):
    world.stop_at = None  # the waits in setup tick the clock too
    if step == "network":
        world.backend.gateway_ip = None
        error = session.SessionError
    elif step == "baseline":
        world.backend.neigh = {}  # the gateway's hardware address never shows up
        error = session.SessionError
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
    # The user is told what is about to become visible before it does.
    assert session.STOP_NOTICE in capsys.readouterr().out


@pytest.mark.parametrize("step", ["ks.load#1", "tunnel.up", "ks.load#3"])
def test_failure_without_portal_rolls_back(world, step):
    world.fail_on.add(step)
    with pytest.raises(Boom):
        start(world)
    assert_restored(world)
    assert world.undone() == (undo_from("undo:killswitch") if step == "ks.load#1" else UNDO_ALL)


def test_setup_failure_prints_the_stop_notice_before_the_first_undo(world, monkeypatch):
    printed = []
    monkeypatch.setattr(session, "_say", lambda message: printed.append(
        (message, len(world.undone()))))
    world.fail_on.add("tunnel.up")
    with pytest.raises(Boom):
        start(world)
    assert (session.STOP_NOTICE, 0) in printed
    assert world.undone() == UNDO_ALL


def test_baseline_waits_for_the_gateway_hardware_address(world):
    world.backend.neigh = {}
    world.stop_at = None

    def on_tick(n):
        if n == 3:
            world.backend.neigh = {GATEWAY: {GATEWAY_MAC}}
        if n == 6:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    assert start(world) == 0
    assert world.events.index("audit") > world.events.index("ks.load#3")
    assert world.notes == []  # a full baseline: the late entry is not a finding
    assert_restored(world)


def test_baseline_never_complete_aborts_the_start(world):
    world.backend.neigh = {}
    world.stop_at = None
    with pytest.raises(session.SessionError, match="hardware address"):
        start(world)
    assert world.ticks == session.BASELINE_TIMEOUT
    assert "audit" not in world.events
    assert_restored(world)


def test_ctrl_c_during_setup_rolls_back_and_propagates(world):
    def interrupted(seconds, clock, sleep):
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        session.start(options(world, portal=True), backend_factory=world.factory,
                      notifier=world.notifier, clock=world.clock, sleep=world.sleep,
                      wait_enter=interrupted, environ={})
    assert world.undone() == undo_from("undo:mac")
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
    assert setup == ["ks.load#1", "harden", "hostname", "mac", "ks.load#2", "ks.load#3",
                     "portal_wait", "ks.load#4", "dns.read", "tunnel.up", "ks.load#5", "audit"]
    rules = [r for r, _ in world.ks.loads]
    # Lockdown until the new identity is in place; the exception only for the
    # window; and a strict reload (which on macOS flushes the states the
    # window opened) before the tunnel comes up.
    assert rules[0] == LOCKDOWN
    assert "portal=False" in rules[1] and "tunnel=None" in rules[1]
    assert "portal=True" in rules[2] and "tunnel=None" in rules[2]
    assert "portal=False" in rules[3] and "tunnel=None" in rules[3]
    assert "portal=False" in rules[4] and f"tunnel={TUNNEL_IF}" in rules[4]
    assert world.rules_at["portal_wait"] == rules[2]
    assert world.rules_at["tunnel.up"] == rules[3]
    assert world.enter_calls == [45]
    assert "NOT protected" in capsys.readouterr().out
    assert_restored(world)


def test_portal_strict_rules_reloaded_even_when_window_fails(world):
    world.fail_on.add("portal_wait")
    with pytest.raises(Boom):
        start(world, portal=True)
    assert "portal=True" in world.ks.loads[2][0]
    assert "portal=False" in world.ks.loads[3][0]
    assert world.events.index("ks.load#4") < world.events.index("undo:killswitch")
    assert "tunnel.up" not in world.events


def test_wait_for_enter_times_out_without_a_terminal(world, monkeypatch):
    monkeypatch.setattr(session.sys, "stdin", None)
    assert session.wait_for_enter(5, world.clock, world.sleep) is False
    assert world.now == 1005.0


# -------------------------------------------------------------- (d) go silent

def spoof_gateway(world, at_tick: int, stop_at: int):
    world.stop_at = None

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
    world.stop_at = None

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
    # The silent rules first (no tunnel, no endpoints; on macOS the load also
    # drops the old rules' states), same token, then the tunnel.
    assert world.events[down - 1:down + 1] == ["ks.load#4", "tunnel.down:nir"]
    rules, undo = world.ks.loads[3]
    assert rules == SILENT
    assert undo == {"anchor": "test/anchor", "token": "42"}
    assert len(world.ks.loads) == 4  # done in one go: nothing is retried
    # The stop afterwards still undoes everything; the dead tunnel is not an error.
    assert world.undone() == ["tunnel.down:nir"] + UNDO_ALL
    assert_restored(world)


def test_go_silent_retries_the_tunnel_every_poll_until_it_is_down(world, monkeypatch):
    monkeypatch.setattr(session, "_tunnel_present", lambda path: True)
    seen = {}

    def on_tick(n):
        if n == 1:
            world.backend.neigh[GATEWAY] = {"02:00:00:00:00:99"}
            world.fail_on.add("tunnel.down:nir")
        if n == 3:  # after poll 2, where the first attempt failed
            seen["up_after_failure"] = set(world.tunnel.up)
            seen["rules"] = world.ks.loads[-1][0]
        if n == 4:  # after poll 3, the retry
            seen["up_after_retry"] = set(world.tunnel.up)
        if n == 6:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=3600.0) == 0
    # The silent rules went in even though the tunnel could not be stopped.
    assert seen["rules"] == SILENT
    assert seen["up_after_failure"] == {world.staged}
    assert seen["up_after_retry"] == set()
    in_hold = world.events[:world.events.index("undo:dns")]
    # Failed on poll 2, retried on poll 3, then the stop's rollback (already down).
    assert in_hold.count("tunnel.down:nir") == 3
    assert [r for r, _ in world.ks.loads].count(SILENT) == 1  # rules were not redone
    assert sum("Could not stop the tunnel" in m for _, m in world.notes) == 1
    assert_restored(world)


def test_go_silent_retries_the_reload_every_poll_until_it_works(world):
    seen = {}

    def on_tick(n):
        if n == 1:
            world.backend.neigh[GATEWAY] = {"02:00:00:00:00:99"}
            world.fail_on.update({"ks.load#4", "ks.load#5"})
        if n == 3:
            seen["after_first"] = (world.ks.loads[-1][0], set(world.tunnel.up))
        if n == 6:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=3600.0) == 0
    # Poll 2: the reload fails, the tunnel still goes down. Poll 3 fails again,
    # poll 4 succeeds, and after that nothing more is reloaded.
    assert seen["after_first"] == (SILENT, set())
    assert [r for r, _ in world.ks.loads][3:] == [SILENT, SILENT, SILENT]
    assert sum("Could not tighten the kill switch" in m for _, m in world.notes) == 1
    assert_restored(world)


def test_alternating_arp_poisoning_goes_silent(world):
    """Seen, clear, seen: 2 of the last 3 checks, though never twice in a row."""
    def on_tick(n):
        world.backend.neigh[GATEWAY] = {"02:00:00:00:00:99" if n % 2 else GATEWAY_MAC}
        if n == 5:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=3600.0) == 0
    assert any("Strict mode" in m for _, m in world.notes)
    assert world.ks.loads[3][0] == SILENT
    assert_restored(world)


def test_empty_dns_read_is_not_a_finding(world):
    def on_tick(n):
        world.backend.dns = [] if n < 4 else [GATEWAY]
        if n == 5:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=3600.0) == 0
    assert world.notes == []
    assert len(world.ks.loads) == 3


def test_no_strict_only_warns(world):
    spoof_gateway(world, at_tick=1, stop_at=4)
    assert start(world, strict=False, duration=3600.0) == 0
    assert len(world.notes) == 1 and "Warning" in world.notes[0][1]
    assert world.undone() == UNDO_ALL  # the tunnel was never stopped early


def test_strict_from_environment(world):
    spoof_gateway(world, at_tick=1, stop_at=4)
    code = session.start(options(world, duration=3600.0), backend_factory=world.factory,
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
    world.stop_at = 6
    assert start(world, duration=3600.0) == 0
    down_notes = [m for _, m in world.notes if "tunnel is down" in m]
    assert len(down_notes) == 1
    assert world.events.count("undo:killswitch") == 1  # only at the final stop


def test_lost_kill_switch_is_reloaded_on_the_next_poll(world):
    seen = {}

    def on_tick(n):
        if n == 1:
            world.ks.loaded = False
        if n == 2:
            seen["loaded"], seen["status"] = world.ks.loaded, session.status()["killswitch"]
    world.on_tick = on_tick
    world.stop_at = 4
    assert start(world, duration=3600.0) == 0
    assert sum("kill switch rules are no longer loaded" in m for _, m in world.notes) == 1
    # The rules that were current (with the tunnel interface), same token; once.
    assert world.ks.loads[3] == world.ks.loads[2]
    assert len(world.ks.loads) == 4
    assert seen == {"loaded": True, "status": True}
    # The tunnel was left alone: its first "down" is the stop's own rollback.
    assert world.events.count("tunnel.down:nir") == 1
    assert world.events.index("tunnel.down:nir") > world.events.index("tunnel.down:nir-fallback")
    assert_restored(world)


def test_kill_switch_check_that_raises_is_treated_as_lost(world):
    def on_tick(n):
        if n == 1:
            world.ks.check_error = RuntimeError("pfctl went away")
    world.on_tick = on_tick
    world.stop_at = 3
    assert start(world, duration=3600.0) == 0
    assert len(world.ks.loads) == 4 and world.ks.loads[3] == world.ks.loads[2]
    assert any("could not be checked" in m for _, m in world.notes)


def test_reload_journals_a_new_pf_enable_token(world):
    """pf itself was disabled: enabling it again takes a second reference,
    which is journaled and released at the stop like the first."""
    def on_tick(n):
        if n == 1:
            world.ks.loaded = False
            world.ks.new_token = "43"
    world.on_tick = on_tick
    world.stop_at = 3
    assert start(world, duration=3600.0) == 0
    assert world.ks.released == ["43", "42"]
    assert_restored(world)


def test_lost_kill_switch_that_cannot_be_reloaded_goes_silent_and_keeps_trying(world):
    seen = {}

    def on_tick(n):
        if n == 1:
            world.ks.loaded = False
            world.fail_on.update({"ks.load#4", "ks.load#5", "ks.load#6"})
        if n == 2:  # after poll 1: the reload and the silent load both failed
            seen["tunnel"] = set(world.tunnel.up)
            seen["status"] = session.status()
        if n == 6:
            raise KeyboardInterrupt
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=3600.0) == 0
    # The tunnel was stopped at once, so nothing can leave outside it.
    assert seen["tunnel"] == set()
    assert seen["status"]["silent"] is True and seen["status"]["killswitch"] is False
    assert any("could not be reloaded" in m for _, m in world.notes)
    # Poll 1: tunnel rules, then silent rules, both fail. Poll 2: fails again.
    # Poll 3: the silent rules load, and nothing more is loaded afterwards.
    rules = [r for r, _ in world.ks.loads]
    assert rules[3] == rules[2] and rules[4:] == [SILENT, SILENT, SILENT]
    assert world.ks.loaded is False  # (rolled back by the stop at the end)
    assert_restored(world)


def test_notifier_failure_does_not_end_the_session(world):
    def broken(title, message):
        raise RuntimeError("no display")
    spoof_gateway(world, at_tick=1, stop_at=4)
    code = session.start(options(world, strict=False, duration=3600.0), backend_factory=world.factory,
                         notifier=broken, clock=world.clock, sleep=world.sleep, environ={})
    assert code == 0
    assert_restored(world)


# ------------------------------------------------- (e) duration end / SIGTERM

def test_duration_end_goes_silent_and_waits_for_stop(world, capsys):
    seen = {}

    def on_tick(n):
        if n == 3:  # the last tick inside the duration
            seen["before"] = (session.status()["silent"], set(world.tunnel.up))
        if n == 8:  # long after it
            seen["status"] = session.status()
            seen["pending"] = [e["kind"] for e in journal.pending()]
            seen["mac"] = world.backend.mac
            seen["names"] = dict(world.backend.hostnames)
            seen["tunnel"] = set(world.tunnel.up)
            seen["rules"] = world.ks.loads[-1][0]
            seen["loaded"] = world.ks.loaded
            seen["undone"] = world.undone()
            seen["out"] = capsys.readouterr().out
        if n == 9:
            os.kill(os.getpid(), signal.SIGTERM)  # `session stop`
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=9.0, poll=3.0) == 0
    assert seen["before"] == (False, {world.staged})
    # Time is up: blocked, tunnel down, and *nothing* put back.
    assert seen["status"]["silent"] is True and seen["status"]["ends_at"] is None
    assert seen["rules"] == SILENT and seen["loaded"] is True
    assert seen["tunnel"] == set()
    assert seen["mac"] != ORIGINAL_MAC and seen["names"] != ORIGINAL_NAMES
    assert seen["undone"] == ["tunnel.down:nir"]
    assert seen["pending"] == ["tunnel", "tunnel", "dns", "mac", "hostname", "inbound",
                               "pf_token", "killswitch"]
    assert session.TIME_UP_NOTICE in seen["out"] and session.STOP_NOTICE not in seen["out"]
    assert world.notes == [(session.TITLE, session.TIME_UP_NOTICE)]
    # The stop the user then asks for rolls everything back.
    assert session.STOP_NOTICE in capsys.readouterr().out
    assert world.undone() == ["tunnel.down:nir"] + UNDO_ALL
    assert_restored(world)


def test_time_up_notice_wording():
    assert session.TIME_UP_NOTICE == (
        "Session time is up. All traffic is blocked. Leave the network (or turn Wi-Fi off), "
        "then run `sudo python main.py session stop`.")


def test_sighup_goes_silent_and_leaves_the_journal_pending(world, capsys):
    before = signal.getsignal(signal.SIGHUP)

    def on_tick(n):
        if n == 2:
            os.kill(os.getpid(), signal.SIGHUP)  # the terminal was closed
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=3600.0) == 1
    assert world.ticks == 2
    # Blocked and tunnel down, but the identity and the kill switch stay.
    assert world.ks.loads[-1][0] == SILENT and world.ks.loaded is True
    assert world.tunnel.up == set()
    assert world.undone() == ["tunnel.down:nir"]
    assert world.backend.mac != ORIGINAL_MAC and world.backend.hostnames != ORIGINAL_NAMES
    assert [e["kind"] for e in journal.pending()] == [
        "tunnel", "tunnel", "dns", "mac", "hostname", "inbound", "pf_token", "killswitch"]
    assert Path(world.staged).exists()  # the pending tunnel entries still need it
    out = capsys.readouterr().out
    assert session.LEAVE_HINT in out and session.STOP_NOTICE not in out
    assert any(session.LEAVE_HINT in m for _, m in world.notes)
    # The process is gone: no status, no lock, handlers back.
    assert not session.status_path().exists() and session.running_pid() is None
    assert signal.getsignal(signal.SIGHUP) is before
    # A new session is refused; `session stop` rolls back directly.
    with pytest.raises(session.SessionError, match="panic"):
        start(world)
    assert Path(world.staged).exists()
    assert session.stop_running(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert session.STOP_NOTICE in capsys.readouterr().out
    assert world.undone() == ["tunnel.down:nir"] + UNDO_ALL
    assert_restored(world)


def test_unexpected_error_in_hold_goes_silent_and_leaves_the_journal_pending(world, capsys):
    def on_tick(n):
        if n == 2:
            raise RuntimeError("something broke")
    world.on_tick = on_tick
    world.stop_at = None
    with pytest.raises(RuntimeError, match="something broke"):
        start(world, duration=3600.0)
    assert world.ks.loads[-1][0] == SILENT and world.ks.loaded is True
    assert world.tunnel.up == set()
    assert world.backend.mac != ORIGINAL_MAC
    assert len(journal.pending()) == 8
    assert session.LEAVE_HINT in capsys.readouterr().out
    assert session.running_pid() is None
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert_restored(world)


def test_sighup_after_time_is_up_changes_nothing_more(world):
    def on_tick(n):
        if n == 6:
            os.kill(os.getpid(), signal.SIGHUP)
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=9.0) == 1
    assert [r for r, _ in world.ks.loads].count(SILENT) == 1
    assert world.undone() == ["tunnel.down:nir"]
    assert len(journal.pending()) == 8


def test_sighup_during_setup_goes_silent_instead_of_rolling_back(world, capsys):
    def hung_up(seconds, clock, sleep):
        raise session._Hangup
    code = session.start(options(world, portal=True), backend_factory=world.factory,
                         notifier=world.notifier, clock=world.clock, sleep=world.sleep,
                         wait_enter=hung_up, environ={})
    assert code == 1
    # The portal exception was closed, then everything was blocked.
    assert "portal=False" in world.ks.loads[3][0] and world.ks.loads[4][0] == SILENT
    assert world.undone() == [] and world.backend.mac != ORIGINAL_MAC
    assert [e["kind"] for e in journal.pending()] == [
        "mac", "hostname", "inbound", "pf_token", "killswitch"]
    assert session.LEAVE_HINT in capsys.readouterr().out
    assert session.stop_running(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert_restored(world)


def test_abandon_keeps_trying_when_the_silent_reload_fails(world, capsys):
    def on_tick(n):
        if n == 2:
            world.fail_on.update({"ks.load#4", "ks.load#5"})
            os.kill(os.getpid(), signal.SIGHUP)
    world.on_tick = on_tick
    world.stop_at = None
    assert start(world, duration=3600.0) == 1
    assert world.ks.loads[-1][0] == SILENT and len(world.ks.loads) == 6
    assert world.tunnel.up == set()
    assert "could not be put into the blocked state" not in capsys.readouterr().out


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
    world.stop_at = None
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
    world.stop_at = 3
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
    journal.record("dns", {"services": DNS_SETTINGS})
    journal.record("tunnel", {"config_path": world.config})
    journal.record("tunnel", {"config_path": world.fallback})
    world.tunnel.up = {world.config}


def test_panic_after_crash_restores_everything(world, capsys):
    leave_crashed_session(world)
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert world.undone() == UNDO_ALL
    assert_restored(world)
    out = capsys.readouterr().out
    assert out.count("restored") == 8
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
    assert out.count("restored") == 7
    # A second run finishes the job.
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 0
    assert_restored(world)


def test_panic_on_a_corrupt_journal_still_removes_the_kill_switch(world, capsys):
    leave_crashed_session(world)
    path = journal.journal_path()
    lines = path.read_bytes().split(b"\n")
    lines[2] = b"{not json"
    path.write_bytes(b"\n".join(lines))
    with pytest.raises(journal.JournalCorrupt):
        journal.pending()

    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 1
    # Our anchor, by name; no token, so no pf enable reference is released.
    assert world.ks.unloaded_with == [{"anchor": "test/anchor"}]
    assert world.ks.released == [] and world.ks.loaded is False
    # Nothing else was guessed at.
    assert world.events == ["undo:killswitch"]
    assert world.backend.mac == "02:11:22:33:44:55" and world.tunnel.up == {world.config}
    assert world.commands == []
    assert path.exists()  # left for inspection
    out = capsys.readouterr().out
    assert "unreadable" in out and "kill switch rules" in out and "Nothing else was undone" in out
    assert ORIGINAL_MAC not in out and "Real" not in out


def test_panic_on_a_corrupt_journal_reports_a_failed_unload(world, capsys):
    leave_crashed_session(world)
    journal.journal_path().write_bytes(b"garbage\n" + journal.journal_path().read_bytes())
    world.fail_on.add("undo:killswitch")
    assert session.panic(world.factory, clock=world.clock, sleep=world.sleep) == 1
    assert "FAILED    kill switch rules" in capsys.readouterr().out


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
    assert world.events == [] and len(journal.pending()) == 8
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
    for kind in ("mac", "hostname", "inbound", "killswitch", "pf_token", "tunnel", "dns"):
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
    world.stop_at = None
    assert start(world, duration=3600.0) == 0
    assert world.ks.loads[3][0] == SILENT
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


# ------------------------------------------------------------------ (f2) dns

LIST_SERVICES = (
    "An asterisk (*) denotes that a network service is disabled.\n"
    "Wi-Fi\n"
    "USB 10/100/1000 LAN\n"
    "*Thunderbolt Bridge\n")


def networksetup(answers: dict, calls: list):
    def runner(*args, check=True, input=None):
        calls.append(args)
        assert args[0] == "networksetup"
        return answers[args[1:]]
    return runner


def test_read_dns_settings_reads_every_service(monkeypatch):
    calls = []
    runner = networksetup({
        ("-listallnetworkservices",): LIST_SERVICES,
        ("-getdnsservers", "Wi-Fi"): "There aren't any DNS Servers set on Wi-Fi.\n",
        ("-getsearchdomains", "Wi-Fi"): "There aren't any Search Domains set on Wi-Fi.\n",
        ("-getdnsservers", "USB 10/100/1000 LAN"): "192.0.2.53\n2001:db8::53\n",
        ("-getsearchdomains", "USB 10/100/1000 LAN"): "example.test\n",
        ("-getdnsservers", "Thunderbolt Bridge"): "There aren't any DNS Servers set on Thunderbolt Bridge.\n",
        ("-getsearchdomains", "Thunderbolt Bridge"): "corp.example\nlab.example\n",
    }, calls)
    assert session.read_dns_settings(runner) == {
        "Wi-Fi": {"servers": [], "search": []},  # empty: automatic
        "USB 10/100/1000 LAN": {"servers": ["192.0.2.53", "2001:db8::53"], "search": ["example.test"]},
        "Thunderbolt Bridge": {"servers": [], "search": ["corp.example", "lab.example"]},
    }
    # Read-only, and a service name with spaces is one argument.
    assert all(call[1].startswith(("-list", "-get")) for call in calls)
    assert ("networksetup", "-getdnsservers", "USB 10/100/1000 LAN") in calls


def test_undo_dns_sets_servers_and_search_domains_back(world):
    undo = {"services": {
        "Wi-Fi": {"servers": [], "search": []},
        "USB 10/100/1000 LAN": {"servers": ["192.0.2.53", "192.0.2.54"], "search": ["example.test"]},
    }}
    for _ in range(2):  # idempotent: it sets values, it does not toggle
        world.commands.clear()
        session._undo_dns(undo, world.factory)
        assert world.commands == [
            ("networksetup", "-setdnsservers", "Wi-Fi", "Empty"),
            ("networksetup", "-setsearchdomains", "Wi-Fi", "Empty"),
            ("networksetup", "-setdnsservers", "USB 10/100/1000 LAN", "192.0.2.53", "192.0.2.54"),
            ("networksetup", "-setsearchdomains", "USB 10/100/1000 LAN", "example.test"),
        ]


def test_undo_dns_skips_a_vanished_service_but_reports_a_real_failure(world, monkeypatch):
    undo = {"services": {"Gone": {"servers": ["192.0.2.53"], "search": []},
                         "Wi-Fi": {"servers": [], "search": []}}}
    listing = {"text": "header\nWi-Fi\n"}
    fail = {"Gone"}

    def run(*args, check=True, input=None):
        world.commands.append(args)
        if args[1] == "-listallnetworkservices":
            return listing["text"]
        if args[2] in fail:
            raise BackendError("networksetup failed")
        return ""
    monkeypatch.setattr(session, "run", run)
    session._undo_dns(undo, world.factory)  # "Gone" no longer exists: nothing to restore
    assert ("networksetup", "-setdnsservers", "Wi-Fi", "Empty") in world.commands

    listing["text"] = "header\nWi-Fi\nGone\n"
    with pytest.raises(BackendError, match="Gone"):
        session._undo_dns(undo, world.factory)
    fail.add("Wi-Fi")
    with pytest.raises(BackendError, match="2 network service"):
        session._undo_dns(undo, world.factory)


def test_session_records_dns_before_the_tunnel_and_restores_it_after(world):
    assert start(world) == 0
    assert world.dns_reads == 1
    assert world.events.index("dns.read") < world.events.index("tunnel.up")
    # Rollback: tunnel down first (so wg-quick is out of the way), then DNS.
    assert world.undone().index("tunnel.down:nir") < world.undone().index("undo:dns")
    assert world.commands == [
        ("networksetup", "-setdnsservers", "Wi-Fi", "Empty"),
        ("networksetup", "-setsearchdomains", "Wi-Fi", "Empty"),
        ("networksetup", "-setdnsservers", "USB 10/100/1000 LAN", "192.0.2.53", "192.0.2.54"),
        ("networksetup", "-setsearchdomains", "USB 10/100/1000 LAN", "example.test"),
    ]


def test_no_dns_entry_where_the_tunnel_does_not_touch_dns_settings(world, monkeypatch):
    monkeypatch.setattr(session, "_manages_dns", lambda: False)  # Linux
    assert start(world) == 0
    assert world.dns_reads == 0 and world.commands == []
    assert "dns" not in [e["kind"] for e in world.pending_at_audit]
    assert world.undone() == [e for e in UNDO_ALL if e != "undo:dns"]


def test_manages_dns_only_on_macos(monkeypatch):
    monkeypatch.setattr(session.sys, "platform", "darwin")
    assert session._manages_dns() is True
    monkeypatch.setattr(session.sys, "platform", "linux")
    assert session._manages_dns() is False


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
    assert not session.staging_dir().exists()  # the good config is not left staged


def test_preflight_refuses_two_configs_with_the_same_file_name(world):
    other = world.tmp / "elsewhere"
    other.mkdir()
    world.fallback = _write_config(other / "nir.conf", "192.0.2.20:443")
    with pytest.raises(session.SessionError, match="different file names"):
        start(world)
    assert world.events == []


def test_preflight_refuses_a_symlinked_config(world):
    link = world.tmp / "link.conf"
    link.symlink_to(world.config)
    world.config = str(link)
    with pytest.raises(session.SessionError, match="cannot be used"):
        start(world)
    assert world.events == [] and not session.staging_dir().exists()


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
    macos = "   route to: 192.0.2.1\n    gateway: 192.168.1.1\n  interface: utun4\n      flags: <UP>\n"
    assert session.parse_default_route_interfaces(macos, "darwin") == ["utun4"]
    linux = ("default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
             "default dev wg0 table 51820 scope link\n"
             "192.168.1.0/24 dev wlan0 proto kernel scope link\n")
    assert session.parse_default_route_interfaces(linux, "linux") == ["wlan0", "wg0"]
    assert session.parse_default_route_interfaces("", "linux") == []
    # WireGuard-style half routes, and the lookup of the probe address.
    halves = ("default via 192.168.1.1 dev wlan0\n"
              "0.0.0.0/1 dev tun0 scope link\n"
              "128.0.0.0/1 dev tun0 scope link\n"
              "10.0.0.0/8 dev docker0 scope link\n")
    assert session.parse_default_route_interfaces(halves, "linux") == ["wlan0", "tun0"]
    lookup = "192.0.2.1 dev tun1 src 10.8.0.2 uid 0\n    cache\n"
    assert session.parse_default_route_interfaces(lookup, "linux") == ["tun1"]


def test_default_route_tunnel_detection(monkeypatch):
    calls = []

    def runner_for(route_iface, wg_interfaces=""):
        def runner(*args, check=True):
            calls.append(args)
            if args[0] == "wg":
                return wg_interfaces
            return f"  interface: {route_iface}\n"
        return runner
    monkeypatch.setattr(session.sys, "platform", "darwin")
    assert session.default_route_tunnel("en0", runner_for("en0")) is None
    assert session.default_route_tunnel("en0", runner_for("utun4")) == "utun4"
    assert session.default_route_tunnel("en0", runner_for("en7")) is None
    assert session.default_route_tunnel("en0", runner_for("corp0", "corp0\n")) == "corp0"
    # A lookup of a public address, never `get default`: a VPN that routes with
    # 0.0.0.0/1 + 128.0.0.0/1 leaves the default route on the physical interface.
    routes = [c for c in calls if c[0] == "route"]
    assert routes and all(c == ("route", "-n", "get", "192.0.2.1") for c in routes)


def test_default_route_tunnel_detection_linux(monkeypatch):
    calls = []

    def runner(*args, check=True):
        calls.append(args)
        if args[0] == "wg":
            return ""
        if args[:4] == ("ip", "-4", "route", "get"):
            return "192.0.2.1 dev tun0 src 10.8.0.2 uid 0\n"
        return "default via 192.168.1.1 dev wlan0 proto dhcp\n"
    monkeypatch.setattr(session.sys, "platform", "linux")
    assert session.default_route_tunnel("wlan0", runner) == "tun0"
    assert ("ip", "-4", "route", "get", "192.0.2.1") in calls


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
    command = session.build_notify_command(
        'say "hi"', 'a\\b" & do shell script "x"\nnext', "darwin", environ={})
    assert command[:2] == ["osascript", "-e"] and len(command) == 3
    assert command[2] == (
        'display notification "a\\\\b\\" & do shell script \\"x\\" next" '
        'with title "say \\"hi\\""')
    # No unescaped quote is left to close the string early.
    body = command[2].replace("\\\\", "").replace('\\"', "")
    assert body.count('"') == 4


def test_notify_command_linux_and_unsupported():
    with_tool = session.build_notify_command(
        "-t", "msg", "linux", which=lambda name: "/usr/bin/" + name, environ={})
    assert with_tool == ["notify-send", "--", "-t", "msg"]
    assert session.build_notify_command("t", "m", "linux", which=lambda name: None, environ={}) is None
    assert session.build_notify_command("t", "m", "win32", environ={}) is None


SUDO = {"SUDO_UID": "501", "SUDO_USER": "alice", "PATH": "/evil", "WG_CONFIG": "/x.conf"}


def test_notify_command_under_sudo_runs_as_the_invoking_user():
    """Root cannot reach the user's notification centre or session bus."""
    macos = session.build_notify_command("t", "m", "darwin", environ=SUDO)
    assert macos[:7] == ["launchctl", "asuser", "501", "sudo", "-u", "alice", "osascript"]
    assert macos[7] == "-e" and len(macos) == 9
    linux = session.build_notify_command("t", "m", "linux", which=lambda name: True, environ=SUDO)
    assert linux == ["sudo", "-u", "alice", "env",
                     "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/501/bus",
                     "notify-send", "--", "t", "m"]
    env = session.build_notify_env("linux", SUDO)
    assert env["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/501/bus"
    # The fixed environment every command gets: nothing of the caller's PATH.
    assert env["PATH"] != "/evil" and "WG_CONFIG" not in env
    assert "DBUS_SESSION_BUS_ADDRESS" not in session.build_notify_env("darwin", SUDO)


@pytest.mark.parametrize("environ", [
    {"SUDO_UID": "501"},  # no user name
    {"SUDO_USER": "alice"},  # no uid
    {"SUDO_UID": "0", "SUDO_USER": "root"},  # sudo from a root shell: nobody to hand over to
    {"SUDO_UID": "501; rm", "SUDO_USER": "alice"},
    {"SUDO_UID": "501", "SUDO_USER": "-i"},
    {"SUDO_UID": "501", "SUDO_USER": "a b"},
])
def test_notify_command_ignores_incomplete_or_odd_sudo_variables(environ):
    assert session.build_notify_command("t", "m", "darwin", environ=environ)[0] == "osascript"
    assert session.build_notify_command(
        "t", "m", "linux", which=lambda name: True, environ=environ)[0] == "notify-send"


def test_notify_runs_without_a_shell_and_never_raises(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        raise OSError("no display")
    monkeypatch.setattr(session.subprocess, "run", fake_run)
    monkeypatch.setattr(session.sys, "platform", "darwin")
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_USER", "alice")
    session.notify("title", 'mess"age')  # must not raise
    (command, kwargs), = calls
    assert isinstance(command, list) and not kwargs.get("shell")
    assert command[:6] == ["launchctl", "asuser", "501", "sudo", "-u", "alice"]
    assert kwargs["env"]["PATH"] and kwargs["timeout"] == 5

    def explode(*args, **kwargs):
        raise RuntimeError("anything at all")
    monkeypatch.setattr(session, "build_notify_command", explode)
    session.notify("title", "message")  # still must not raise


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
