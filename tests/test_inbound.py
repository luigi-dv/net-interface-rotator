import pytest

from rotator.backends import linux, macos
from rotator.backends.base import BackendError
from rotator.backends.linux import LinuxBackend
from rotator.backends.macos import SOCKETFILTERFW, MacOSBackend, parse_firewall_flag

from tests.fakes import FakeBackend

GETTERS = {"global": "--getglobalstate", "blockall": "--getblockall",
           "stealth": "--getstealthmode"}
SETTERS = {"global": "--setglobalstate", "blockall": "--setblockall",
           "stealth": "--setstealthmode"}
WORDING = {
    "global": {True: "Firewall is enabled. (State = 1)\n",
               False: "Firewall is disabled. (State = 0)\n"},
    "blockall": {True: "Firewall has block all state set to enabled.\n",
                 False: "Firewall has block all state set to disabled.\n"},
    "stealth": {True: "Firewall stealth mode is on\n",
                False: "Firewall stealth mode is off\n"},
}


class FakeFirewall:
    """Stands in for rotator.backends.macos.run with a stateful firewall.

    Keys listed in ``stuck`` ignore set commands, like a setting that is
    managed elsewhere.
    """

    def __init__(self, stuck: tuple[str, ...] = (), **state: bool):
        self.state = {"global": False, "blockall": False, "stealth": False, **state}
        self.stuck = stuck
        self.calls: list[tuple] = []

    def __call__(self, *args: str, check: bool = True) -> str:
        self.calls.append(args)
        assert args[0] == SOCKETFILTERFW
        for key, flag in GETTERS.items():
            if args[1] == flag:
                return WORDING[key][self.state[key]]
        for key, flag in SETTERS.items():
            if args[1] == flag:
                if key not in self.stuck:
                    self.state[key] = {"on": True, "off": False}[args[2]]
                return ""
        raise AssertionError(f"unexpected command: {args}")

    @property
    def sets(self) -> list[tuple]:
        return [c[1:] for c in self.calls if c[1].startswith("--set")]


@pytest.mark.parametrize("key, output, expected", [
    ("global", "Firewall is enabled. (State = 1)", True),
    ("global", "Firewall is disabled. (State = 0)", False),
    ("global", "Firewall is blocking all non-essential incoming connections. (State = 2)", True),
    ("global", "Firewall is on.", True),
    ("global", "State = 0", False),
    ("blockall", "Firewall has block all state set to enabled.", True),
    ("blockall", "Firewall has block all state set to disabled.", False),
    ("blockall", "Block all INCOMING connections is enabled", True),
    ("blockall", "Block all DISABLED!", False),
    ("blockall", "Firewall is set to block all non-essential incoming connections", True),
    ("stealth", "Firewall stealth mode is on", True),
    ("stealth", "Firewall stealth mode is off", False),
    ("stealth", "Stealth mode enabled", True),
    ("stealth", "Stealth mode disabled\n", False),
])
def test_parse_firewall_flag_variants(key, output, expected):
    assert parse_firewall_flag(key, output) is expected


@pytest.mark.parametrize("key, output", [
    ("global", ""),
    ("global", "Firewall status unknown"),
    ("global", "Firewall is enabled. (State = 0)"),
    ("blockall", "Block all INCOMING connections"),
    ("stealth", "Stealth mode enabled or disabled"),
    ("stealth", "Firewall is set to block all non-essential incoming connections"),
])
def test_parse_firewall_flag_raises_when_undetermined(key, output):
    with pytest.raises(BackendError):
        parse_firewall_flag(key, output)


def test_macos_get_inbound_reads_three_settings(monkeypatch):
    fake = FakeFirewall(**{"global": True})
    monkeypatch.setattr(macos, "run", fake)

    assert MacOSBackend("en0").get_inbound() == {
        "global": True, "blockall": False, "stealth": False}
    assert fake.calls == [
        (SOCKETFILTERFW, "--getglobalstate"),
        (SOCKETFILTERFW, "--getblockall"),
        (SOCKETFILTERFW, "--getstealthmode"),
    ]


def test_macos_get_inbound_raises_on_unparseable_output(monkeypatch):
    monkeypatch.setattr(macos, "run", lambda *args, check=True: "???\n")

    with pytest.raises(BackendError):
        MacOSBackend("en0").get_inbound()


def test_macos_harden_sets_only_differing_values_and_returns_previous(monkeypatch):
    fake = FakeFirewall(**{"global": True})
    monkeypatch.setattr(macos, "run", fake)

    previous = MacOSBackend("en0").harden_inbound()

    assert previous == {"global": True, "blockall": False, "stealth": False}
    assert fake.sets == [("--setblockall", "on"), ("--setstealthmode", "on")]
    assert fake.state == {"global": True, "blockall": True, "stealth": True}


def test_macos_harden_from_all_off_sets_in_order(monkeypatch):
    fake = FakeFirewall()
    monkeypatch.setattr(macos, "run", fake)

    previous = MacOSBackend("en0").harden_inbound()

    assert previous == {"global": False, "blockall": False, "stealth": False}
    assert fake.sets == [("--setglobalstate", "on"), ("--setblockall", "on"),
                         ("--setstealthmode", "on")]


def test_macos_harden_already_hardened_issues_no_set(monkeypatch):
    fake = FakeFirewall(**{"global": True, "blockall": True, "stealth": True})
    monkeypatch.setattr(macos, "run", fake)

    assert MacOSBackend("en0").harden_inbound() == {
        "global": True, "blockall": True, "stealth": True}
    assert fake.sets == []


def test_macos_harden_readback_mismatch_raises_and_rolls_back(monkeypatch):
    fake = FakeFirewall(stuck=("stealth",))
    monkeypatch.setattr(macos, "run", fake)

    with pytest.raises(BackendError, match="stealth"):
        MacOSBackend("en0").harden_inbound()

    # What did change is put back, since the caller never got the old values.
    assert fake.state == {"global": False, "blockall": False, "stealth": False}
    assert fake.sets[-2:] == [("--setblockall", "off"), ("--setglobalstate", "off")]


def test_macos_restore_sets_in_reverse_order_only_where_different(monkeypatch):
    fake = FakeFirewall(**{"global": True, "blockall": True, "stealth": True})
    monkeypatch.setattr(macos, "run", fake)

    MacOSBackend("en0").restore_inbound(
        {"global": False, "blockall": False, "stealth": False})

    assert fake.sets == [("--setstealthmode", "off"), ("--setblockall", "off"),
                         ("--setglobalstate", "off")]


def test_macos_restore_skips_values_that_already_match(monkeypatch):
    fake = FakeFirewall(**{"global": True, "blockall": True, "stealth": True})
    monkeypatch.setattr(macos, "run", fake)

    MacOSBackend("en0").restore_inbound(
        {"global": True, "blockall": False, "stealth": True})

    assert fake.sets == [("--setblockall", "off")]


def test_macos_restore_can_turn_a_setting_back_on(monkeypatch):
    fake = FakeFirewall(**{"global": True})
    monkeypatch.setattr(macos, "run", fake)

    MacOSBackend("en0").restore_inbound(
        {"global": True, "blockall": False, "stealth": True})

    assert fake.sets == [("--setstealthmode", "on")]


def test_macos_restore_with_empty_previous_runs_nothing(monkeypatch):
    fake = FakeFirewall()
    monkeypatch.setattr(macos, "run", fake)

    MacOSBackend("en0").restore_inbound({})

    assert fake.calls == []


def test_linux_inbound_is_a_noop(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(linux, "run", lambda *args, check=True: calls.append(args) or "")
    backend = LinuxBackend("eth0")

    assert backend.get_inbound() == {}
    assert backend.harden_inbound() == {}
    assert backend.restore_inbound({}) is None
    assert backend.restore_inbound({"global": True}) is None
    assert calls == []


def test_fake_backend_harden_and_restore():
    backend = FakeBackend()

    previous = backend.harden_inbound()

    assert previous == {"global": False, "blockall": False, "stealth": False}
    assert backend.get_inbound() == {"global": True, "blockall": True, "stealth": True}

    backend.restore_inbound(previous)

    assert backend.inbound == previous
    assert backend.inbound_calls == [("harden",), ("restore", previous)]
