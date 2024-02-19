import pytest

from rotator import audit
from rotator import tunnel
from rotator.audit import AuditContext, CheckResult
from rotator.backends.base import BackendError
from tests.fakes import FakeBackend

# Made-up addresses: documentation ranges and locally administered MACs.
RANDOM_MAC = "02:aa:bb:cc:dd:ee"
HARDWARE_MAC = "a4:83:e7:00:11:22"
ORIGINAL_MAC = "f0:18:98:12:34:56"
TUNNEL_DNS = ("198.51.100.1", "2001:db8:1::1")
ORIGINAL_HOSTNAMES = {"ComputerName": "Work Laptop", "LocalHostName": "Work-Laptop", "HostName": None}
RANDOM_HOSTNAMES = {"ComputerName": "MacBook-Air", "LocalHostName": "MacBook-Air", "HostName": None}

ROUTE_DEFAULT_UTUN = """\
   route to: 192.0.2.1
destination: 128.0.0.0
       mask: 128.0.0.0
    gateway: 198.51.100.1
  interface: utun4
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recursive gateway: 192.0.2.1
"""

ROUTE_DEFAULT_EN0 = """\
   route to: 192.0.2.1
destination: default
       mask: default
    gateway: 192.0.2.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""

SCUTIL_DNS_TUNNEL = """\
DNS configuration

resolver #1
  search domain[0] : example.invalid
  nameserver[0] : 198.51.100.1
  nameserver[1] : 2001:db8:1::1
  if_index : 23 (utun4)
  flags    : Request A records, Request AAAA records
  reach    : 0x00000002 (Reachable)

resolver #2
  nameserver[0] : 192.0.2.1
  if_index : 15 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 200000

"""

SCUTIL_DNS_LAN_FIRST = """\
DNS configuration

resolver #1
  nameserver[0] : 192.0.2.1
  if_index : 15 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #2
  nameserver[0] : 198.51.100.1
  if_index : 23 (utun4)
  reach    : 0x00000002 (Reachable)

"""

SCUTIL_DNS_NO_RESOLVER = "DNS configuration\n\n"

IFCONFIG_LINK_LOCAL_ONLY = """\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
\tether a4:83:e7:00:11:22
\tinet6 fe80::1c2d:3e4f:5a6b:7c8d%en0 prefixlen 64 secured scopeid 0xc
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
\tnd6 options=201<PERFORMNUD,DAD>
\tmedia: autoselect
\tstatus: active
"""

IFCONFIG_GLOBAL_IPV6 = """\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether a4:83:e7:00:11:22
\tinet6 fe80::1c2d:3e4f:5a6b:7c8d%en0 prefixlen 64 secured scopeid 0xc
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2001:db8:2::23 prefixlen 64 autoconf secured
\tstatus: active
"""

IP_ROUTE_DEFAULT_WG = "192.0.2.1 dev wg0 src 198.51.100.7 uid 1000\n    cache\n"
IP_ROUTE_DEFAULT_LAN = "192.0.2.1 via 10.0.0.1 dev wlan0 src 10.0.0.23 uid 1000\n    cache\n"
IP_ROUTE_TUNNEL_DNS_WG = {
    "198.51.100.1": "198.51.100.1 dev wg0 src 198.51.100.7 uid 1000\n    cache\n",
    "2001:db8:1::1": "2001:db8:1::1 dev wg0 src 2001:db8:1::7 uid 1000\n    cache\n",
}
IP_ROUTE_TUNNEL_DNS_LAN = {
    "198.51.100.1": "198.51.100.1 via 10.0.0.1 dev wlan0 src 10.0.0.23 uid 1000\n    cache\n",
    "2001:db8:1::1": "2001:db8:1::1 via 10.0.0.1 dev wlan0 src 10.0.0.23 uid 1000\n    cache\n",
}
RESOLV_CONF_TUNNEL = "# managed by hand\nnameserver 198.51.100.1\nnameserver 2001:db8:1::1\n"
RESOLV_CONF_STUB = "# systemd-resolved stub\nnameserver 127.0.0.53\n"
RESOLVECTL_DNS_TUNNEL = """\
Global:
Link 2 (wlan0): 192.0.2.1
Link 5 (wg0): 198.51.100.1 2001:db8:1::1
"""
RESOLVECTL_DNS_NO_TUNNEL = "Global:\nLink 2 (wlan0): 192.0.2.1\n"
IP6_GLOBAL_WLAN0 = """\
    inet6 2001:db8:2::23/64 scope global dynamic mngtmpaddr
       valid_lft 86000sec preferred_lft 14000sec
"""


def macos_route_to(ip: str, iface: str) -> str:
    return (f"   route to: {ip}\ndestination: {ip}\n  interface: {iface}\n"
            "      flags: <UP,HOST,DONE,STATIC,PRCLONING>\n")


class FakeRunner:
    """Answers only the argument tuples it was given. Anything else is a
    BackendError, so an unexpected command shows up as a failed check. A value
    that is an exception is raised instead of returned."""

    def __init__(self, outputs=None):
        self.outputs = {tuple(key): value for key, value in (outputs or {}).items()}
        self.calls: list[tuple] = []

    def __call__(self, *args, check=True):
        self.calls.append(args)
        if args not in self.outputs:
            raise BackendError(f"unexpected command: {' '.join(args)}")
        value = self.outputs[args]
        if isinstance(value, Exception):
            raise value
        return value


class StubKillSwitch:
    def __init__(self, loaded: bool):
        self.loaded = loaded

    def is_loaded(self) -> bool:
        return self.loaded


def make_ctx(backend, tunnel_if="utun4", tunnel_dns=TUNNEL_DNS,
             original_mac=ORIGINAL_MAC, original_hostnames=ORIGINAL_HOSTNAMES):
    return AuditContext(backend=backend, tunnel_if=tunnel_if, tunnel_dns=tunnel_dns,
                        original_mac=original_mac, original_hostnames=original_hostnames)


def macos_backend(**kw):
    kw.setdefault("interface", "en0")
    kw.setdefault("mac", RANDOM_MAC)
    kw.setdefault("hardware", HARDWARE_MAC)
    kw.setdefault("hostnames", RANDOM_HOSTNAMES)
    kw.setdefault("inbound", {"global": True, "blockall": True, "stealth": True})
    return FakeBackend(**kw)


def linux_backend(**kw):
    kw.setdefault("interface", "wlan0")
    kw.setdefault("mac", RANDOM_MAC)
    kw.setdefault("hardware", HARDWARE_MAC)
    kw.setdefault("hostnames", {"transient": "random-host"})
    return FakeBackend(**kw)


# ------------------------------------------------------------ mac_randomized

@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_mac_randomized_passes(platform):
    result = audit.check_mac_randomized(make_ctx(macos_backend()), FakeRunner(), platform=platform)
    assert result.name == "mac_randomized" and result.ok


def test_mac_randomized_fails_on_vendor_address():
    backend = macos_backend(mac=HARDWARE_MAC)
    result = audit.check_mac_randomized(make_ctx(backend), FakeRunner(), platform="darwin")
    assert not result.ok and "vendor" in result.detail


def test_mac_randomized_fails_when_equal_to_hardware():
    backend = macos_backend(mac=RANDOM_MAC, hardware=RANDOM_MAC)
    result = audit.check_mac_randomized(make_ctx(backend), FakeRunner(), platform="darwin")
    assert not result.ok and "hardware" in result.detail


def test_mac_randomized_fails_when_equal_to_original():
    backend = macos_backend(mac=RANDOM_MAC)
    ctx = make_ctx(backend, original_mac=RANDOM_MAC)
    result = audit.check_mac_randomized(ctx, FakeRunner(), platform="linux")
    assert not result.ok and "original" in result.detail


def test_mac_randomized_skips_comparisons_with_none():
    backend = macos_backend(hardware=None)
    ctx = make_ctx(backend, original_mac=None)
    result = audit.check_mac_randomized(ctx, FakeRunner(), platform="darwin")
    assert result.ok and "hardware" not in result.detail and "original" not in result.detail


# ------------------------------------------------------------ hostname_changed

@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_hostname_changed_passes(platform):
    result = audit.check_hostname_changed(make_ctx(macos_backend()), FakeRunner(), platform=platform)
    assert result.ok


def test_hostname_changed_fails_when_name_matches_original():
    backend = macos_backend(hostnames={"ComputerName": "Work Laptop", "LocalHostName": "MacBook-Air", "HostName": None})
    result = audit.check_hostname_changed(make_ctx(backend), FakeRunner(), platform="darwin")
    assert not result.ok


def test_hostname_changed_not_managed_when_original_is_none():
    backend = macos_backend(hostnames=ORIGINAL_HOSTNAMES)
    ctx = make_ctx(backend, original_hostnames=None)
    result = audit.check_hostname_changed(ctx, FakeRunner(), platform="darwin")
    assert result.ok and result.detail == "not managed this session"


# -------------------------------------------------------------- inbound_blocked

def test_inbound_blocked_macos_passes():
    result = audit.check_inbound_blocked(make_ctx(macos_backend()), FakeRunner(),
                                         killswitch=StubKillSwitch(False), platform="darwin")
    assert result.ok


def test_inbound_blocked_macos_fails_when_stealth_off():
    backend = macos_backend(inbound={"global": True, "blockall": True, "stealth": False})
    result = audit.check_inbound_blocked(make_ctx(backend), FakeRunner(),
                                         killswitch=StubKillSwitch(True), platform="darwin")
    assert not result.ok and "stealth" in result.detail


def test_inbound_blocked_linux_passes_with_killswitch():
    result = audit.check_inbound_blocked(make_ctx(linux_backend()), FakeRunner(),
                                         killswitch=StubKillSwitch(True), platform="linux")
    assert result.ok


def test_inbound_blocked_linux_fails_without_killswitch():
    result = audit.check_inbound_blocked(make_ctx(linux_backend()), FakeRunner(),
                                         killswitch=StubKillSwitch(False), platform="linux")
    assert not result.ok


# ------------------------------------------------------------ killswitch_loaded

@pytest.mark.parametrize("platform", ["darwin", "linux"])
@pytest.mark.parametrize("loaded", [True, False])
def test_killswitch_loaded(platform, loaded):
    result = audit.check_killswitch_loaded(make_ctx(macos_backend()), FakeRunner(),
                                           killswitch=StubKillSwitch(loaded), platform=platform)
    assert result.ok is loaded


# ------------------------------------------------------------------ tunnel_up

def test_tunnel_up_pass(monkeypatch):
    monkeypatch.setattr(tunnel, "is_up", lambda name, *a, **k: name == "utun4")
    result = audit.check_tunnel_up(make_ctx(macos_backend()), FakeRunner(), platform="darwin")
    assert result.ok


def test_tunnel_up_fail(monkeypatch):
    monkeypatch.setattr(tunnel, "is_up", lambda name, *a, **k: False)
    result = audit.check_tunnel_up(make_ctx(macos_backend()), FakeRunner(), platform="darwin")
    assert not result.ok


def test_tunnel_up_fails_without_interface(monkeypatch):
    def must_not_be_called(*a, **k):
        raise AssertionError("tunnel.is_up called without an interface")
    monkeypatch.setattr(tunnel, "is_up", must_not_be_called)
    result = audit.check_tunnel_up(make_ctx(macos_backend(), tunnel_if=None), FakeRunner(), platform="darwin")
    assert not result.ok


# --------------------------------------------------------- default_route_via_tunnel

def test_default_route_macos_pass():
    runner = FakeRunner({("route", "-n", "get", "192.0.2.1"): ROUTE_DEFAULT_UTUN})
    result = audit.check_default_route_via_tunnel(make_ctx(macos_backend()), runner, platform="darwin")
    assert result.ok and "utun4" in result.detail


def test_default_route_macos_fail():
    runner = FakeRunner({("route", "-n", "get", "192.0.2.1"): ROUTE_DEFAULT_EN0})
    result = audit.check_default_route_via_tunnel(make_ctx(macos_backend()), runner, platform="darwin")
    assert not result.ok and "en0" in result.detail


def test_default_route_linux_pass():
    runner = FakeRunner({("ip", "route", "get", "192.0.2.1"): IP_ROUTE_DEFAULT_WG})
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    result = audit.check_default_route_via_tunnel(ctx, runner, platform="linux")
    assert result.ok


def test_default_route_linux_fail():
    runner = FakeRunner({("ip", "route", "get", "192.0.2.1"): IP_ROUTE_DEFAULT_LAN})
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    result = audit.check_default_route_via_tunnel(ctx, runner, platform="linux")
    assert not result.ok and "wlan0" in result.detail


def test_default_route_unreadable_output_fails():
    runner = FakeRunner({("route", "-n", "get", "192.0.2.1"): "route: not in table\n"})
    result = audit.check_default_route_via_tunnel(make_ctx(macos_backend()), runner, platform="darwin")
    assert not result.ok


# -------------------------------------------------------------- dns_via_tunnel

def macos_dns_runner(scutil, routes):
    outputs = {("scutil", "--dns"): scutil}
    for ip, iface in routes.items():
        outputs[("route", "-n", "get", ip)] = macos_route_to(ip, iface)
    return FakeRunner(outputs)


def test_dns_macos_pass_reads_first_resolver_only():
    runner = macos_dns_runner(SCUTIL_DNS_TUNNEL, {"198.51.100.1": "utun4", "2001:db8:1::1": "utun4"})
    result = audit.check_dns_via_tunnel(make_ctx(macos_backend()), runner, platform="darwin")
    assert result.ok


def test_dns_macos_fail_lan_resolver_in_use():
    runner = macos_dns_runner(SCUTIL_DNS_LAN_FIRST, {"192.0.2.1": "en0"})
    result = audit.check_dns_via_tunnel(make_ctx(macos_backend()), runner, platform="darwin")
    assert not result.ok and "192.0.2.1" in result.detail


def test_dns_macos_fail_resolver_routed_outside_tunnel():
    runner = macos_dns_runner(SCUTIL_DNS_TUNNEL, {"198.51.100.1": "en0", "2001:db8:1::1": "utun4"})
    result = audit.check_dns_via_tunnel(make_ctx(macos_backend()), runner, platform="darwin")
    assert not result.ok and "198.51.100.1 via en0" in result.detail


def test_dns_macos_fail_no_resolver_block():
    runner = macos_dns_runner(SCUTIL_DNS_NO_RESOLVER, {})
    result = audit.check_dns_via_tunnel(make_ctx(macos_backend()), runner, platform="darwin")
    assert not result.ok


def test_dns_linux_pass(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(RESOLV_CONF_TUNNEL)
    monkeypatch.setattr(audit, "RESOLV_CONF", resolv)
    outputs = {("ip", "route", "get", ip): out for ip, out in IP_ROUTE_TUNNEL_DNS_WG.items()}
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    result = audit.check_dns_via_tunnel(ctx, FakeRunner(outputs), platform="linux")
    assert result.ok


def test_dns_linux_fail_lan_resolver_in_resolv_conf(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.0.2.1\n")
    monkeypatch.setattr(audit, "RESOLV_CONF", resolv)
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    result = audit.check_dns_via_tunnel(ctx, FakeRunner(), platform="linux")
    assert not result.ok and "192.0.2.1" in result.detail


def test_dns_linux_fail_resolver_routed_outside_tunnel(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(RESOLV_CONF_TUNNEL)
    monkeypatch.setattr(audit, "RESOLV_CONF", resolv)
    outputs = {("ip", "route", "get", ip): out for ip, out in IP_ROUTE_TUNNEL_DNS_LAN.items()}
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    result = audit.check_dns_via_tunnel(ctx, FakeRunner(outputs), platform="linux")
    assert not result.ok and "wlan0" in result.detail


def test_dns_linux_systemd_stub_pass(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(RESOLV_CONF_STUB)
    monkeypatch.setattr(audit, "RESOLV_CONF", resolv)
    outputs = {("resolvectl", "dns"): RESOLVECTL_DNS_TUNNEL}
    outputs.update({("ip", "route", "get", ip): out for ip, out in IP_ROUTE_TUNNEL_DNS_WG.items()})
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    result = audit.check_dns_via_tunnel(ctx, FakeRunner(outputs), platform="linux")
    assert result.ok


def test_dns_linux_systemd_stub_fail_no_tunnel_link(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(RESOLV_CONF_STUB)
    monkeypatch.setattr(audit, "RESOLV_CONF", resolv)
    runner = FakeRunner({("resolvectl", "dns"): RESOLVECTL_DNS_NO_TUNNEL})
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    result = audit.check_dns_via_tunnel(ctx, runner, platform="linux")
    assert not result.ok


def test_dns_fails_when_tunnel_config_has_no_dns():
    ctx = make_ctx(macos_backend(), tunnel_dns=())
    result = audit.check_dns_via_tunnel(ctx, FakeRunner(), platform="darwin")
    assert not result.ok


# --------------------------------------------------------------- ipv6_contained

def test_ipv6_passes_when_killswitch_loaded_without_reading_interface():
    # An empty runner: any command would fail, so passing proves none ran.
    result = audit.check_ipv6_contained(make_ctx(macos_backend()), FakeRunner(),
                                        killswitch=StubKillSwitch(True), platform="darwin")
    assert result.ok


def test_ipv6_macos_passes_with_link_local_only():
    runner = FakeRunner({("ifconfig", "en0"): IFCONFIG_LINK_LOCAL_ONLY})
    result = audit.check_ipv6_contained(make_ctx(macos_backend()), runner,
                                        killswitch=StubKillSwitch(False), platform="darwin")
    assert result.ok


def test_ipv6_macos_fails_with_global_address():
    runner = FakeRunner({("ifconfig", "en0"): IFCONFIG_GLOBAL_IPV6})
    result = audit.check_ipv6_contained(make_ctx(macos_backend()), runner,
                                        killswitch=StubKillSwitch(False), platform="darwin")
    assert not result.ok


def test_ipv6_linux_passes_with_no_global_address():
    runner = FakeRunner({("ip", "-6", "addr", "show", "dev", "wlan0", "scope", "global"): ""})
    result = audit.check_ipv6_contained(make_ctx(linux_backend()), runner,
                                        killswitch=StubKillSwitch(False), platform="linux")
    assert result.ok


def test_ipv6_linux_fails_with_global_address():
    runner = FakeRunner({("ip", "-6", "addr", "show", "dev", "wlan0", "scope", "global"): IP6_GLOBAL_WLAN0})
    result = audit.check_ipv6_contained(make_ctx(linux_backend()), runner,
                                        killswitch=StubKillSwitch(False), platform="linux")
    assert not result.ok


# ------------------------------------------------------------------ run_checks

CHECK_NAMES = [
    "mac_randomized", "hostname_changed", "inbound_blocked", "killswitch_loaded",
    "tunnel_up", "default_route_via_tunnel", "dns_via_tunnel", "ipv6_contained",
]


def healthy_macos(monkeypatch):
    monkeypatch.setattr(tunnel, "is_up", lambda *a, **k: True)
    runner = macos_dns_runner(SCUTIL_DNS_TUNNEL, {"198.51.100.1": "utun4", "2001:db8:1::1": "utun4"})
    runner.outputs[("route", "-n", "get", "192.0.2.1")] = ROUTE_DEFAULT_UTUN
    runner.outputs[("ifconfig", "en0")] = IFCONFIG_LINK_LOCAL_ONLY
    return make_ctx(macos_backend()), runner


def test_run_checks_all_pass_macos(monkeypatch):
    ctx, runner = healthy_macos(monkeypatch)
    results = audit.run_checks(ctx, runner=runner, killswitch=StubKillSwitch(True), platform="darwin")
    assert [r.name for r in results] == CHECK_NAMES
    assert audit.all_ok(results)


def test_run_checks_all_pass_linux(monkeypatch, tmp_path):
    monkeypatch.setattr(tunnel, "is_up", lambda *a, **k: True)
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(RESOLV_CONF_TUNNEL)
    monkeypatch.setattr(audit, "RESOLV_CONF", resolv)
    outputs = {("ip", "route", "get", "192.0.2.1"): IP_ROUTE_DEFAULT_WG}
    outputs.update({("ip", "route", "get", ip): out for ip, out in IP_ROUTE_TUNNEL_DNS_WG.items()})
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    results = audit.run_checks(ctx, runner=FakeRunner(outputs), killswitch=StubKillSwitch(True), platform="linux")
    assert [r.name for r in results] == CHECK_NAMES
    assert audit.all_ok(results), audit.format_table(results)


def test_run_checks_backend_error_fails_one_check_only(monkeypatch):
    ctx, runner = healthy_macos(monkeypatch)
    runner.outputs[("route", "-n", "get", "192.0.2.1")] = BackendError("`route -n get 192.0.2.1` failed: boom")
    results = audit.run_checks(ctx, runner=runner, killswitch=StubKillSwitch(True), platform="darwin")
    by_name = {r.name: r for r in results}
    assert [r.name for r in results] == CHECK_NAMES
    assert not by_name["default_route_via_tunnel"].ok
    assert "boom" in by_name["default_route_via_tunnel"].detail
    assert all(r.ok for r in results if r.name != "default_route_via_tunnel")
    assert not audit.all_ok(results)


def test_run_checks_os_error_from_resolv_conf_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(tunnel, "is_up", lambda *a, **k: True)
    monkeypatch.setattr(audit, "RESOLV_CONF", tmp_path / "missing")
    ctx = make_ctx(linux_backend(), tunnel_if="wg0")
    results = audit.run_checks(ctx, runner=FakeRunner(), killswitch=StubKillSwitch(True), platform="linux")
    by_name = {r.name: r for r in results}
    assert not by_name["dns_via_tunnel"].ok
    assert len(results) == len(CHECK_NAMES)


def test_run_checks_unexpected_exception_is_contained(monkeypatch):
    ctx, runner = healthy_macos(monkeypatch)
    runner.outputs[("route", "-n", "get", "192.0.2.1")] = ValueError("odd output")
    results = audit.run_checks(ctx, runner=runner, killswitch=StubKillSwitch(True), platform="darwin")
    assert len(results) == len(CHECK_NAMES)
    assert not results[5].ok and "odd output" in results[5].detail


# --------------------------------------------------------- format_table, all_ok

def test_format_table_aligns_rows():
    results = [
        CheckResult("tunnel_up", True, "utun4 has a recent handshake"),
        CheckResult("dns_via_tunnel", False, "system resolver(s) not from the tunnel: 192.0.2.1"),
    ]
    assert audit.format_table(results) == (
        "PASS  tunnel_up       utun4 has a recent handshake\n"
        "FAIL  dns_via_tunnel  system resolver(s) not from the tunnel: 192.0.2.1"
    )


def test_format_table_empty():
    assert audit.format_table([]) == "no checks run"


def test_all_ok_true_only_when_every_check_passes():
    passing = [CheckResult("a", True, ""), CheckResult("b", True, "")]
    assert audit.all_ok(passing)
    assert not audit.all_ok(passing + [CheckResult("c", False, "")])


def test_all_ok_false_for_empty_list():
    assert not audit.all_ok([])
