from pathlib import Path

import pytest

from rotator.backends import linux, macos
from rotator.backends.linux import (
    LinuxBackend,
    parse_ip_neigh,
    parse_ip_route_gateway,
    parse_iw_link,
    parse_nmcli_dns,
)
from rotator.backends.macos import (
    MacOSBackend,
    parse_arp,
    parse_dhcp_dns,
    parse_route_gateway,
)

SAMPLES = Path(__file__).parent / "samples"


def sample(name: str) -> str:
    return (SAMPLES / name).read_text()


class FakeRun:
    """Stands in for rotator.backends.*.run: canned output per argument tuple."""

    def __init__(self, responses: dict[tuple, str] | None = None):
        self.responses = responses or {}
        self.calls: list[tuple] = []

    def __call__(self, *args: str, check: bool = True) -> str:
        self.calls.append(args)
        return self.responses.get(args, "")


# --- macOS parsers ---------------------------------------------------------

def test_parse_arp_keeps_only_the_named_interface():
    result = parse_arp(sample("arp_macos.txt"), "en0")

    assert result == {
        "192.0.2.1": {"02:00:5e:10:00:01"},
        "192.0.2.50": {"96:d8:d5:00:00:50"},
        "192.0.2.52": {"5c:3e:1b:00:00:52"},
    }


def test_parse_arp_skips_incomplete_entries():
    result = parse_arp(sample("arp_macos.txt"), "en0")

    assert "169.254.169.254" not in result


def test_parse_arp_pads_unpadded_octets():
    # The sample's en4 line is printed as 0:1b:63:a:b:c.
    result = parse_arp(sample("arp_macos.txt"), "en4")

    assert result == {"198.51.100.7": {"00:1b:63:0a:0b:0c"}}


def test_parse_arp_reports_two_macs_for_a_conflicting_ip():
    result = parse_arp(sample("arp_macos_conflict.txt"), "en0")

    assert result["192.0.2.1"] == {"02:00:5e:10:00:01", "02:00:5e:66:66:66"}
    assert result["192.0.2.50"] == {"96:d8:d5:00:00:50"}


def test_parse_arp_empty_output():
    assert parse_arp("", "en0") == {}


def test_parse_arp_skips_incomplete_without_mac():
    output = "? (192.0.2.9) at (incomplete) on en0 ifscope [ethernet]\n"

    assert parse_arp(output, "en0") == {}


def test_parse_dhcp_dns_returns_servers_in_order():
    assert parse_dhcp_dns(sample("dhcp_macos.txt")) == ["192.0.2.53", "192.0.2.1"]


def test_parse_dhcp_dns_empty_when_missing():
    assert parse_dhcp_dns("op = BOOTREPLY\nyiaddr = 192.0.2.77\n") == []
    assert parse_dhcp_dns("") == []


def test_parse_route_gateway():
    output = "   route to: default\n   gateway: 192.0.2.1\n  interface: en0\n"

    assert parse_route_gateway(output) == "192.0.2.1"
    assert parse_route_gateway("") is None


def test_macos_neighbours_calls_arp_and_filters(monkeypatch):
    fake = FakeRun({("arp", "-an"): sample("arp_macos_conflict.txt")})
    monkeypatch.setattr(macos, "run", fake)

    result = MacOSBackend("en0").neighbours()

    assert fake.calls == [("arp", "-an")]
    assert result["192.0.2.1"] == {"02:00:5e:10:00:01", "02:00:5e:66:66:66"}


def test_macos_gateway_calls_route_with_ifscope(monkeypatch):
    fake = FakeRun({
        ("route", "-n", "get", "-ifscope", "en0", "default"):
            "   gateway: 192.0.2.1\n",
    })
    monkeypatch.setattr(macos, "run", fake)

    assert MacOSBackend("en0").gateway() == "192.0.2.1"
    assert fake.calls == [("route", "-n", "get", "-ifscope", "en0", "default")]


def test_macos_dhcp_dns_calls_ipconfig_getpacket(monkeypatch):
    fake = FakeRun({("ipconfig", "getpacket", "en0"): sample("dhcp_macos.txt")})
    monkeypatch.setattr(macos, "run", fake)

    assert MacOSBackend("en0").dhcp_dns() == ["192.0.2.53", "192.0.2.1"]
    assert fake.calls == [("ipconfig", "getpacket", "en0")]


def test_macos_wifi_is_redacted(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(macos, "run", fake)

    assert MacOSBackend("en0").ssid() is None
    assert MacOSBackend("en0").bssid() is None
    assert fake.calls == []


# --- Linux parsers ---------------------------------------------------------

def test_parse_ip_neigh_keeps_only_the_named_interface():
    result = parse_ip_neigh(sample("ip_neigh_linux.txt"), "wlan0")

    assert result == {
        "192.0.2.1": {"02:00:5e:10:00:01"},
        "192.0.2.50": {"96:d8:d5:00:00:50"},
        "fe80::1": {"02:00:5e:10:00:01"},
    }


def test_parse_ip_neigh_skips_failed_and_lladdr_less_lines():
    result = parse_ip_neigh(sample("ip_neigh_linux.txt"), "wlan0")

    assert "192.0.2.99" not in result


def test_parse_ip_neigh_filters_eth0_and_pads_macs():
    result = parse_ip_neigh(sample("ip_neigh_linux.txt"), "eth0")

    assert result == {"198.51.100.7": {"00:1b:63:0a:0b:0c"}}


def test_parse_ip_neigh_skips_incomplete_and_failed_states():
    output = (
        "192.0.2.7 dev wlan0 lladdr 02:00:5e:00:00:07 INCOMPLETE\n"
        "192.0.2.8 dev wlan0 lladdr 02:00:5e:00:00:08 FAILED\n"
    )

    assert parse_ip_neigh(output, "wlan0") == {}


def test_parse_ip_neigh_empty_output():
    assert parse_ip_neigh("", "wlan0") == {}


def test_parse_nmcli_dns_splits_on_pipe():
    assert parse_nmcli_dns(sample("nmcli_dns_linux.txt")) == ["192.0.2.53", "192.0.2.1"]


def test_parse_nmcli_dns_empty_output():
    assert parse_nmcli_dns("") == []
    assert parse_nmcli_dns("\n") == []


def test_parse_iw_link_connected():
    assert parse_iw_link(sample("iw_link_linux.txt")) == (
        "CafeGuest", "02:00:5e:aa:bb:cc",
    )


def test_parse_iw_link_disconnected():
    assert parse_iw_link(sample("iw_link_linux_disconnected.txt")) == (None, None)


def test_parse_iw_link_empty_output():
    assert parse_iw_link("") == (None, None)


def test_parse_ip_route_gateway():
    output = "default via 192.0.2.1 proto dhcp metric 600\n"

    assert parse_ip_route_gateway(output) == "192.0.2.1"
    assert parse_ip_route_gateway("") is None


def test_linux_neighbours_calls_ip_neigh_show_dev(monkeypatch):
    fake = FakeRun({("ip", "neigh", "show", "dev", "wlan0"): sample("ip_neigh_linux.txt")})
    monkeypatch.setattr(linux, "run", fake)

    result = LinuxBackend("wlan0").neighbours()

    assert fake.calls == [("ip", "neigh", "show", "dev", "wlan0")]
    assert result["192.0.2.1"] == {"02:00:5e:10:00:01"}


def test_linux_dhcp_dns_calls_nmcli(monkeypatch):
    fake = FakeRun({
        ("nmcli", "-g", "IP4.DNS", "device", "show", "wlan0"): sample("nmcli_dns_linux.txt"),
    })
    monkeypatch.setattr(linux, "run", fake)
    monkeypatch.setattr(linux.shutil, "which", lambda name: "/usr/bin/nmcli")

    assert LinuxBackend("wlan0").dhcp_dns() == ["192.0.2.53", "192.0.2.1"]
    assert fake.calls == [("nmcli", "-g", "IP4.DNS", "device", "show", "wlan0")]


def test_linux_dhcp_dns_empty_without_nmcli(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(linux, "run", fake)
    monkeypatch.setattr(linux.shutil, "which", lambda name: None)

    assert LinuxBackend("wlan0").dhcp_dns() == []
    assert fake.calls == []


def test_linux_wifi_calls_iw_link(monkeypatch):
    fake = FakeRun({("iw", "dev", "wlan0", "link"): sample("iw_link_linux.txt")})
    monkeypatch.setattr(linux, "run", fake)
    monkeypatch.setattr(linux.shutil, "which", lambda name: "/usr/sbin/iw")

    backend = LinuxBackend("wlan0")

    assert backend.ssid() == "CafeGuest"
    assert backend.bssid() == "02:00:5e:aa:bb:cc"
    assert fake.calls == [
        ("iw", "dev", "wlan0", "link"),
        ("iw", "dev", "wlan0", "link"),
    ]


def test_linux_wifi_none_without_iw(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(linux, "run", fake)
    monkeypatch.setattr(linux.shutil, "which", lambda name: None)

    assert LinuxBackend("wlan0").ssid() is None
    assert LinuxBackend("wlan0").bssid() is None
    assert fake.calls == []


def test_linux_gateway_calls_ip_route(monkeypatch):
    fake = FakeRun({
        ("ip", "route", "show", "default", "dev", "wlan0"):
            "default via 192.0.2.1 proto dhcp metric 600\n",
    })
    monkeypatch.setattr(linux, "run", fake)

    assert LinuxBackend("wlan0").gateway() == "192.0.2.1"
    assert fake.calls == [("ip", "route", "show", "default", "dev", "wlan0")]
