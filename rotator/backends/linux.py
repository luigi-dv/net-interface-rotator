"""Linux backend (iproute2, /sys)."""
import re
import shutil
from pathlib import Path

from .. import mac as macmod
from .base import Backend, BackendError, run


HOSTNAME_PATH = Path("/proc/sys/kernel/hostname")
_VIA_RE = re.compile(r"via\s+(\S+)")
_IW_CONNECTED_RE = re.compile(r"^Connected to\s+(\S+)", re.M)
_IW_SSID_RE = re.compile(r"^\s*SSID:[ \t]*(.*?)\s*$", re.M)
_NEIGH_SKIP_STATES = {"FAILED", "INCOMPLETE"}


def parse_ip_route_gateway(output: str) -> str | None:
    """The gateway IP from ``ip route show default dev <iface>`` output, or None."""
    gw = _VIA_RE.search(output)
    return gw.group(1) if gw else None


def parse_ip_neigh(output: str, interface: str) -> dict[str, set[str]]:
    """IP -> MACs from ``ip neigh show dev <iface>`` output, for ``interface`` only.

    Lines without ``lladdr`` and FAILED/INCOMPLETE entries are skipped. IPv6
    entries are kept.
    """
    result: dict[str, set[str]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2 or "lladdr" not in parts or "dev" not in parts:
            continue
        if _NEIGH_SKIP_STATES & set(parts):
            continue
        dev_at = parts.index("dev") + 1
        if dev_at >= len(parts) or parts[dev_at] != interface:
            continue
        lladdr_at = parts.index("lladdr") + 1
        if lladdr_at >= len(parts):
            continue
        try:
            mac = macmod.normalize(parts[lladdr_at])
        except ValueError:
            continue
        result.setdefault(parts[0], set()).add(mac)
    return result


def parse_nmcli_dns(output: str) -> list[str]:
    """DNS servers from ``nmcli -g IP4.DNS device show <iface>`` output, in order."""
    return [s.strip() for s in output.replace("\n", "|").split("|") if s.strip()]


def parse_iw_link(output: str) -> tuple[str | None, str | None]:
    """(ssid, bssid) from ``iw dev <iface> link`` output.

    ``Not connected.`` (or any output without a connection) gives (None, None).
    """
    connected = _IW_CONNECTED_RE.search(output)
    if not connected:
        return None, None
    try:
        bssid: str | None = macmod.normalize(connected.group(1))
    except ValueError:
        bssid = None
    ssid_match = _IW_SSID_RE.search(output)
    ssid = ssid_match.group(1) if ssid_match and ssid_match.group(1) else None
    return ssid, bssid


class LinuxBackend(Backend):
    def _sys(self, name: str) -> Path:
        return Path("/sys/class/net") / self.interface / name

    def current_mac(self) -> str:
        try:
            return macmod.normalize(self._sys("address").read_text())
        except FileNotFoundError as e:
            raise BackendError(f"Interface {self.interface} not found") from e

    def hardware_mac(self) -> str | None:
        # iproute2 shows `permaddr` once the address has been changed.
        out = run("ip", "link", "show", "dev", self.interface, check=False)
        m = re.search(r"permaddr\s+([0-9a-f:]{17})", out)
        if m:
            return macmod.normalize(m.group(1))
        if shutil.which("ethtool"):
            out = run("ethtool", "-P", self.interface, check=False)
            m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", out)
            if m and m.group(1) != "00:00:00:00:00:00":
                return macmod.normalize(m.group(1))
        return None

    def set_mac(self, mac: str) -> None:
        mac = macmod.normalize(mac)
        run("ip", "link", "set", "dev", self.interface, "down")
        try:
            run("ip", "link", "set", "dev", self.interface, "address", mac)
        finally:
            run("ip", "link", "set", "dev", self.interface, "up")
        if self.current_mac() != mac:
            raise BackendError(f"{self.interface} did not accept {mac}")

    def network_id(self) -> str | None:
        gw = self.gateway()
        if gw is None:
            return None
        neigh = run("ip", "neigh", "show", gw, "dev", self.interface, check=False)
        gw_mac = re.search(r"lladdr\s+([0-9a-f:]+)", neigh)
        return f"{gw}@{gw_mac.group(1) if gw_mac else '?'}"

    def gateway(self) -> str | None:
        out = run("ip", "route", "show", "default", "dev", self.interface, check=False)
        return parse_ip_route_gateway(out)

    def neighbours(self) -> dict[str, set[str]]:
        return parse_ip_neigh(
            run("ip", "neigh", "show", "dev", self.interface, check=False), self.interface
        )

    def dhcp_dns(self) -> list[str]:
        if not shutil.which("nmcli"):
            return []
        return parse_nmcli_dns(
            run("nmcli", "-g", "IP4.DNS", "device", "show", self.interface, check=False)
        )

    def _iw_link(self) -> tuple[str | None, str | None]:
        if not shutil.which("iw"):
            return None, None
        return parse_iw_link(run("iw", "dev", self.interface, "link", check=False))

    def ssid(self) -> str | None:
        return self._iw_link()[0]

    def bssid(self) -> str | None:
        return self._iw_link()[1]

    def get_hostname(self) -> dict[str, str | None]:
        return {"transient": HOSTNAME_PATH.read_text().strip()}

    def set_hostname(self, names: dict[str, str | None]) -> None:
        for key, value in names.items():
            if value is None:
                continue
            if key != "transient":
                raise ValueError(f"Unknown host name key: {key}")
            run("hostnamectl", "set-hostname", "--transient", value)

    # Inbound exposure: nothing to do here. On Linux, inbound blocking comes
    # from the session's own nftables table (the Phase 2 kill switch), which is
    # removed as a whole, so there is no host firewall setting to save.

    def get_inbound(self) -> dict[str, bool]:
        """No-op: inbound blocking on Linux is the Phase 2 nftables table."""
        return {}

    def harden_inbound(self) -> dict[str, bool]:
        """No-op: inbound blocking on Linux is the Phase 2 nftables table."""
        return {}

    def restore_inbound(self, previous: dict[str, bool]) -> None:
        """No-op: inbound blocking on Linux is the Phase 2 nftables table."""
