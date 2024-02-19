"""macOS backend (ifconfig / networksetup / route / arp)."""
import re
import time

from .. import mac as macmod
from .base import Backend, BackendError, run

_ETHER_RE = re.compile(r"^\s*ether\s+([0-9a-f:]{17})", re.M)
_HOSTNAME_KEYS = ("ComputerName", "LocalHostName", "HostName")

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
# Journal key -> (read flag, write flag), in the order hardening applies them.
# Restoring walks this in reverse.
_INBOUND_SETTINGS = (
    ("global", "--getglobalstate", "--setglobalstate"),
    ("blockall", "--getblockall", "--setblockall"),
    ("stealth", "--getstealthmode", "--setstealthmode"),
)
_STATE_RE = re.compile(r"State\s*=\s*(\d+)", re.I)
_ON_RE = re.compile(r"\b(?:enabled|on)\b", re.I)
_OFF_RE = re.compile(r"\b(?:disabled|off)\b", re.I)
# Older macOS reports an active block-all without the word "enabled".
_BLOCKALL_ON_RE = re.compile(r"set to block all", re.I)
_ROUTE_GATEWAY_RE = re.compile(r"gateway:\s*(\S+)")
_DNS_RE = re.compile(r"domain_name_server \(ip_mult\):\s*\{([^}]*)\}")
_MAC_TOKEN_RE = re.compile(r"^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$", re.I)


def parse_firewall_flag(key: str, output: str) -> bool:
    """Turn one ``socketfilterfw --get...`` answer into a bool.

    The wording differs between macOS versions, so this accepts
    ``State = N`` (0 is off, anything else on) and the words
    enabled/disabled/on/off. It raises rather than guess when the output has
    no verdict or a contradictory one.
    """
    verdicts: set[bool] = set()
    state = _STATE_RE.search(output)
    if state:
        verdicts.add(int(state.group(1)) != 0)
    if _ON_RE.search(output):
        verdicts.add(True)
    if _OFF_RE.search(output):
        verdicts.add(False)
    if not verdicts and key == "blockall" and _BLOCKALL_ON_RE.search(output):
        verdicts.add(True)
    if len(verdicts) != 1:
        raise BackendError(
            f"Cannot tell the firewall '{key}' setting from: {output.strip()!r}"
        )
    return verdicts.pop()


def parse_route_gateway(output: str) -> str | None:
    """The gateway IP from ``route -n get ... default`` output, or None."""
    gw = _ROUTE_GATEWAY_RE.search(output)
    return gw.group(1) if gw else None


def parse_arp(output: str, interface: str) -> dict[str, set[str]]:
    """IP -> MACs from ``arp -an`` output, for entries on ``interface`` only.

    macOS prints octets without zero padding (``0:1b:63:a:b:c``), so each octet
    is padded before normalizing. Incomplete entries are skipped.
    """
    result: dict[str, set[str]] = {}
    for line in output.splitlines():
        if f" on {interface} " not in line or "(incomplete)" in line:
            continue
        m = re.match(r"^\S+\s+\(([^)]+)\)\s+at\s+(\S+)", line)
        if not m or not _MAC_TOKEN_RE.match(m.group(2)):
            continue
        octets = (o.zfill(2) for o in m.group(2).split(":"))
        try:
            mac = macmod.normalize(":".join(octets))
        except ValueError:
            continue
        result.setdefault(m.group(1), set()).add(mac)
    return result


def parse_dhcp_dns(output: str) -> list[str]:
    """DNS servers from ``ipconfig getpacket <iface>`` output, in order."""
    m = _DNS_RE.search(output)
    if not m:
        return []
    return [s.strip() for s in m.group(1).split(",") if s.strip()]


class MacOSBackend(Backend):
    def current_mac(self) -> str:
        m = _ETHER_RE.search(run("ifconfig", self.interface))
        if not m:
            raise BackendError(f"No MAC address found for {self.interface}")
        return macmod.normalize(m.group(1))

    def hardware_mac(self) -> str | None:
        out = run("networksetup", "-getmacaddress", self.interface, check=False)
        m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", out, re.I)
        return macmod.normalize(m.group(1)) if m else None

    def _is_wifi(self) -> bool:
        out = run("networksetup", "-listallhardwareports", check=False)
        for block in out.split("\n\n"):
            if f"Device: {self.interface}" in block:
                return "Wi-Fi" in block or "AirPort" in block
        return False

    def set_mac(self, mac: str) -> None:
        mac = macmod.normalize(mac)
        if self._is_wifi():
            # Recent macOS only accepts a new address while Wi-Fi is not associated
            # to a network. Power-cycling the radio drops the association, and the
            # address must be set right after it comes back, before it rejoins.
            run("networksetup", "-setairportpower", self.interface, "off")
            run("networksetup", "-setairportpower", self.interface, "on")
            run("ifconfig", self.interface, "ether", mac)
        else:
            run("ifconfig", self.interface, "down")
            run("ifconfig", self.interface, "ether", mac)
            run("ifconfig", self.interface, "up")
        for _ in range(10):
            if self.current_mac() == mac:
                return
            time.sleep(0.5)
        raise BackendError(
            f"{self.interface} did not accept the new address. "
            "The driver may not allow MAC changes."
        )

    def network_id(self) -> str | None:
        # macOS 15+ redacts the SSID without Location Services, so identify the
        # network by its default gateway (IP + MAC) on this interface instead.
        gw = self.gateway()
        if gw is None:
            return None
        arp = run("arp", "-n", gw, check=False)
        gw_mac = re.search(r" at ([0-9a-f:]+) ", arp)
        return f"{gw}@{gw_mac.group(1) if gw_mac else '?'}"

    def gateway(self) -> str | None:
        out = run("route", "-n", "get", "-ifscope", self.interface, "default", check=False)
        return parse_route_gateway(out)

    def neighbours(self) -> dict[str, set[str]]:
        return parse_arp(run("arp", "-an", check=False), self.interface)

    def dhcp_dns(self) -> list[str]:
        return parse_dhcp_dns(run("ipconfig", "getpacket", self.interface, check=False))

    def ssid(self) -> str | None:
        # macOS redacts the SSID and BSSID from command-line tools unless the
        # calling app has Location Services access, so they are reported as unknown.
        return None

    def bssid(self) -> str | None:
        # Redacted on macOS as well; see ssid().
        return None

    def get_hostname(self) -> dict[str, str | None]:
        names: dict[str, str | None] = {}
        for key in _HOSTNAME_KEYS:
            out = run("scutil", "--get", key, check=False).strip()
            names[key] = None if not out or "not set" in out else out
        return names

    def set_hostname(self, names: dict[str, str | None]) -> None:
        for key, value in names.items():
            if value is None:
                continue
            run("scutil", "--set", key, value)

    def get_inbound(self) -> dict[str, bool]:
        return {
            key: parse_firewall_flag(key, run(SOCKETFILTERFW, getter))
            for key, getter, _ in _INBOUND_SETTINGS
        }

    def harden_inbound(self) -> dict[str, bool]:
        previous = self.get_inbound()
        try:
            for key, _, setter in _INBOUND_SETTINGS:
                if not previous[key]:
                    run(SOCKETFILTERFW, setter, "on")
            after = self.get_inbound()
            failed = [key for key, _, _ in _INBOUND_SETTINGS if not after[key]]
            if failed:
                raise BackendError(
                    "Firewall settings did not take effect: " + ", ".join(failed)
                )
        except BackendError:
            # The caller never receives ``previous`` when this raises, so undo
            # here whatever was changed before failing.
            try:
                self.restore_inbound(previous)
            except BackendError:
                pass
            raise
        return previous

    def restore_inbound(self, previous: dict[str, bool]) -> None:
        if not previous:
            return
        current = self.get_inbound()
        for key, _, setter in reversed(_INBOUND_SETTINGS):
            if key in previous and current[key] != bool(previous[key]):
                run(SOCKETFILTERFW, setter, "on" if previous[key] else "off")
