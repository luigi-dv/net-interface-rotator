"""macOS backend (ifconfig / networksetup / route / arp)."""
import re
import time

from .. import mac as macmod
from .base import Backend, BackendError, run

_ETHER_RE = re.compile(r"^\s*ether\s+([0-9a-f:]{17})", re.M)


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
            f"{self.interface} still reports {self.current_mac()} instead of {mac}. "
            "The driver may not allow MAC changes."
        )

    def network_id(self) -> str | None:
        # macOS 15+ redacts the SSID without Location Services, so identify the
        # network by its default gateway (IP + MAC) on this interface instead.
        out = run("route", "-n", "get", "-ifscope", self.interface, "default", check=False)
        gw = re.search(r"gateway:\s*(\S+)", out)
        if not gw:
            return None
        arp = run("arp", "-n", gw.group(1), check=False)
        gw_mac = re.search(r" at ([0-9a-f:]+) ", arp)
        return f"{gw.group(1)}@{gw_mac.group(1) if gw_mac else '?'}"
