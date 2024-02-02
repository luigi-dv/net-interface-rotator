"""Linux backend (iproute2, /sys)."""
import re
import shutil
from pathlib import Path

from .. import mac as macmod
from .base import Backend, BackendError, run


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
        out = run("ip", "route", "show", "default", "dev", self.interface, check=False)
        gw = re.search(r"via\s+(\S+)", out)
        if not gw:
            return None
        neigh = run("ip", "neigh", "show", gw.group(1), "dev", self.interface, check=False)
        gw_mac = re.search(r"lladdr\s+([0-9a-f:]+)", neigh)
        return f"{gw.group(1)}@{gw_mac.group(1) if gw_mac else '?'}"
