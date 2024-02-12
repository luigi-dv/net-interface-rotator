"""In-memory test doubles for the platform backends."""
from rotator import mac
from rotator.backends.base import Backend


class FakeBackend(Backend):
    def __init__(self, interface: str = "en0", mac: str = "aa:bb:cc:dd:ee:ff",
                 hardware: str | None = None, network: str | None = None,
                 hostnames: dict[str, str | None] | None = None,
                 inbound: dict[str, bool] | None = None,
                 gateway_ip: str | None = None,
                 neigh: dict[str, set[str]] | None = None,
                 dns: list[str] | None = None,
                 wifi_ssid: str | None = None,
                 wifi_bssid: str | None = None):
        super().__init__(interface)
        self.mac = mac
        self.hardware = hardware
        self.network = network
        self.gateway_ip = gateway_ip
        self.neigh: dict[str, set[str]] = {ip: set(macs) for ip, macs in (neigh or {}).items()}
        self.dns: list[str] = list(dns or [])
        self.wifi_ssid = wifi_ssid
        self.wifi_bssid = wifi_bssid
        self.hostnames: dict[str, str | None] = (
            dict(hostnames) if hostnames is not None
            else {"ComputerName": "Real Mac", "LocalHostName": "Real-Mac", "HostName": None}
        )
        self.set_calls: list[str] = []
        self.hostname_calls: list[dict[str, str | None]] = []
        self.inbound: dict[str, bool] = (
            dict(inbound) if inbound is not None
            else {"global": False, "blockall": False, "stealth": False}
        )
        self.inbound_calls: list[tuple] = []

    def current_mac(self) -> str:
        return self.mac

    def hardware_mac(self) -> str | None:
        return self.hardware

    def set_mac(self, m: str) -> None:
        normalized = mac.normalize(m)
        self.set_calls.append(normalized)
        self.mac = normalized

    def network_id(self) -> str | None:
        return self.network

    def get_hostname(self) -> dict[str, str | None]:
        return dict(self.hostnames)

    def set_hostname(self, names: dict[str, str | None]) -> None:
        self.hostname_calls.append(dict(names))
        for key, value in names.items():
            if value is not None:
                self.hostnames[key] = value

    def get_inbound(self) -> dict[str, bool]:
        return dict(self.inbound)

    def harden_inbound(self) -> dict[str, bool]:
        previous = dict(self.inbound)
        self.inbound_calls.append(("harden",))
        self.inbound = {key: True for key in self.inbound}
        return previous

    def restore_inbound(self, previous: dict[str, bool]) -> None:
        self.inbound_calls.append(("restore", dict(previous)))
        self.inbound.update(previous)

    def gateway(self) -> str | None:
        return self.gateway_ip

    def neighbours(self) -> dict[str, set[str]]:
        return {ip: set(macs) for ip, macs in self.neigh.items()}

    def dhcp_dns(self) -> list[str]:
        return list(self.dns)

    def ssid(self) -> str | None:
        return self.wifi_ssid

    def bssid(self) -> str | None:
        return self.wifi_bssid
