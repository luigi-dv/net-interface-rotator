"""In-memory test doubles for the platform backends."""
from rotator import mac
from rotator.backends.base import Backend


class FakeBackend(Backend):
    def __init__(self, interface: str = "en0", mac: str = "aa:bb:cc:dd:ee:ff",
                 hardware: str | None = None, network: str | None = None):
        super().__init__(interface)
        self.mac = mac
        self.hardware = hardware
        self.network = network
        self.set_calls: list[str] = []

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
