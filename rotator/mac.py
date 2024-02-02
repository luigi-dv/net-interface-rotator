"""MAC address generation and validation."""
import re
import secrets

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def normalize(mac: str) -> str:
    """Return ``mac`` lower-cased and colon-separated, or raise ValueError."""
    cleaned = mac.strip().lower().replace("-", ":")
    if not _MAC_RE.match(cleaned):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return cleaned


def is_unicast(mac: str) -> bool:
    return int(normalize(mac)[:2], 16) & 0x01 == 0


def is_locally_administered(mac: str) -> bool:
    return int(normalize(mac)[:2], 16) & 0x02 != 0


def generate(exclude: str | None = None) -> str:
    """Generate a random unicast, locally administered MAC address.

    The first octet has the multicast bit cleared and the locally-administered
    bit set, so the address never collides with a real vendor prefix and is
    accepted by drivers that reject multicast addresses.
    """
    while True:
        octets = bytearray(secrets.token_bytes(6))
        octets[0] = (octets[0] & 0b11111100) | 0b00000010
        mac = ":".join(f"{b:02x}" for b in octets)
        if mac != exclude:
            return mac
