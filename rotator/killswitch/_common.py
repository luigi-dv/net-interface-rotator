"""Input checks shared by the kill-switch rule builders.

Everything placed into rule text is validated here first, so a strange
interface name or address can never inject extra rules.
"""
import ipaddress
import re

_IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")


def check_iface(name: str) -> str:
    if not isinstance(name, str) or not _IFACE.fullmatch(name):
        raise ValueError(f"Invalid interface name: {name!r}")
    return name


def check_endpoints(endpoints) -> list[tuple[ipaddress.IPv4Address, int]]:
    """Validate and de-duplicate ``(ip, port)`` pairs, keeping their order.

    IPv4 only: IPv6 is blocked on every interface but the tunnel, so an IPv6
    endpoint could never be reached."""
    seen = []
    for host, port in endpoints:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as e:
            raise ValueError(f"Endpoint is not an IP address: {host!r}") from e
        if ip.version != 4:
            raise ValueError(f"Endpoint must be IPv4: {host!r}")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"Invalid endpoint port: {port!r}")
        if (ip, port) not in seen:
            seen.append((ip, port))
    if not seen:
        raise ValueError("At least one tunnel endpoint is required")
    return seen
