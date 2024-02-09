"""Linux kill switch: one nftables table of our own.

A drop verdict in any base chain is final, so other tables cannot let through
what this one drops. Only this table is ever created or deleted.
"""
import subprocess

from ..backends.base import BackendError
from ._common import check_endpoints, check_iface

FAMILY = "inet"
TABLE = "net_interface_rotator"
LOOPBACK = "lo"
# After connection tracking (-200), which the input chain relies on, and just
# ahead of the conventional filter priority (0).
PRIORITY = -10


def build_rules(iface: str, tunnel_if: str | None, endpoints: list[tuple[str, int]],
                allow_portal: bool) -> str:
    """The nft script for our table. Pure; output is deterministic.

    The leading ``add table`` / ``delete table`` pair makes the script replace
    any earlier copy of the table within a single atomic transaction.
    """
    check_iface(iface)
    if tunnel_if is not None:
        check_iface(tunnel_if)
        if tunnel_if == iface:
            raise ValueError("Tunnel interface must differ from the physical interface")
    eps = check_endpoints(endpoints)

    i, o = f'iifname "{iface}"', f'oifname "{iface}"'
    v4 = "meta nfproto ipv4"

    inp = [f'iifname "{LOOPBACK}" accept']
    outp = [f'oifname "{LOOPBACK}" accept']
    if tunnel_if is not None:
        inp.append(f'iifname "{tunnel_if}" accept')
        outp.append(f'oifname "{tunnel_if}" accept')

    inp.append(f"{i} {v4} udp sport 67 udp dport 68 ct state established accept")
    outp.append(f"{o} {v4} udp sport 68 udp dport 67 accept")
    for ip, port in eps:
        inp.append(f"{i} ip saddr {ip} udp sport {port} ct state established accept")
        outp.append(f"{o} ip daddr {ip} udp dport {port} accept")
    if allow_portal:
        for proto, port in (("tcp", 80), ("tcp", 443), ("udp", 53), ("tcp", 53)):
            inp.append(f"{i} {v4} {proto} sport {port} ct state established accept")
            outp.append(f"{o} {v4} {proto} dport {port} accept")
    inp.append(f"{i} drop")
    outp.append(f"{o} drop")
    fwd = [f"{i} drop", f"{o} drop"]

    lines = [
        f"add table {FAMILY} {TABLE}",
        f"delete table {FAMILY} {TABLE}",
        f"table {FAMILY} {TABLE} {{",
    ]
    for n, (name, rules) in enumerate((("input", inp), ("output", outp), ("forward", fwd))):
        if n:
            lines.append("")
        lines.append(f"\tchain {name} {{")
        lines.append(f"\t\ttype filter hook {name} priority {PRIORITY}; policy accept;")
        lines += [f"\t\t{rule}" for rule in rules]
        lines.append("\t}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _nft(*args: str, input: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["nft", *args]
    try:
        result = subprocess.run(cmd, input=input, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise BackendError("Command not found: nft") from e
    if check and result.returncode != 0:
        raise BackendError(
            f"`{' '.join(cmd)}` failed: {result.stderr.strip() or result.returncode}")
    return result


def load(rules: str, undo: dict | None = None) -> dict:
    """Load (or atomically replace) our table. ``undo`` is accepted for
    symmetry with the macOS module and is not needed here."""
    if f"table {FAMILY} {TABLE} {{" not in rules or " drop" not in rules:
        raise BackendError("Refusing to load kill switch rules without our table and a drop rule")
    _nft("-f", "-", input=rules)
    return {"table": TABLE}


def unload(undo: dict) -> list[str]:
    """Delete our table only. A table that is already gone is not an error."""
    result = _nft("delete", "table", FAMILY, TABLE, check=False)
    if result.returncode != 0 and "No such file or directory" not in result.stderr:
        raise BackendError(
            f"`nft delete table {FAMILY} {TABLE}` failed: "
            f"{result.stderr.strip() or result.returncode}")
    return []


def is_loaded() -> bool:
    """True when our table exists."""
    return _nft("list", "table", FAMILY, TABLE, check=False).returncode == 0
