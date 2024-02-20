"""Linux kill switch: one nftables table of our own.

A drop verdict in any base chain is final, so other tables cannot let through
what this one drops. Only this table is ever created or deleted.
"""
import subprocess

from ..backends.base import BackendError, command_env
from ._common import check_endpoints, check_iface

FAMILY = "inet"
TABLE = "net_interface_rotator"
LOOPBACK = "lo"
# After connection tracking (-200), which the input chain relies on, and just
# ahead of the conventional filter priority (0).
PRIORITY = -10
DROP_ALL = "drop"  # no interface, no family: everything not accepted above


def build_rules(iface: str, tunnel_if: str | None, endpoints: list[tuple[str, int]],
                allow_portal: bool, *, silent: bool = False, allow_dhcp: bool = True) -> str:
    """The nft script for our table. Pure; output is deterministic.

    Default deny on **every** interface, IPv4 and IPv6: loopback is accepted,
    the tunnel interface is accepted, the physical ``iface`` gets DHCP, the
    tunnel endpoints and (``allow_portal``) web and DNS, and each chain ends
    with a bare ``drop``. Nothing is forwarded.

    The leading ``add table`` / ``delete table`` pair makes the script replace
    any earlier copy of the table within a single atomic transaction.

    ``silent=True`` is the ruleset for a session that has gone silent:
    ``tunnel_if``, ``endpoints`` and ``allow_portal`` are ignored, so only
    loopback and DHCP pass and a tunnel that is still running has no way out.
    With ``allow_dhcp=False`` as well this is the *lockdown* ruleset used
    while the identity changes: only loopback passes.
    """
    check_iface(iface)
    if silent:
        tunnel_if, eps, allow_portal = None, [], False
    else:
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

    if allow_dhcp:
        inp.append(f"{i} {v4} udp sport 67 udp dport 68 ct state established accept")
        outp.append(f"{o} {v4} udp sport 68 udp dport 67 accept")
    for ip, port in eps:
        inp.append(f"{i} ip saddr {ip} udp sport {port} ct state established accept")
        outp.append(f"{o} ip daddr {ip} udp dport {port} accept")
    if allow_portal:
        for proto, port in (("tcp", 80), ("tcp", 443), ("udp", 53), ("tcp", 53)):
            inp.append(f"{i} {v4} {proto} sport {port} ct state established accept")
            outp.append(f"{o} {v4} {proto} dport {port} accept")
    inp.append(DROP_ALL)
    outp.append(DROP_ALL)
    fwd = [DROP_ALL]

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
        # Not ``backends.base.run``: the exit status and stderr are needed here
        # (pfctl prints its enable token on stderr). Same fixed environment.
        result = subprocess.run(cmd, input=input, capture_output=True, text=True,
                                errors="replace", env=command_env("nft"))
    except FileNotFoundError as e:
        raise BackendError("Command not found: nft") from e
    if check and result.returncode != 0:
        raise BackendError(
            f"`{' '.join(cmd)}` failed: {result.stderr.strip() or result.returncode}")
    return result


def _chains_end_with_drop(rules: str) -> bool:
    """Whether input, output and forward all exist and end with a bare drop."""
    lines = [line.strip() for line in rules.splitlines()]
    ended = set()
    for n, line in enumerate(lines):
        if line == "}" and n >= 1 and lines[n - 1] == DROP_ALL:
            for back in range(n - 1, -1, -1):
                if lines[back].startswith("chain "):
                    ended.add(lines[back].split()[1])
                    break
    return ended == {"input", "output", "forward"}


def load(rules: str, undo: dict | None = None) -> dict:
    """Load (or atomically replace) our table. ``undo`` is accepted for
    symmetry with the macOS module and is not needed here."""
    if f"table {FAMILY} {TABLE} {{" not in rules or not _chains_end_with_drop(rules):
        raise BackendError(
            "Refusing to load kill switch rules without our table or whose chains do not "
            "end by dropping everything")
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
