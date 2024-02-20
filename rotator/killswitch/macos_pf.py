"""macOS kill switch: pf rules in our own anchor.

The stock /etc/pf.conf evaluates ``anchor "com.apple/*"``, so the rules live
in a child of that anchor. Children are evaluated in name order, so ours is
named to sort ahead of Apple's own (``200.AirDrop`` and so on). Only this
anchor is ever loaded or flushed, and pf is enabled through a reference token
so that unloading releases only our own reference. The main ruleset is never
replaced, flushed or disabled. The one thing touched outside the anchor is
pf's state table, which is flushed after every load.
"""
import re
import subprocess

from ..backends.base import BackendError, command_env
from ._common import check_endpoints, check_iface

ANCHOR = "com.apple/000.net-interface-rotator"
LOOPBACK = "lo0"

BLOCK_ALL = "block drop quick all"

_TOKEN = re.compile(r"Token\s*:\s*(\d+)")
_PARENT_ANCHOR = re.compile(r'^\s*anchor "com\.apple/\*"', re.MULTILINE)


def build_rules(iface: str, tunnel_if: str | None, endpoints: list[tuple[str, int]],
                allow_portal: bool, *, silent: bool = False, allow_dhcp: bool = True) -> str:
    """The pf ruleset for our anchor. Pure; output is deterministic.

    Default deny on **every** interface, IPv4 and IPv6: loopback passes, the
    tunnel interface passes, the physical ``iface`` passes outbound DHCP, the
    tunnel endpoints and (``allow_portal``) web and DNS, and the final rule
    blocks everything else wherever it is. A second interface (Ethernet,
    tethering, awdl0) therefore passes nothing. Every rule is ``quick``: the
    first match decides. Replies pass through pf state only.

    ``silent=True`` is the ruleset for a session that has gone silent:
    ``tunnel_if``, ``endpoints`` and ``allow_portal`` are ignored, so only
    loopback and outbound DHCP pass and a tunnel that is still running has
    no way out. With ``allow_dhcp=False`` as well this is the *lockdown*
    ruleset used while the identity changes: only loopback passes.

    States opened under an earlier ruleset outlive a reload, which is why
    ``load`` flushes them every time.
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

    out = f"pass out quick on {iface}"
    lines = [f"pass quick on {LOOPBACK} all no state"]
    if tunnel_if is not None:
        lines.append(f"pass quick on {tunnel_if} all no state")
    if allow_dhcp:
        lines.append(f"{out} inet proto udp from any port 68 to any port 67 keep state")
    for ip, port in eps:
        lines.append(f"{out} inet proto udp from any to {ip} port {port} keep state")
    if allow_portal:
        lines += [
            f"{out} inet proto tcp from any to any port 80 flags S/SA keep state",
            f"{out} inet proto tcp from any to any port 443 flags S/SA keep state",
            f"{out} inet proto udp from any to any port 53 keep state",
            f"{out} inet proto tcp from any to any port 53 flags S/SA keep state",
        ]
    lines.append(BLOCK_ALL)
    return "\n".join(lines) + "\n"


def _pfctl(*args: str, input: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["pfctl", *args]
    try:
        # Not ``backends.base.run``: the exit status and stderr are needed here
        # (pfctl prints its enable token on stderr). Same fixed environment.
        result = subprocess.run(cmd, input=input, capture_output=True, text=True,
                                errors="replace", env=command_env("pfctl"))
    except FileNotFoundError as e:
        raise BackendError("Command not found: pfctl") from e
    if check and result.returncode != 0:
        raise BackendError(
            f"`{' '.join(cmd)}` failed: {result.stderr.strip() or result.returncode}")
    return result


def _require_parent_anchor() -> None:
    if not _PARENT_ANCHOR.search(_pfctl("-sr").stdout):
        raise BackendError(
            'The main pf ruleset does not evaluate anchor "com.apple/*", so the kill '
            "switch rules would have no effect. Refusing to continue.")


def _ends_with_block_all(rules: str) -> bool:
    lines = [line.strip() for line in rules.splitlines() if line.strip()]
    return bool(lines) and lines[-1] == BLOCK_ALL


def load(rules: str, undo: dict | None = None) -> dict:
    """Load ``rules`` into our anchor, make sure pf is enabled, flush states.

    First call: ``undo`` is None and pf is enabled by reference. Reload: pass
    the dict returned by the first call; the anchor's rules are replaced in
    one step and no second enable reference is taken.

    Every load ends by flushing pf's state table, because a state lets its
    connection carry on whatever the new rules say: connections opened before
    the kill switch, or during a captive-portal window, would otherwise
    survive the tighter ruleset. All states are flushed, not one interface's,
    since the rules deny on every interface. Whatever the rules still allow
    simply creates a new state with its next outbound packet.

    Journal contract: the caller records a kill-switch journal entry *before*
    the first call (no token yet), then journals the returned token.
    ``unload`` accepts either form: without a token it flushes the anchor and
    releases nothing.
    """
    token = (undo or {}).get("token")
    if not _ends_with_block_all(rules):
        raise BackendError("Refusing to load kill switch rules that do not end by blocking everything")

    _require_parent_anchor()
    _pfctl("-a", ANCHOR, "-f", "-", input=rules)
    if token is not None:
        _pfctl("-F", "states")
        return {"anchor": ANCHOR, "token": str(token)}

    new_token = None
    try:
        new_token = _enable()
        _pfctl("-F", "states")
    except BackendError:
        _pfctl("-a", ANCHOR, "-F", "all", check=False)
        if new_token is not None:
            _pfctl("-X", new_token, check=False)
        raise
    return {"anchor": ANCHOR, "token": new_token}


def _enable() -> str:
    """Take one pf enable reference and return its token."""
    result = _pfctl("-E")
    found = _TOKEN.search(result.stderr) or _TOKEN.search(result.stdout)
    if not found:
        raise BackendError("pfctl -E did not return an enable token")
    return found.group(1)


def _enabled() -> bool:
    info = _pfctl("-si", check=False)
    return info.returncode == 0 and "Status: Enabled" in info.stdout


def ensure_enabled() -> str | None:
    """Enable pf again if something disabled it. Returns the new enable
    token, which the caller must journal (``pf_token``), or None when pf was
    still enabled and nothing was done."""
    if _enabled():
        return None
    return _enable()


def unload(undo: dict) -> list[str]:
    """Flush our anchor and release our enable reference. Nothing else.

    Raises if the anchor cannot be flushed. A token that pf no longer knows
    (for example after a reboot) is reported as a warning, not an error.
    """
    warnings = []
    token = (undo or {}).get("token")
    flush_error = None
    try:
        _pfctl("-a", ANCHOR, "-F", "all")
    except BackendError as e:
        flush_error = e
    if token is not None:
        result = _pfctl("-X", str(token), check=False)
        if result.returncode != 0:
            warnings.append(
                f"pfctl -X could not release the enable token: "
                f"{result.stderr.strip() or result.returncode}")
    if flush_error is not None:
        raise flush_error
    return warnings


def drop_states(iface: str | None = None) -> None:
    """Drop pf states: every state, or only those on ``iface``. ``load``
    already flushes every state after each load."""
    if iface is None:
        _pfctl("-F", "states")
    else:
        _pfctl("-i", check_iface(iface), "-F", "states")


def release_token(token) -> list[str]:
    """Release one pf enable reference and touch nothing else.

    For callers that journal the token separately from the anchor (the anchor
    entry is then undone with ``unload`` and no token). Like ``unload``, a
    token pf no longer knows is a warning, so releasing twice is harmless.
    """
    if not str(token).isdigit():
        raise BackendError("pf enable token is not a number")
    result = _pfctl("-X", str(token), check=False)
    if result.returncode != 0:
        return [
            f"pfctl -X could not release the enable token: "
            f"{result.stderr.strip() or result.returncode}"]
    return []


def is_loaded() -> bool:
    """True only when the kill switch is really in force: the main ruleset
    still evaluates ``com.apple/*``, our anchor's rules end with the rule
    that blocks everything, and pf is enabled."""
    main = _pfctl("-sr", check=False)
    if main.returncode != 0 or not _PARENT_ANCHOR.search(main.stdout):
        return False
    rules = _pfctl("-a", ANCHOR, "-sr", check=False)
    if rules.returncode != 0 or not _ends_with_block_all(rules.stdout):
        return False
    return _enabled()
