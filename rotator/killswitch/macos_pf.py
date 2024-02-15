"""macOS kill switch: pf rules in our own anchor.

The stock /etc/pf.conf evaluates ``anchor "com.apple/*"``, so the rules live
in a child of that anchor. Children are evaluated in name order, so ours is
named to sort ahead of Apple's own (``200.AirDrop`` and so on). Only this anchor is ever loaded or flushed, and pf
is enabled through a reference token so that unloading releases only our own
reference. The main ruleset is never replaced, flushed or disabled.
"""
import re
import subprocess

from ..backends.base import BackendError
from ._common import check_endpoints, check_iface

ANCHOR = "com.apple/000.net-interface-rotator"
LOOPBACK = "lo0"

_TOKEN = re.compile(r"Token\s*:\s*(\d+)")
_PARENT_ANCHOR = re.compile(r'^\s*anchor "com\.apple/\*"', re.MULTILINE)
_BLOCK_ALL = re.compile(r"^block drop quick on (\S+) all$", re.MULTILINE)


def build_rules(iface: str, tunnel_if: str | None, endpoints: list[tuple[str, int]],
                allow_portal: bool, *, silent: bool = False) -> str:
    """The pf ruleset for our anchor. Pure; output is deterministic.

    Every rule is ``quick``: the first match decides, and the final two rules
    block everything else on ``iface``. Replies pass through pf state only.

    ``silent=True`` is the ruleset for a session that has gone silent:
    ``tunnel_if``, ``endpoints`` and ``allow_portal`` are ignored, so only
    loopback and outbound DHCP pass and a tunnel that is still running has
    no way out. States opened earlier outlive a reload; see ``drop_states``.
    """
    check_iface(iface)
    if silent:
        return "\n".join([
            f"pass quick on {LOOPBACK} all no state",
            f"pass out quick on {iface} inet proto udp from any port 68 to any port 67 keep state",
            f"block drop quick on {iface} inet6 all",
            f"block drop quick on {iface} all",
        ]) + "\n"
    if tunnel_if is not None:
        check_iface(tunnel_if)
        if tunnel_if == iface:
            raise ValueError("Tunnel interface must differ from the physical interface")
    eps = check_endpoints(endpoints)

    out = f"pass out quick on {iface}"
    lines = [f"pass quick on {LOOPBACK} all no state"]
    if tunnel_if is not None:
        lines.append(f"pass quick on {tunnel_if} all no state")
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
    lines += [
        f"block drop quick on {iface} inet6 all",
        f"block drop quick on {iface} all",
    ]
    return "\n".join(lines) + "\n"


def _pfctl(*args: str, input: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["pfctl", *args]
    try:
        result = subprocess.run(cmd, input=input, capture_output=True, text=True)
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


def load(rules: str, undo: dict | None = None) -> dict:
    """Load ``rules`` into our anchor and make sure pf is enabled.

    First call: ``undo`` is None; pf is enabled by reference and existing
    states on the physical interface are dropped so that connections opened
    before the kill switch cannot carry on. Reload: pass the dict returned by
    the first call; the anchor's rules are replaced in one step and no second
    enable reference is taken.

    Journal contract: the caller records a kill-switch journal entry *before*
    the first call (no token yet), then adds the returned token to it.
    ``unload`` accepts either form: without a token it flushes the anchor and
    releases nothing.
    """
    token = (undo or {}).get("token")
    match = _BLOCK_ALL.search(rules)
    if not match:
        raise BackendError("Refusing to load kill switch rules without a block-all rule")
    iface = match.group(1)

    _require_parent_anchor()
    _pfctl("-a", ANCHOR, "-f", "-", input=rules)
    if token is not None:
        return {"anchor": ANCHOR, "token": str(token)}

    new_token = None
    try:
        result = _pfctl("-E")
        found = _TOKEN.search(result.stderr) or _TOKEN.search(result.stdout)
        if not found:
            raise BackendError("pfctl -E did not return an enable token")
        new_token = found.group(1)
        _pfctl("-i", iface, "-F", "states")
    except BackendError:
        _pfctl("-a", ANCHOR, "-F", "all", check=False)
        if new_token is not None:
            _pfctl("-X", new_token, check=False)
        raise
    return {"anchor": ANCHOR, "token": new_token}


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


def drop_states(iface: str) -> None:
    """Drop every pf state on ``iface``, so flows that an earlier ruleset
    let through (the tunnel's own packets to its endpoint) cannot carry on
    under a stricter one. ``load`` does this itself on the first load only."""
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
    """True when our anchor holds rules and pf is enabled."""
    rules = _pfctl("-a", ANCHOR, "-sr", check=False)
    if rules.returncode != 0 or not rules.stdout.strip():
        return False
    info = _pfctl("-si", check=False)
    return info.returncode == 0 and "Status: Enabled" in info.stdout
