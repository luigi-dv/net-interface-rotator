"""Hostile-network detection: pure verdicts over successive network readings.

Detection informs the user; it is not the protection (the tunnel and the kill
switch are). Everything here is pure except ``reading_from``, the one place
that asks a backend for the facts.
"""
from dataclasses import dataclass

ARP_SPOOF_SUSPECTED = "arp_spoof_suspected"
ARP_CONFLICT = "arp_conflict"
NETWORK_RECONFIGURED = "network_reconfigured"
POSSIBLE_EVIL_TWIN = "possible_evil_twin"

ALL_FINDINGS = frozenset(
    {ARP_SPOOF_SUSPECTED, ARP_CONFLICT, NETWORK_RECONFIGURED, POSSIBLE_EVIL_TWIN}
)

# possible_evil_twin only warns by default: large venues legitimately hand a
# device between access points that share one network name.
DEFAULT_STRICT_ON = frozenset({ARP_SPOOF_SUSPECTED, ARP_CONFLICT, NETWORK_RECONFIGURED})

WARN = "warn"
GO_SILENT = "go_silent"


@dataclass(frozen=True)
class Reading:
    """What the network looked like at one moment."""

    gateway: str | None  # None when disconnected
    gateway_macs: frozenset[str]  # every MAC seen answering for the gateway IP
    dns: tuple[str, ...]  # DHCP-supplied resolvers, in the order given
    ssid: str | None  # None where the OS redacts it (macOS)
    bssid: str | None  # None where the OS redacts it (macOS)


def reading_from(backend) -> Reading:
    """Take one reading through ``backend``. The only I/O in this module."""
    gateway = backend.gateway()
    macs = backend.neighbours().get(gateway, set()) if gateway else set()
    bssid = backend.bssid()
    return Reading(
        gateway=gateway,
        gateway_macs=frozenset(m.lower() for m in macs),
        dns=tuple(backend.dhcp_dns()),
        ssid=backend.ssid(),
        bssid=bssid.lower() if bssid else None,
    )


def findings(baseline: Reading, previous: Reading, current: Reading) -> set[str]:
    """Names of everything suspicious about ``current``.

    ``baseline`` is the reading taken once the session was established; every
    finding is judged against it, so a finding persists for as long as the
    condition does. ``previous`` (the reading before ``current``) is accepted
    so callers pass the full sequence, but no finding depends on it today.

    A disconnected ``current`` yields nothing: the session handles disconnects
    itself.
    """
    if current.gateway is None:
        return set()

    found: set[str] = set()

    if len(current.gateway_macs) > 1:
        found.add(ARP_CONFLICT)

    # An empty MAC set means "no neighbour entry right now", which is not
    # evidence of anything, so both sides must be known.
    if (
        current.gateway == baseline.gateway
        and baseline.gateway_macs
        and current.gateway_macs
        and current.gateway_macs != baseline.gateway_macs
    ):
        found.add(ARP_SPOOF_SUSPECTED)

    # Order is ignored: a reshuffled resolver list alone must not trip strict mode.
    if current.gateway != baseline.gateway or set(current.dns) != set(baseline.dns):
        found.add(NETWORK_RECONFIGURED)

    if (
        baseline.ssid is not None
        and current.ssid is not None
        and baseline.bssid is not None
        and current.bssid is not None
        and current.ssid == baseline.ssid
        and current.bssid != baseline.bssid
    ):
        found.add(POSSIBLE_EVIL_TWIN)

    return found


def _check_names(names) -> None:
    for name in sorted(names):
        if name not in ALL_FINDINGS:
            raise ValueError(
                f"Unknown finding name: {name!r} "
                f"(known: {', '.join(sorted(ALL_FINDINGS))})"
            )


def react(
    current_findings: set[str],
    history: list[set[str]],
    strict: bool,
    strict_on: frozenset[str],
) -> list[tuple[str, str]]:
    """Decide what to do about this check's findings.

    ``history`` holds the findings of the earlier checks, oldest first, and
    does not include ``current_findings``.

    Returns ``(action, finding)`` pairs, warnings first, each group sorted by
    finding name:

    - ``("warn", f)`` the first time ``f`` appears, and not again while it
      persists on consecutive checks. It warns again if it clears and returns.
    - ``("go_silent", f)`` when strict mode is on, ``f`` is in ``strict_on``,
      and ``f`` was seen on this check and the one immediately before. One
      garbled reading is therefore never enough. Emitted once per unbroken run
      of ``f``: on the second consecutive check, not the third or later.
    """
    _check_names(strict_on)

    last = history[-1] if history else set()
    before_last = history[-2] if len(history) >= 2 else set()

    actions = [(WARN, f) for f in sorted(current_findings - last)]
    if strict:
        confirmed = (current_findings & last & strict_on) - before_last
        actions += [(GO_SILENT, f) for f in sorted(confirmed)]
    return actions


def strict_settings(cli_strict: bool | None, environ: dict) -> tuple[bool, frozenset[str]]:
    """Resolve strict mode and the set of findings that trigger it.

    Precedence for the switch: ``--strict`` / ``--no-strict`` (``cli_strict``
    True / False), then ``STRICT=0|1`` in ``environ``, then on by default.
    ``STRICT_ON`` is a comma-separated list of finding names replacing
    ``DEFAULT_STRICT_ON``; a blank value means "not set", so strict mode is
    never emptied by accident.
    """
    raw_on = (environ.get("STRICT_ON") or "").strip()
    if raw_on:
        names = [part.strip() for part in raw_on.split(",")]
        strict_on = frozenset(name for name in names if name)
        _check_names(strict_on)
    else:
        strict_on = DEFAULT_STRICT_ON

    raw = (environ.get("STRICT") or "").strip()
    if raw not in ("", "0", "1"):
        raise ValueError(f"STRICT must be 0 or 1, not {raw!r}")

    if cli_strict is not None:
        strict = cli_strict
    elif raw:
        strict = raw == "1"
    else:
        strict = True
    return strict, strict_on
