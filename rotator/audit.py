"""Read-only leak checks for an active session.

Nothing here changes the system. Every command runs through ``runner``
(``rotator.backends.base.run`` by default), so tests pass a fake and never
execute real commands. A check that fails to read its evidence reports the
error as its detail; it never stops the other checks.
"""
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from . import mac as macmod
from .backends.base import Backend, BackendError, run
from .killswitch import platform_module

RESOLV_CONF = Path("/etc/resolv.conf")
_SYSTEMD_STUB = "127.0.0.53"
_ROUTE_PROBE_IP = "192.0.2.1"
_INBOUND_KEYS = ("global", "blockall", "stealth")

_ROUTE_IF_MACOS = re.compile(r"^\s*interface:\s*(\S+)", re.M)
_ROUTE_DEV_LINUX = re.compile(r"\bdev\s+(\S+)")
_NAMESERVER_MACOS = re.compile(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)")
_NAMESERVER_LINUX = re.compile(r"^\s*nameserver\s+(\S+)", re.M)


@dataclass(frozen=True)
class AuditContext:
    backend: Backend
    tunnel_if: str | None
    tunnel_dns: tuple[str, ...]          # DNS servers from the WireGuard config
    original_mac: str | None             # from the journal; None if unknown
    original_hostnames: dict | None      # from the journal; None if unknown
    manage_inbound: bool = True          # False with --keep-firewall


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


class _Unavailable:
    """Stands in for a kill switch module that cannot be loaded here."""

    def __init__(self, reason: str):
        self._reason = reason

    def is_loaded(self) -> bool:
        raise BackendError(self._reason)


def _platform_kind(platform: str) -> str | None:
    if platform == "darwin":
        return "darwin"
    if platform.startswith("linux"):
        return "linux"
    return None


def _unsupported(name: str, platform: str) -> CheckResult:
    return CheckResult(name, False, f"no check for platform {platform!r}")


def _resolve_killswitch(killswitch, platform: str):
    if killswitch is not None:
        return killswitch
    try:
        return platform_module()
    except NotImplementedError as e:
        return _Unavailable(str(e))


# ------------------------------------------------------------------ checks

def check_mac_randomized(ctx: AuditContext, runner=run, *, killswitch=None,
                         platform: str = sys.platform) -> CheckResult:
    name = "mac_randomized"
    current = macmod.normalize(ctx.backend.current_mac())
    if not macmod.is_locally_administered(current):
        return CheckResult(name, False, "current address is a vendor (universal) address")
    compared = ["locally administered"]
    hardware = ctx.backend.hardware_mac()
    if hardware is not None:
        if macmod.normalize(hardware) == current:
            return CheckResult(name, False, "current address equals the hardware address")
        compared.append("differs from hardware address")
    if ctx.original_mac is not None:
        if macmod.normalize(ctx.original_mac) == current:
            return CheckResult(name, False, "current address equals the journaled original")
        compared.append("differs from journaled original")
    return CheckResult(name, True, "; ".join(compared))


def check_hostname_changed(ctx: AuditContext, runner=run, *, killswitch=None,
                           platform: str = sys.platform) -> CheckResult:
    name = "hostname_changed"
    if ctx.original_hostnames is None:
        return CheckResult(name, True, "not managed this session")
    original = {v for v in ctx.original_hostnames.values() if v is not None}
    current = {v for v in ctx.backend.get_hostname().values() if v is not None}
    if original & current:
        return CheckResult(name, False, "a host name still matches the journaled original")
    return CheckResult(name, True, "no host name matches the journaled original")


def check_inbound_blocked(ctx: AuditContext, runner=run, *, killswitch=None,
                          platform: str = sys.platform) -> CheckResult:
    name = "inbound_blocked"
    if not ctx.manage_inbound:
        return CheckResult(name, True, "not managed this session")
    kind = _platform_kind(platform)
    if kind == "linux":
        loaded = bool(killswitch.is_loaded())
        if loaded:
            return CheckResult(name, True, "kill switch loaded, which blocks inbound")
        return CheckResult(name, False, "kill switch not loaded, so inbound is not blocked")
    if kind == "darwin":
        settings = ctx.backend.get_inbound()
        off = [key for key in _INBOUND_KEYS if not settings.get(key)]
        if off:
            return CheckResult(name, False, "firewall not set: " + ", ".join(off))
        return CheckResult(name, True, "firewall on, block-all and stealth set")
    return _unsupported(name, platform)


def check_killswitch_loaded(ctx: AuditContext, runner=run, *, killswitch=None,
                            platform: str = sys.platform) -> CheckResult:
    name = "killswitch_loaded"
    loaded = bool(killswitch.is_loaded())
    return CheckResult(name, loaded, "loaded" if loaded else "not loaded")


def check_tunnel_up(ctx: AuditContext, runner=run, *, killswitch=None,
                    platform: str = sys.platform) -> CheckResult:
    from . import tunnel  # imported here so tests can monkeypatch rotator.tunnel.is_up

    name = "tunnel_up"
    if ctx.tunnel_if is None:
        return CheckResult(name, False, "no tunnel interface")
    if tunnel.is_up(ctx.tunnel_if):
        return CheckResult(name, True, f"{ctx.tunnel_if} has a recent handshake")
    return CheckResult(name, False, f"{ctx.tunnel_if} has no recent handshake")


def check_default_route_via_tunnel(ctx: AuditContext, runner=run, *, killswitch=None,
                                   platform: str = sys.platform) -> CheckResult:
    name = "default_route_via_tunnel"
    if ctx.tunnel_if is None:
        return CheckResult(name, False, "no tunnel interface")
    kind = _platform_kind(platform)
    if kind == "darwin":
        via = _macos_route_iface(runner, "default")
    elif kind == "linux":
        via = _linux_route_dev(runner, _ROUTE_PROBE_IP)
    else:
        return _unsupported(name, platform)
    if via is None:
        return CheckResult(name, False, "could not read the default route's interface")
    if via != ctx.tunnel_if:
        return CheckResult(name, False, f"default route goes via {via}, not {ctx.tunnel_if}")
    return CheckResult(name, True, f"default route goes via {via}")


def check_dns_via_tunnel(ctx: AuditContext, runner=run, *, killswitch=None,
                         platform: str = sys.platform) -> CheckResult:
    name = "dns_via_tunnel"
    if ctx.tunnel_if is None:
        return CheckResult(name, False, "no tunnel interface")
    if not ctx.tunnel_dns:
        return CheckResult(name, False, "the tunnel config lists no DNS servers")
    kind = _platform_kind(platform)
    if kind == "darwin":
        resolvers = _macos_resolvers(runner("scutil", "--dns"))
        route = lambda ip: _macos_route_iface(runner, ip)  # noqa: E731
    elif kind == "linux":
        resolvers = _linux_resolvers(runner, ctx.tunnel_if)
        route = lambda ip: _linux_route_dev(runner, ip)  # noqa: E731
    else:
        return _unsupported(name, platform)

    expected, found = set(ctx.tunnel_dns), set(resolvers)
    if found != expected:
        stray = sorted(found - expected)
        missing = sorted(expected - found)
        problems = []
        if stray:
            problems.append("system resolver(s) not from the tunnel: " + ", ".join(stray))
        if missing:
            problems.append("tunnel resolver(s) not in use: " + ", ".join(missing))
        if not found:
            problems = ["no system resolver found"]
        return CheckResult(name, False, "; ".join(problems))

    off = []
    for ip in sorted(expected):
        iface = route(ip)
        if iface != ctx.tunnel_if:
            off.append(f"{ip} via {iface or 'unknown'}")
    if off:
        return CheckResult(name, False, "resolver routes not via the tunnel: " + ", ".join(off))
    return CheckResult(name, True, f"{len(expected)} resolver(s) match the tunnel config, all via {ctx.tunnel_if}")


def check_ipv6_contained(ctx: AuditContext, runner=run, *, killswitch=None,
                         platform: str = sys.platform) -> CheckResult:
    name = "ipv6_contained"
    if killswitch.is_loaded():
        return CheckResult(name, True, "kill switch blocks IPv6 on the interface")
    iface = ctx.backend.interface
    kind = _platform_kind(platform)
    if kind == "darwin":
        has_global = any(
            parts[0] == "inet6" and not parts[1].startswith("fe80")
            for parts in (line.split() for line in runner("ifconfig", iface).splitlines())
            if len(parts) >= 2
        )
    elif kind == "linux":
        out = runner("ip", "-6", "addr", "show", "dev", iface, "scope", "global")
        has_global = any(
            parts and parts[0] == "inet6"
            for parts in (line.split() for line in out.splitlines())
        )
    else:
        return _unsupported(name, platform)
    if has_global:
        return CheckResult(name, False, f"{iface} has a global IPv6 address and the kill switch is not loaded")
    return CheckResult(name, True, f"{iface} has no global IPv6 address")


# ---------------------------------------------------------------- helpers

def _macos_route_iface(runner, target: str) -> str | None:
    match = _ROUTE_IF_MACOS.search(runner("route", "-n", "get", target))
    return match.group(1) if match else None


def _linux_route_dev(runner, target: str) -> str | None:
    match = _ROUTE_DEV_LINUX.search(runner("ip", "route", "get", target))
    return match.group(1) if match else None


def _macos_resolvers(output: str) -> list[str]:
    """Nameservers of the first ``resolver #1`` block of ``scutil --dns``."""
    lines = output.splitlines()
    start = next((i + 1 for i, line in enumerate(lines) if line.strip() == "resolver #1"), None)
    if start is None:
        return []
    servers = []
    for line in lines[start:]:
        if not line.strip() or line.strip().startswith("resolver #"):
            break
        match = _NAMESERVER_MACOS.match(line)
        if match:
            servers.append(match.group(1))
    return servers


def _linux_resolvers(runner, tunnel_if: str) -> list[str]:
    """Nameservers in use. Behind systemd-resolved, the tunnel link's own list."""
    servers = _NAMESERVER_LINUX.findall(RESOLV_CONF.read_text(encoding="utf-8", errors="replace"))
    if _SYSTEMD_STUB not in servers:
        return servers
    listing = runner("resolvectl", "dns")
    pattern = re.compile(rf"^Link \d+ \({re.escape(tunnel_if)}\):?(.*)$", re.M)
    match = pattern.search(listing)
    return match.group(1).split() if match else []


# ------------------------------------------------------------ orchestration

_CHECKS = (
    check_mac_randomized,
    check_hostname_changed,
    check_inbound_blocked,
    check_killswitch_loaded,
    check_tunnel_up,
    check_default_route_via_tunnel,
    check_dns_via_tunnel,
    check_ipv6_contained,
)


def run_checks(ctx: AuditContext, *, runner=run, killswitch=None,
               platform: str = sys.platform) -> list[CheckResult]:
    """Run every check in order. Never raises: an error becomes a failed check."""
    ks = _resolve_killswitch(killswitch, platform)
    results = []
    for check in _CHECKS:
        name = check.__name__.removeprefix("check_")
        try:
            results.append(check(ctx, runner, killswitch=ks, platform=platform))
        except (BackendError, OSError) as e:
            results.append(CheckResult(name, False, str(e) or type(e).__name__))
        except Exception as e:  # one unexpected reading must not hide the others
            results.append(CheckResult(name, False, f"{type(e).__name__}: {e}"))
    return results


def format_table(results: list[CheckResult]) -> str:
    if not results:
        return "no checks run"
    width = max(len(r.name) for r in results)
    return "\n".join(
        f"{'PASS' if r.ok else 'FAIL'}  {r.name.ljust(width)}  {r.detail}" for r in results
    )


def all_ok(results: list[CheckResult]) -> bool:
    return bool(results) and all(r.ok for r in results)
