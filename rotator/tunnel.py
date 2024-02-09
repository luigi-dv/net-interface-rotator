"""WireGuard tunnel: check the user's wg-quick config, then start, stop and
verify it. All encryption is WireGuard's own; this module only orchestrates.

The private key is never stored, returned, raised or logged: the parser
skips secret values, error messages name line numbers and keys only, and
output from ``wg-quick`` is scrubbed before it reaches an exception.
"""
import ipaddress
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .backends.base import BackendError, run

HANDSHAKE_MAX_AGE = 180
HANDSHAKE_TIMEOUT = 15
_POLL_SECONDS = 0.5
_NAME_DIR = Path("/var/run/wireguard")  # macOS: wg-quick writes <name>.name here

_SECRET_KEYS = {"privatekey", "presharedkey"}
_IF_NAME = re.compile(r"[A-Za-z0-9_=+.-]{1,15}")
_ENDPOINT_V4 = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
_ENDPOINT_V6 = re.compile(r"\[([0-9A-Fa-f:.]+)\]:(\d{1,5})")
_KEY_LIKE = re.compile(r"[A-Za-z0-9+/]{42,43}=")
# wg-quick runs these as root, so a session refuses any config that has them.
_HOOK_KEYS = (("preup", "PreUp"), ("postup", "PostUp"), ("predown", "PreDown"), ("postdown", "PostDown"))


class ConfigError(ValueError):
    """The config cannot be used. The message never contains file contents."""


@dataclass(frozen=True)
class TunnelConfig:
    endpoint_ip: str
    endpoint_port: int
    dns: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    has_keepalive: bool = False


# ---------------------------------------------------------------- pure: parsing

def _read_fields(text: str) -> tuple[dict[str, list[str]], list[dict[str, list[str]]], list[str]]:
    """Split a wg-quick config into ([Interface] fields, one dict per [Peer],
    problems). Secret values are dropped here and go no further."""
    interface: dict[str, list[str]] = {}
    peers: list[dict[str, list[str]]] = []
    problems: list[str] = []
    current = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").strip().lower()
            if section == "interface":
                current = interface
            elif section == "peer":
                current = {}
                peers.append(current)
            else:
                current = None
                problems.append(f"Line {number}: unknown section.")
            continue
        key, sep, value = line.partition("=")
        key = key.strip().lower()
        if not sep or not key.isalnum():
            problems.append(f"Line {number}: not a `Key = value` line.")
            continue
        if current is None:
            problems.append(f"Line {number}: setting outside [Interface] or [Peer].")
            continue
        if key in _SECRET_KEYS:
            current.setdefault(key, []).append("")  # presence only, never the value
            continue
        current.setdefault(key, []).extend(
            part.strip() for part in value.split(",") if part.strip())
    return interface, peers, problems


def _parse_endpoint(value: str) -> tuple[str, int] | None:
    """``1.2.3.4:51820`` or ``[2001:db8::1]:51820`` -> (ip, port); else None."""
    match = _ENDPOINT_V4.fullmatch(value) or _ENDPOINT_V6.fullmatch(value)
    if not match:
        return None
    host, port = match.group(1), int(match.group(2))
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if value.startswith("[") != (ip.version == 6) or not 1 <= port <= 65535:
        return None
    return str(ip), port


def _dns_addresses(values: list[str]) -> list[str]:
    """wg-quick's DNS line may also carry search domains; keep addresses only."""
    found = []
    for value in values:
        try:
            found.append(str(ipaddress.ip_address(value)))
        except ValueError:
            pass
    return found


def _covers_everything(allowed: list[str]) -> tuple[bool, bool, bool]:
    """(covers all IPv4, covers all IPv6, every entry was a valid network)."""
    nets, valid = {4: [], 6: []}, True
    for value in allowed:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            valid = False
            continue
        nets[net.version].append(net)
    full = {4: ipaddress.ip_network("0.0.0.0/0"), 6: ipaddress.ip_network("::/0")}
    covered = {v: full[v] in list(ipaddress.collapse_addresses(nets[v])) for v in (4, 6)}
    return covered[4], covered[6], valid


def parse_config(text: str) -> TunnelConfig:
    """Extract the few fields the tool needs. Raises ``ConfigError`` unless
    there is exactly one peer with an IP-literal endpoint."""
    interface, peers, _ = _read_fields(text)
    if len(peers) != 1:
        raise ConfigError(f"Expected exactly one [Peer] section, found {len(peers)}.")
    peer = peers[0]
    endpoints = peer.get("endpoint", [])
    endpoint = _parse_endpoint(endpoints[0]) if len(endpoints) == 1 else None
    if endpoint is None:
        raise ConfigError("Endpoint must be a single IPv4 or bracketed IPv6 literal with a port.")
    keepalive = peer.get("persistentkeepalive", [])
    return TunnelConfig(
        endpoint_ip=endpoint[0],
        endpoint_port=endpoint[1],
        dns=_dns_addresses(interface.get("dns", [])),
        allowed_ips=list(peer.get("allowedips", [])),
        has_keepalive=any(v.isdigit() and int(v) > 0 for v in keepalive),
    )


def invoking_uid(environ=None) -> int:
    """The user who ran sudo, or the current user when not under sudo."""
    value = (os.environ if environ is None else environ).get("SUDO_UID", "")
    return int(value) if value.isdigit() else os.getuid()


def validate(config_text: str, file_stat, local_networks=(), owner_uid: int | None = None) -> list[str]:
    """Preflight check of a config. Returns human-readable problems; an empty
    list means the config may be used. Never includes file contents.

    ``file_stat`` needs ``st_mode`` and ``st_uid``. ``local_networks`` are the
    networks of the untrusted LAN (strings or ``ipaddress`` networks).
    ``owner_uid`` defaults to the invoking user (``SUDO_UID``).
    """
    problems: list[str] = []

    mode = stat.S_IMODE(file_stat.st_mode)
    if mode & 0o077 or not mode & 0o400:
        problems.append(
            f"Config file mode is {mode:04o}; it must be 0600 (readable by its owner only).")
    allowed_owner = invoking_uid() if owner_uid is None else owner_uid
    if file_stat.st_uid not in (0, allowed_owner):
        problems.append(
            f"Config file is owned by uid {file_stat.st_uid}; it must be owned by root "
            f"or by the user running the tool.")

    interface, peers, syntax = _read_fields(config_text)
    problems += syntax
    if "privatekey" not in interface:
        problems.append("[Interface] has no PrivateKey.")
    if len(peers) != 1:
        problems.append(f"Expected exactly one [Peer] section, found {len(peers)}.")
    peer = peers[0] if peers else {}

    v4, v6, valid = _covers_everything(peer.get("allowedips", []))
    if not valid:
        problems.append("AllowedIPs contains an entry that is not a network.")
    if not v4:
        problems.append("AllowedIPs must cover 0.0.0.0/0, or some IPv4 traffic would bypass the tunnel.")
    if not v6:
        problems.append("AllowedIPs must cover ::/0, or some IPv6 traffic would bypass the tunnel.")

    dns = _dns_addresses(interface.get("dns", []))
    if not dns:
        problems.append("DNS is not set; the tunnel must supply its own resolver address.")
    networks = [ipaddress.ip_network(str(n), strict=False) for n in local_networks]
    for address in dns:
        ip = ipaddress.ip_address(address)
        if any(ip.version == n.version and ip in n for n in networks):
            problems.append(
                f"DNS server {address} is on the local network; lookups would be "
                f"answered by the untrusted network.")

    endpoints = peer.get("endpoint", [])
    endpoint = _parse_endpoint(endpoints[0]) if len(endpoints) == 1 else None
    if endpoint is None:
        problems.append(
            "Endpoint must be an IP literal with a port (a.b.c.d:port). A hostname "
            "would be resolved through the untrusted network.")
    elif ipaddress.ip_address(endpoint[0]).version != 4:
        problems.append(
            "Endpoint is IPv6; use an IPv4 endpoint. IPv6 is fully blocked on the "
            "physical interface.")

    if not any(v.isdigit() and int(v) > 0 for v in peer.get("persistentkeepalive", [])):
        problems.append(
            "PersistentKeepalive is not set; it is needed to complete and keep the "
            "handshake through the network's NAT (25 is the usual value).")

    for key, name in _HOOK_KEYS:
        if key in interface:
            problems.append(f"{name} is not allowed; wg-quick would run it as root.")
    if any(v.lower() == "true" for v in interface.get("saveconfig", [])):
        problems.append("SaveConfig = true is not allowed; wg-quick would rewrite the config file.")
    if "table" in interface and [v.lower() for v in interface["table"]] != ["auto"]:
        problems.append(
            "Table must be absent or `auto`; any other value stops traffic being "
            "routed through the tunnel.")
    return problems


def validate_file(config_path, local_networks=()) -> list[str]:
    """``validate`` for a path. Reads and stats the same open file, and
    requires a regular file."""
    try:
        fd = os.open(str(config_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        return [f"Cannot open config file {config_path}: {e.strerror}."]
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
        file_stat = os.fstat(handle.fileno())
        if not stat.S_ISREG(file_stat.st_mode):
            return [f"Config {config_path} is not a regular file."]
        return validate(handle.read(), file_stat, local_networks)


def parse_latest_handshakes(output: str, now: float) -> float | None:
    """Age in seconds of the newest handshake in ``wg show <if>
    latest-handshakes`` output, or None if no peer has ever completed one."""
    newest = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            newest = max(newest, int(parts[-1]))
    if newest == 0:
        return None
    return max(0.0, now - newest)


# ------------------------------------------------------------ thin: doing

def tunnel_name(config_path) -> str:
    """The wg-quick interface name: the config's file stem."""
    path = Path(config_path)
    if path.suffix != ".conf" or not _IF_NAME.fullmatch(path.stem):
        raise BackendError(
            "WireGuard config must be named <name>.conf, where <name> is at most 15 "
            "letters, digits or `_=+.-`.")
    return path.stem


def _secrets(config_path) -> list[str]:
    """Secret values in the config, used only to scrub command output."""
    found = []
    try:
        text = Path(config_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return found
    for line in text.splitlines():
        key, sep, value = line.split("#", 1)[0].partition("=")
        if sep and key.strip().lower() in _SECRET_KEYS and value.strip():
            found.append(value.strip())
    return found


def _redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, "[redacted]")
    return _KEY_LIKE.sub("[redacted]", text)


def _wg_quick(action: str, config_path) -> None:
    tunnel_name(config_path)
    try:
        run("wg-quick", action, str(config_path))
    except BackendError as e:
        # wg can echo a malformed key in its error text; scrub before raising,
        # and drop the chained exception, which holds the raw output.
        raise BackendError(_redact(str(e), _secrets(config_path))) from None


def up(config_path) -> str:
    """Run ``wg-quick up`` and return the real tunnel interface name."""
    name = tunnel_name(config_path)
    _wg_quick("up", config_path)
    if sys.platform != "darwin":
        return name
    try:
        real = (_NAME_DIR / f"{name}.name").read_text().strip()
    except OSError as e:
        raise BackendError(f"Tunnel {name} started but its interface name could not be read.") from e
    if not _IF_NAME.fullmatch(real):
        raise BackendError(f"Tunnel {name} reported an unusable interface name.")
    return real


def down(config_path) -> None:
    _wg_quick("down", config_path)


def handshake_age(tunnel_if: str) -> float | None:
    """Seconds since the last completed handshake; None if there has been
    none or the interface does not exist."""
    try:
        output = run("wg", "show", tunnel_if, "latest-handshakes")
    except BackendError:
        return None
    return parse_latest_handshakes(output, time.time())


def is_up(tunnel_if: str, max_age: float = HANDSHAKE_MAX_AGE) -> bool:
    age = handshake_age(tunnel_if)
    return age is not None and age < max_age


def _wait_for_handshake(tunnel_if: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if is_up(tunnel_if):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)


def up_with_fallback(primary, fallback=None, timeout: float = HANDSHAKE_TIMEOUT) -> tuple[str, str]:
    """Bring up ``primary``; if no handshake completes within ``timeout``
    seconds, tear it down and try ``fallback`` once. Returns
    ``(config_path_used, tunnel_if)``. On failure no tunnel is left up."""
    failures = []
    for config_path in [p for p in (primary, fallback) if p]:
        label = Path(config_path).name
        try:
            tunnel_if = up(config_path)
        except BackendError as e:
            failures.append(f"{label}: {e}")
            try:
                down(config_path)  # wg-quick may have left a half-built interface
            except BackendError:
                pass
            continue
        if _wait_for_handshake(tunnel_if, timeout):
            return str(config_path), tunnel_if
        failures.append(f"{label}: no handshake within {timeout:g} s")
        try:
            down(config_path)
        except BackendError as e:
            raise BackendError(
                f"Tunnel {label} did not connect and could not be stopped: {e}") from None
    raise BackendError(
        "WireGuard tunnel did not connect (" + "; ".join(failures) + "). "
        "This network may block UDP, in which case it cannot be used with this tool.")
