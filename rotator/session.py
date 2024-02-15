"""A session: set up every protection, hold it for a set time, undo it all.

Order of a ``start`` (each change is journaled *before* it is made):

1. preflight (changes nothing);
2. kill switch up, with no tunnel interface yet (first, so it is also the
   last thing a rollback removes);
3. block inbound connections, randomize the host name;
4. rotate the MAC address (this drops the Wi-Fi association, so the network
   only ever sees the new identity), wait to rejoin, optional captive-portal
   window;
5. tunnel up, kill switch reloaded with the real tunnel interface, detection
   baseline, leak audit;
6. hold: detection and tunnel checks every few seconds;
7. stop: undo every journal entry, newest first.

Any failure in steps 2-5 runs step 7 before the error is re-raised. ``panic``
runs step 7 on its own, from the journal alone, after a crash or a reboot.

Nothing here prints the WireGuard key, the original MAC address or the
original host name. The originals live only in the root-only journal.
"""
import contextlib
import fcntl
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import cli as _cli
from . import detect, identity, journal, killswitch, tunnel
from .backends import BackendError, get_backend
from .backends.base import run

TITLE = "net-interface-rotator"
PANIC_HINT = "sudo python main.py panic"
STOP_NOTICE = (
    "Restoring your real hardware address and hostname. If you are still connected to "
    "the public network, it will see them: leave the network or turn Wi-Fi off first "
    "if that matters.")
NETWORK_TIMEOUT = 45  # seconds to wait for the interface to rejoin a network
STOP_TIMEOUT = 30  # seconds `session stop` waits for the session's own rollback

_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
# Generic tunnel interface names; deliberately no provider-specific ones.
_TUNNEL_IF = re.compile(r"(utun|tun|tap|wg|ppp|ipsec)\d*$")
_DURATION = re.compile(r"\s*(\d+)\s*([smh])\s*", re.IGNORECASE)
_UNITS = {"s": 1, "m": 60, "h": 3600}

_LABELS = {
    "tunnel": "WireGuard tunnel",
    "pf_token": "pf enable reference",
    "killswitch": "kill switch rules",
    "mac": "MAC address",
    "hostname": "host name",
    "inbound": "inbound firewall settings",
}

_FINDING_TEXT = {
    detect.ARP_SPOOF_SUSPECTED: "The gateway's hardware address changed (possible ARP spoofing).",
    detect.ARP_CONFLICT: "Two devices are answering for the gateway address (ARP conflict).",
    detect.NETWORK_RECONFIGURED: "The gateway or DNS servers of this network changed mid-session.",
    detect.POSSIBLE_EVIL_TWIN: "The access point changed while the network name stayed the same.",
}


class SessionError(RuntimeError):
    """The session cannot start or continue. The message is safe to print."""


@dataclass(frozen=True)
class Options:
    interface: str
    duration: float  # seconds
    config: str  # path to the WireGuard config (WG_CONFIG)
    fallback: str | None = None  # WG_CONFIG_FALLBACK
    portal: bool = False
    portal_seconds: float = 120
    strict: bool | None = None  # None: STRICT in the environment, else on
    keep_hostname: bool = False
    keep_firewall: bool = False
    poll: float = 3


# ------------------------------------------------------------------ pure parts

def parse_duration(text: str) -> float:
    """``90s``, ``15m`` or ``2h`` -> seconds. Raises ValueError otherwise."""
    match = _DURATION.fullmatch(text) if isinstance(text, str) else None
    if not match:
        raise ValueError(f"Invalid duration {text!r}: use a number and a unit, e.g. 90s, 15m or 2h")
    seconds = int(match.group(1)) * _UNITS[match.group(2).lower()]
    if seconds <= 0:
        raise ValueError("Duration must be greater than zero")
    return float(seconds)


def parse_default_route_interfaces(output: str, platform: str) -> list[str]:
    """Interfaces carrying an IPv4 default route.

    macOS: from ``route -n get default``. Linux: from ``ip -4 route show
    table all`` (wg-quick keeps its default route in a table of its own).
    """
    if platform == "darwin":
        return re.findall(r"^\s*interface:\s*(\S+)", output, re.MULTILINE)
    found = []
    for line in output.splitlines():
        match = re.match(r"\s*default\b.*?\bdev\s+(\S+)", line)
        if match and match.group(1) not in found:
            found.append(match.group(1))
    return found


def _applescript_string(text: str) -> str:
    """``text`` as the inside of an AppleScript double-quoted string."""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in str(text))
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def build_notify_command(title: str, message: str, platform: str | None = None,
                         which: Callable[[str], Any] = shutil.which) -> list[str] | None:
    """The argument list that shows a desktop notification, or None if this
    platform has no way to. Never goes through a shell."""
    platform = sys.platform if platform is None else platform
    if platform == "darwin":
        script = (f'display notification "{_applescript_string(message)}" '
                  f'with title "{_applescript_string(title)}"')
        return ["osascript", "-e", script]
    if platform.startswith("linux") and which("notify-send"):
        return ["notify-send", "--", str(title), str(message)]
    return None


def format_status(data: dict, now: float) -> str:
    """The text ``session status`` prints for a running session."""
    lines = [f"Session:      running (pid {data.get('pid', '?')}, {data.get('phase', 'holding')})"]
    ends_at = data.get("ends_at")
    if data.get("silent"):
        lines.append("Time left:    held until `session stop` (silent mode)")
    elif ends_at is None:
        lines.append("Time left:    not started yet")
    else:
        left = max(0, int(ends_at - now))
        lines.append(f"Time left:    {left // 3600}h {left % 3600 // 60:02d}m {left % 60:02d}s")
    name = data.get("tunnel_if") or "none"
    if data.get("silent"):
        tunnel_state = "stopped on purpose; all traffic is blocked"
    elif data.get("tunnel_up"):
        tunnel_state = f"{name} up"
    else:
        tunnel_state = f"{name} DOWN (traffic is blocked by the kill switch)"
    lines.append(f"Tunnel:       {tunnel_state}")
    loaded = data.get("killswitch")
    lines.append("Kill switch:  " + ("unknown" if loaded is None else "loaded" if loaded else "NOT LOADED"))
    lines.append("Findings:     " + (", ".join(data.get("findings") or []) or "none"))
    return "\n".join(lines)


# ------------------------------------------------------------- small I/O helpers

def _say(message: str) -> None:
    """Print a line. Never raises: output must not be able to stop a rollback
    (the terminal may already be gone)."""
    try:
        print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)
    except (OSError, ValueError):
        pass


def notify(title: str, message: str) -> None:
    """Show a desktop notification if the platform can. Never raises."""
    try:
        command = build_notify_command(title, message)
        if command:
            subprocess.run(command, capture_output=True, timeout=5, check=False)
    except Exception:
        pass


def wait_for_enter(seconds: float, clock: Callable[[], float] = time.time,
                   sleep: Callable[[float], None] = time.sleep) -> bool:
    """Wait up to ``seconds``; return True early if the user presses Enter."""
    deadline = clock() + seconds
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except (OSError, ValueError):
        interactive = False
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            return False
        step = min(1.0, remaining)
        if not interactive:
            sleep(step)
            continue
        try:
            ready, _, _ = select.select([sys.stdin], [], [], step)
        except (OSError, ValueError):
            interactive = False
            continue
        if ready:
            sys.stdin.readline()
            return True


def _is_root() -> bool:
    return os.geteuid() == 0


def _have(command: str) -> bool:
    return shutil.which(command) is not None


def _audit_module():
    from . import audit
    return audit


def default_route_tunnel(physical: str, runner=run) -> str | None:
    """Name of a tunnel interface, other than ``physical``, that already
    carries the default route; None if there is none. Generic on purpose: it
    recognizes tunnel interfaces, not providers."""
    if sys.platform == "darwin":
        output = runner("route", "-n", "get", "default", check=False)
    else:
        output = runner("ip", "-4", "route", "show", "table", "all", check=False)
    try:
        wireguard = set(runner("wg", "show", "interfaces", check=False).split())
    except BackendError:
        wireguard = set()
    for name in parse_default_route_interfaces(output, sys.platform):
        if name != physical and (name in wireguard or _TUNNEL_IF.fullmatch(name)):
            return name
    return None


@contextlib.contextmanager
def _signals_ignored():
    """Ignore stop signals for the duration (used around a rollback, which
    must run to the end). Child commands inherit this, so Ctrl-C in the
    terminal cannot kill a half-finished ``wg-quick down`` either."""
    saved = {}
    for signum in _SIGNALS:
        try:
            saved[signum] = signal.signal(signum, signal.SIG_IGN)
        except (ValueError, OSError):  # not the main thread
            pass
    try:
        yield
    finally:
        for signum, handler in saved.items():
            signal.signal(signum, handler)


@contextlib.contextmanager
def _signals_blocked():
    """Hold stop signals back for a few statements that must not be split;
    a signal that arrives meanwhile is delivered on exit."""
    try:
        old = signal.pthread_sigmask(signal.SIG_BLOCK, set(_SIGNALS))
    except (AttributeError, ValueError, OSError):
        old = None
    try:
        yield
    finally:
        if old is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


def _install_stop_handlers() -> dict:
    """Make SIGTERM and SIGHUP end the session the way Ctrl-C does."""
    saved = {}
    for signum in (signal.SIGTERM, signal.SIGHUP):
        try:
            saved[signum] = signal.signal(signum, _raise_interrupt)
        except (ValueError, OSError):  # not the main thread
            pass
    return saved


def _restore_handlers(saved: dict) -> None:
    for signum, handler in saved.items():
        try:
            signal.signal(signum, handler)
        except (ValueError, OSError):
            pass


# ------------------------------------------------------- lock and status files

def _state_dir() -> Path:
    return journal.journal_path().parent


def status_path() -> Path:
    return _state_dir() / "status.json"


def _lock_path() -> Path:
    return _state_dir() / "session.lock"


def _acquire_lock() -> int:
    """Take the one-session-per-machine lock and write our pid into it.

    The lock is an ``flock``, so it disappears with the process: a stale pid
    left by a crash is never mistaken for a running session.
    """
    directory = _state_dir()
    directory.mkdir(mode=journal.DIR_MODE, parents=True, exist_ok=True)
    fd = os.open(_lock_path(), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                 journal.FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise SessionError(
            "A session is already running. Stop it first with `session stop`.") from None
    os.ftruncate(fd, 0)
    os.pwrite(fd, str(os.getpid()).encode(), 0)
    return fd


def _release_lock(fd: int) -> None:
    try:
        os.ftruncate(fd, 0)
    except OSError:
        pass
    os.close(fd)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def running_pid() -> int | None:
    """The pid of the live session process, or None when there is none."""
    try:
        fd = os.open(_lock_path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raw = os.pread(fd, 32, 0).decode("ascii", "replace").strip()
            if raw.isdigit() and int(raw) > 1 and _pid_alive(int(raw)):
                return int(raw)
            raise SessionError(
                "A session holds the lock but its process could not be identified.") from None
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    finally:
        os.close(fd)


def _write_status(data: dict) -> None:
    """Replace the status file in one step. Best effort: a full disk must not
    end the session."""
    path = status_path()
    temporary = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                     journal.FILE_MODE)
        try:
            os.fchmod(fd, journal.FILE_MODE)
            os.write(fd, json.dumps(data).encode())
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except OSError:
        pass


def _remove_status() -> None:
    for path in (status_path(), status_path().with_name(status_path().name + ".tmp")):
        try:
            path.unlink()
        except OSError:
            pass


def _read_status_file() -> dict | None:
    try:
        data = json.loads(status_path().read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def status() -> dict | None:
    """The running session's status, or None when no session is running
    (no status file, or its process is gone)."""
    pid = running_pid()
    if pid is None:
        return None
    data = _read_status_file()
    if data is None or data.get("pid") != pid:
        return {"pid": pid, "phase": "starting"}
    return data


# ------------------------------------------------------------------ journal undo
#
# Every function sets an old value back (never toggles) and treats "already
# undone" as success, because a crash between an undo and its journal marker
# makes the undo run a second time.

def _undo_hostname(undo: dict, backend_factory) -> None:
    backend_factory(undo["interface"]).set_hostname(undo["names"])


def _undo_inbound(undo: dict, backend_factory) -> None:
    backend_factory(undo["interface"]).restore_inbound(undo["previous"])


def _undo_killswitch(undo: dict, backend_factory) -> None:
    # No token in here by design: this removes our rules and nothing else.
    platform_undo = {k: v for k, v in (undo.get("platform_undo") or {}).items() if k != "token"}
    for warning in killswitch.platform_module().unload(platform_undo):
        _say(f"Kill switch: {warning}")


def _undo_pf_token(undo: dict, backend_factory) -> None:
    release = getattr(killswitch.platform_module(), "release_token", None)
    if release is None:
        raise journal.JournalError("This platform's kill switch has no enable token to release")
    for warning in release(undo["token"]):
        _say(f"Kill switch: {warning}")


def _tunnel_present(config_path) -> bool:
    """Whether the config's tunnel interface still exists. Errs towards True."""
    name = tunnel.tunnel_name(config_path)
    if sys.platform == "darwin":
        try:
            name = (tunnel._NAME_DIR / f"{name}.name").read_text().strip()
        except OSError:
            return False  # wg-quick removes this file when the tunnel goes down
    try:
        return name in run("wg", "show", "interfaces").split()
    except BackendError:
        return True


def _undo_tunnel(undo: dict, backend_factory) -> None:
    config_path = undo["config_path"]
    try:
        tunnel.down(config_path)
    except BackendError as e:
        # A tunnel that is already down (never came up, stopped by strict
        # mode, or gone after a reboot) is the state we want.
        if "is not a WireGuard interface" in str(e) or not _tunnel_present(config_path):
            return
        raise


journal.register_undo("hostname", _undo_hostname)
journal.register_undo("inbound", _undo_inbound)
journal.register_undo("killswitch", _undo_killswitch)
journal.register_undo("pf_token", _undo_pf_token)
journal.register_undo("tunnel", _undo_tunnel)


def _safe_error(entry: dict, error: Exception) -> str:
    """The error text with any original identifier from the entry removed."""
    text = str(error) or type(error).__name__
    undo = entry.get("undo", {})
    originals = [undo.get("mac")] + list((undo.get("names") or {}).values())
    for value in originals:
        if isinstance(value, str) and value:
            text = re.sub(re.escape(value), "[original]", text, flags=re.IGNORECASE)
    return text


def _rollback(backend_factory) -> tuple[list[dict], list[tuple[dict, Exception]]]:
    """Undo everything pending, newest first, past individual failures.
    Returns (entries that were pending, failures)."""
    with _signals_ignored():
        entries = journal.pending()
        failures = journal.rollback(backend_factory, keep_going=True)
    return entries, failures


def _report(entries: list[dict], failures: list[tuple[dict, Exception]]) -> None:
    failed = {entry["id"]: error for entry, error in failures}
    for entry in entries:
        label = _LABELS.get(entry["kind"], entry["kind"])
        if entry["id"] in failed:
            _say(f"  FAILED    {label}: {_safe_error(entry, failed[entry['id']])}")
        else:
            _say(f"  restored  {label}")
    if failures:
        _say(f"{len(failures)} change(s) could not be undone and are still recorded. "
             f"Run `{PANIC_HINT}` to try again.")
    elif entries:
        _say("Everything is back as it was.")


# ----------------------------------------------------------------------- start

@dataclass
class _Plan:
    """What preflight worked out. Nothing in it is secret."""
    ks: Any
    configs: dict  # config path -> tunnel.TunnelConfig, primary first
    endpoints: list
    strict: bool
    strict_on: frozenset
    strict_rules: str
    portal_rules: str | None
    silent_rules: str


def _load_config(path: str) -> tunnel.TunnelConfig:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return tunnel.parse_config(text)  # drops the key; ``text`` goes no further
    except OSError as e:
        raise SessionError(f"Cannot read WireGuard config {path}: {e.strerror}.") from None
    except tunnel.ConfigError as e:
        raise SessionError(f"WireGuard config {path}: {e}") from None


def _local_addresses(backend) -> list[str]:
    """Addresses that certainly belong to the local network: the gateway and
    any private DHCP-supplied resolver. Used to refuse a tunnel DNS setting
    that would really be answered by the untrusted network."""
    import ipaddress
    found = []
    try:
        candidates = [backend.gateway(), *backend.dhcp_dns()]
    except BackendError:
        return found
    for value in candidates:
        try:
            ip = ipaddress.ip_address(value or "")
        except ValueError:
            continue
        if ip.is_private:
            found.append(str(ip))
    return found


def _preflight(options: Options, backend, environ) -> _Plan:
    """Every check that can refuse a session. Changes nothing."""
    if options.duration <= 0 or options.poll <= 0 or options.portal_seconds < 0:
        raise SessionError("Duration and poll interval must be greater than zero.")
    for command in ("wg-quick", "wg"):
        if not _have(command):
            raise SessionError(
                f"`{command}` was not found on PATH. Install wireguard-tools first.")

    paths = [p for p in (options.config, options.fallback) if p]
    if not paths or not options.config:
        raise SessionError("No WireGuard config given: set WG_CONFIG.")
    local = _local_addresses(backend)
    configs = {}
    for path in dict.fromkeys(paths):
        try:
            tunnel.tunnel_name(path)
        except BackendError as e:
            raise SessionError(f"{path}: {e}") from None
        problems = tunnel.validate_file(path, local)
        if problems:
            raise SessionError(
                f"WireGuard config {path} cannot be used:\n  - " + "\n  - ".join(problems))
        configs[path] = _load_config(path)
    endpoints = [(c.endpoint_ip, c.endpoint_port) for c in configs.values()]

    other = default_route_tunnel(options.interface)
    if other:
        raise SessionError(
            f"Another tunnel ({other}) already carries the default route. Disconnect "
            "that VPN first: its own kill switch would conflict with this one.")

    pending = journal.pending()
    if pending:
        raise SessionError(
            f"{len(pending)} change(s) from an earlier session are still applied. "
            f"Run `{PANIC_HINT}` to undo them before starting a new session.")

    try:
        strict, strict_on = detect.strict_settings(options.strict, environ)
        ks = killswitch.platform_module()
        strict_rules = ks.build_rules(options.interface, None, endpoints, False)
        portal_rules = (ks.build_rules(options.interface, None, endpoints, True)
                        if options.portal else None)
        silent_rules = ks.build_rules(options.interface, None, endpoints, False, silent=True)
    except (ValueError, NotImplementedError) as e:
        raise SessionError(str(e)) from None
    return _Plan(ks, configs, endpoints, strict, strict_on, strict_rules, portal_rules,
                 silent_rules)


def _platform_undo(ks) -> dict:
    """What identifies our rules on this platform. Never holds a token."""
    if hasattr(ks, "ANCHOR"):
        return {"anchor": ks.ANCHOR}
    return {"table": ks.TABLE}


class _Session:
    """One run's state. Created after preflight, before the first change."""

    def __init__(self, options: Options, backend, plan: _Plan, notifier, clock, sleep, wait_enter):
        self.options = options
        self.backend = backend
        self.plan = plan
        self.notifier = notifier
        self.clock = clock
        self.sleep = sleep
        self.wait_enter = wait_enter

        self.started_at = clock()
        self.ends_at: float | None = None
        self.phase = "starting"
        self.tunnel_if: str | None = None
        self.config_used: str | None = None
        self.ks_undo: dict | None = None
        self.tunnel_up = False
        self.killswitch_loaded: bool | None = None
        self.silent = False
        self.seen: set[str] = set()

        self.baseline = None
        self.previous = None
        self.history: list[set[str]] = []
        self._tunnel_warned = False
        self._killswitch_warned = False
        self._read_failed = False

    # -- reporting

    def write_status(self) -> None:
        _write_status({
            "pid": os.getpid(),
            "phase": self.phase,
            "interface": self.options.interface,
            "started_at": self.started_at,
            "ends_at": None if self.silent else self.ends_at,
            "tunnel_if": self.tunnel_if,
            "tunnel_dns": self.tunnel_dns(),
            "tunnel_up": self.tunnel_up,
            "killswitch": self.killswitch_loaded,
            "silent": self.silent,
            "findings": sorted(self.seen),
        })

    def tunnel_dns(self) -> list[str]:
        """The in-tunnel resolvers of whichever config came up."""
        used = self.plan.configs.get(self.config_used)
        return list(used.dns) if used else []

    def alert(self, message: str) -> None:
        _say(message)
        try:
            self.notifier(TITLE, message)
        except Exception:
            pass

    # -- steps 2-5

    def setup(self) -> None:
        options, backend, plan, ks = self.options, self.backend, self.plan, self.plan.ks
        iface = options.interface

        # 2. Kill switch first, before anything else changes and before any
        # tunnel exists: only DHCP and the tunnel endpoints can pass. Being the
        # oldest entry, it is also the last thing a rollback removes, so the
        # tunnel, address and names are put back while it still blocks traffic.
        # The entry is journaled before the first load; the pf enable token is
        # journaled on its own as soon as it exists, with stop signals held
        # back so the two cannot be separated.
        journal.record("killswitch", {"platform_undo": _platform_undo(ks)})
        with _signals_blocked():
            self.ks_undo = ks_undo = ks.load(plan.strict_rules)
            if ks_undo.get("token") is not None:
                journal.record("pf_token", {"anchor": ks_undo.get("anchor"),
                                            "token": str(ks_undo["token"])})
        self.killswitch_loaded = True
        _say("Kill switch is up.")
        self.write_status()

        # 3. Inbound exposure and host name.
        if options.keep_firewall:
            _say("Keeping the inbound firewall settings as they are (--keep-firewall).")
        else:
            previous = backend.get_inbound()
            if previous:  # empty: nothing to manage here (Linux; the kill switch drops inbound)
                journal.record("inbound", {"interface": iface, "previous": previous})
                backend.harden_inbound()
                _say("Inbound connections are blocked.")

        original_names = None
        if options.keep_hostname:
            _say("Keeping the host name (--keep-hostname).")
        else:
            original_names = backend.get_hostname()
            journal.record("hostname", {"interface": iface, "names": original_names})
            new_names = identity.randomized(original_names)
            backend.set_hostname(new_names)
            shown = sorted({v for v in new_names.values() if v})
            _say("Host name is now " + (", ".join(shown) or "unchanged") + ".")

        # 4. New MAC. The change drops the Wi-Fi association, so the network
        # the interface rejoins has only ever seen the new address.
        original_mac = backend.current_mac()
        new_mac = _cli.rotate(backend, journal=journal)
        _say(f"{iface} MAC address is now {new_mac}.")
        self._wait_for_network()

        # Captive portal: the exception is open only for this window, under the
        # new identity, and the strict rules come back whatever happens in it.
        if options.portal:
            try:
                ks.load(plan.portal_rules, ks_undo)
                _say(f"WARNING: for up to {options.portal_seconds:g} s, web traffic (TCP 80/443) "
                     "and DNS on this network are NOT protected.")
                _say("Log in to the network's portal page now, and nothing else. "
                     "Press Enter as soon as you are done.")
                self.wait_enter(options.portal_seconds, self.clock, self.sleep)
            finally:
                ks.load(plan.strict_rules, ks_undo)
                _say("Portal window closed; strict kill switch rules are loaded.")

        # 5. Tunnel. Every config that may be brought up is journaled first.
        for path in plan.configs:
            journal.record("tunnel", {"config_path": path})
        paths = list(plan.configs)
        self.config_used, self.tunnel_if = tunnel.up_with_fallback(
            paths[0], paths[1] if len(paths) > 1 else None)
        ks.load(ks.build_rules(iface, self.tunnel_if, plan.endpoints, False), ks_undo)
        self.tunnel_up = True
        _say(f"Tunnel is up on {self.tunnel_if}.")
        self.write_status()

        self.baseline = self.previous = detect.reading_from(backend)

        audit = _audit_module()
        context = audit.AuditContext(
            backend=backend,
            tunnel_if=self.tunnel_if,
            tunnel_dns=tuple(self.tunnel_dns()),
            original_mac=original_mac,
            original_hostnames=original_names,
            manage_inbound=not options.keep_firewall,
        )
        results = audit.run_checks(context, killswitch=ks)
        _say("Leak audit:\n" + audit.format_table(results))
        if not audit.all_ok(results):
            raise SessionError("The leak audit failed, so the session was not started.")

    def _wait_for_network(self) -> None:
        deadline = self.clock() + NETWORK_TIMEOUT
        while True:
            try:
                if self.backend.gateway():
                    return
            except BackendError:
                pass
            if self.clock() >= deadline:
                raise SessionError(
                    f"{self.options.interface} did not rejoin a network within "
                    f"{NETWORK_TIMEOUT} s after its address changed.")
            self.sleep(1)

    # -- step 6

    def hold(self) -> None:
        self.phase = "holding"
        self.ends_at = self.clock() + self.options.duration
        mode = "on" if self.plan.strict else "off"
        _say(f"Session is active (strict mode {mode}). Stop early with Ctrl-C or `session stop`.")
        self.write_status()
        while True:
            remaining = self.ends_at - self.clock()
            if self.silent:
                # Strict mode went silent: stay blocked until someone stops us,
                # rather than reopening a hostile network on a timer.
                self.sleep(self.options.poll)
            elif remaining <= 0:
                _say("Session time is up.")
                return
            else:
                self.sleep(min(self.options.poll, remaining))
            self.poll_once()
            self.write_status()

    def poll_once(self) -> None:
        try:
            reading = detect.reading_from(self.backend)
        except BackendError as e:
            if not self._read_failed:
                _say(f"Could not read the network state: {e}")
            self._read_failed = True
        else:
            self._read_failed = False
            found = detect.findings(self.baseline, self.previous, reading)
            actions = detect.react(found, self.history, self.plan.strict, self.plan.strict_on)
            self.history = (self.history + [found])[-2:]
            self.previous = reading
            self.seen |= found
            for action, finding in actions:
                text = _FINDING_TEXT.get(finding, finding)
                if action == detect.WARN:
                    self.alert(f"Warning ({finding}): {text} Your traffic stays encrypted.")
                elif action == detect.GO_SILENT:
                    self.go_silent(finding)

        self.tunnel_up = bool(self.tunnel_if) and tunnel.is_up(self.tunnel_if)
        if self.tunnel_up:
            self._tunnel_warned = False
        elif not self.silent and not self._tunnel_warned:
            self._tunnel_warned = True
            self.alert("The tunnel is down. All traffic is blocked by the kill switch "
                       "until it reconnects or you stop the session.")

        try:
            self.killswitch_loaded = bool(self.plan.ks.is_loaded())
        except Exception:
            self.killswitch_loaded = None
        if self.killswitch_loaded is False and not self._killswitch_warned:
            self._killswitch_warned = True
            self.alert("WARNING: the kill switch rules are no longer loaded. Traffic "
                       "could leave outside the tunnel. Stop using this network.")

    def go_silent(self, finding: str) -> None:
        if self.silent:
            return
        self.silent = True
        self.alert(f"Strict mode ({finding}): stopping the tunnel. All traffic is blocked "
                   "until you run `session stop`.")
        try:
            tunnel.down(self.config_used)
        except BackendError as e:
            _say(f"Could not stop the tunnel: {e}")
        # Whether or not ``down`` worked: rules with no tunnel and no endpoint
        # exception, then drop the states the old rules created, so a tunnel
        # that is still running has no way out.
        ks = self.plan.ks
        try:
            ks.load(self.plan.silent_rules, self.ks_undo)
            drop_states = getattr(ks, "drop_states", None)  # pf only; nft rules hold no state
            if drop_states is not None:
                drop_states(self.options.interface)
        except Exception as e:
            self.alert(f"Could not tighten the kill switch after stopping the tunnel: {e}")
        self.tunnel_up = False


def start(options: Options, *, backend_factory=get_backend, notifier=notify,
          clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
          wait_enter=wait_for_enter, environ=None) -> int:
    """Run a whole session. Returns 0 when everything was put back, 1 when a
    change could not be undone. Raises ``SessionError`` (or the original
    exception) if the session could not be set up; by then it has been rolled
    back."""
    if not _is_root():
        raise SessionError("A session changes system settings and must be run with sudo.")
    environ = os.environ if environ is None else environ
    lock = _acquire_lock()
    handlers = _install_stop_handlers()
    try:
        _remove_status()  # a leftover from a crashed session
        backend = backend_factory(options.interface)
        plan = _preflight(options, backend, environ)
        session = _Session(options, backend, plan, notifier, clock, sleep, wait_enter)
        session.write_status()
        try:
            session.setup()
            try:
                session.hold()
            except KeyboardInterrupt:
                _say("Stop requested.")
        except BaseException as e:
            # From here on a second Ctrl-C must not cut the rollback short.
            with _signals_ignored():
                reason = "was interrupted" if isinstance(e, KeyboardInterrupt) else "failed"
                _say(f"The session {reason}; undoing every change made so far.")
                session.phase = "stopping"
                session.write_status()
                _report(*_rollback(backend_factory))
            raise
        with _signals_ignored():
            session.phase = "stopping"
            session.write_status()
            _say("Stopping: undoing every change.")
            _say(STOP_NOTICE)
            entries, failures = _rollback(backend_factory)
            _report(entries, failures)
        return 1 if failures else 0
    finally:
        _remove_status()
        _restore_handlers(handlers)
        _release_lock(lock)


# ---------------------------------------------------------------- stop / panic

def _stop_process(pid: int, kill, clock, sleep, timeout: float) -> bool:
    """Ask the session process to stop; True once it has gone."""
    try:
        kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    deadline = clock() + timeout
    while clock() < deadline:
        sleep(0.5)
        try:
            if running_pid() != pid:
                return True
        except SessionError:
            pass
    return False


def stop_running(backend_factory=get_backend, *, kill=os.kill,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 timeout: float = STOP_TIMEOUT) -> int:
    """``session stop``. A live session is asked to stop and does its own
    rollback; with no session process, the journal is rolled back here."""
    if not _is_root():
        raise SessionError("Stopping a session must be run with sudo.")
    pid = running_pid()
    if pid is not None:
        _say(f"Asking the running session (pid {pid}) to stop.")
        if not _stop_process(pid, kill, clock, sleep, timeout):
            _say(f"The session has not finished stopping after {timeout:g} s. "
                 f"If it does not, run `{PANIC_HINT}`.")
            return 1
        left = journal.pending()
        if left:
            _say(f"The session stopped but {len(left)} change(s) are still applied. "
                 f"Run `{PANIC_HINT}`.")
            return 1
        _say("Session stopped; everything is back as it was.")
        return 0

    if not journal.pending():
        _say("No session is running and there is nothing to undo.")
        return 0
    _say("No session process is running; undoing the changes it left behind.")
    _say(STOP_NOTICE)
    entries, failures = _rollback(backend_factory)
    _report(entries, failures)
    return 1 if failures else 0


def load_undo_kinds() -> None:
    """Import every module that registers a journal undo kind. ``mac`` lives
    in ``journal`` itself and the rest are registered by this module, so
    importing this module is what does the work."""
    from . import journal as _journal  # noqa: F401


def panic(backend_factory=get_backend, *, kill=os.kill,
          clock: Callable[[], float] = time.time,
          sleep: Callable[[float], None] = time.sleep,
          timeout: float = STOP_TIMEOUT) -> int:
    """Undo everything in the journal, past individual failures, whatever
    state the previous session was left in. Returns 1 if anything failed."""
    if not _is_root():
        raise SessionError("panic must be run with sudo.")
    load_undo_kinds()
    try:
        pid = running_pid()
    except SessionError as e:
        _say(f"{e} Continuing anyway.")
        pid = None
    if pid is not None:
        # Two processes undoing the same journal would trip over each other,
        # so the session goes first: politely, then not.
        _say(f"Stopping the running session (pid {pid}) first.")
        if not _stop_process(pid, kill, clock, sleep, timeout):
            _say("It did not stop in time; killing it.")
            try:
                kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            sleep(0.5)

    entries, failures = _rollback(backend_factory)
    if not entries:
        _say("Nothing to undo: the journal is empty.")
        return 0
    _report(entries, failures)
    return 1 if failures else 0


# ----------------------------------------------------------------------- audit

def audit_context(backend):
    """An ``AuditContext`` for the standalone ``audit`` command: originals
    from the journal's pending entries, tunnel details from the running
    session's status file. The inbound firewall counts as managed when the
    journal holds an ``inbound`` entry (so not with ``--keep-firewall``)."""
    original_mac = None
    original_names = None
    manage_inbound = False
    for entry in journal.pending():  # newest first, so the oldest entry wins
        undo = entry["undo"]
        if undo.get("interface") != backend.interface:
            continue
        if entry["kind"] == "inbound":
            manage_inbound = True
        elif entry["kind"] == "mac":
            original_mac = undo.get("mac")
        elif entry["kind"] == "hostname":
            original_names = undo.get("names")
    if not manage_inbound:
        # Where the backend has no inbound settings of its own (Linux), the
        # kill switch is what blocks inbound, and that is always checked.
        try:
            manage_inbound = not backend.get_inbound()
        except BackendError:
            pass
    current = status() or {}
    return _audit_module().AuditContext(
        backend=backend,
        tunnel_if=current.get("tunnel_if"),
        tunnel_dns=tuple(current.get("tunnel_dns") or ()),
        original_mac=original_mac,
        original_hostnames=original_names,
        manage_inbound=manage_inbound,
    )
