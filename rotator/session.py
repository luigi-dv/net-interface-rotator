"""A session: set up every protection, hold it for a set time, undo it all.

Order of a ``start`` (each change is journaled *before* it is made):

1. preflight: every check that can refuse a session. The WireGuard configs
   are validated and copied to a root-only directory, and only those copies
   are used afterwards; nothing else changes;
2. kill switch up in *lockdown*: only loopback passes, on every interface
   (first, so it is also the last thing a rollback removes);
3. block inbound connections, randomize the host name, rotate the MAC
   address: all while nothing at all can leave, so the new name is never
   sent from the old address;
4. kill switch reloaded with the strict rules (DHCP and the tunnel endpoints
   only), wait to rejoin the network, optional captive-portal window;
5. DNS settings recorded (macOS), tunnel up, kill switch reloaded with the
   real tunnel interface, detection baseline, leak audit;
6. hold: detection, tunnel and kill-switch checks every few seconds;
7. stop: undo every journal entry, newest first.

What the network has seen: if the interface was already associated when the
session started, the network has seen this device's real hardware address
(and whatever name it announced) before step 2; the session cannot take that
back, and preflight says so. From step 2 on it sees only the new identity.
Start the session before joining a network for the full effect.

Everything a session changes, each with a journal entry of that kind:

- ``killswitch``  our pf anchor / nft table
- ``pf_token``    the pf enable reference (macOS)
- ``inbound``     inbound firewall settings
- ``hostname``    host names
- ``mac``         the interface's MAC address
- ``dns``         each network service's DNS servers and search domains
                  (macOS: ``wg-quick up`` rewrites them, and only its own
                  monitor process would put them back)
- ``tunnel``      the WireGuard tunnel (one entry per config that may be used)

How a session ends. Step 7 puts the real MAC address and host name back and
removes the kill switch, so it only ever runs because the user asked:

- ``session stop`` (SIGTERM) or Ctrl-C: step 7, after ``STOP_NOTICE``;
- a failure in steps 2-5: step 7, after ``STOP_NOTICE``, then the error;
- the duration ends: the session *goes silent* (silent rules, tunnel down)
  and keeps waiting for ``session stop``;
- the terminal closes (SIGHUP) or the hold loop hits an unexpected error:
  the session goes silent and exits, leaving the journal pending; ``session
  stop`` then rolls it back directly.

``panic`` runs step 7 on its own, from the journal alone, after a crash or a
reboot.

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
from .backends.base import command_env, run

TITLE = "net-interface-rotator"
PANIC_HINT = "sudo python main.py panic"
STOP_NOTICE = (
    "Restoring your real hardware address and hostname. If you are still connected to "
    "the public network, it will see them: leave the network or turn Wi-Fi off first "
    "if that matters.")
STOP_HINT = "sudo python main.py session stop"
LEAVE_HINT = (
    "All traffic is blocked. Leave the network (or turn Wi-Fi off), then run "
    f"`{STOP_HINT}`.")
TIME_UP_NOTICE = "Session time is up. " + LEAVE_HINT
SEEN_NOTICE = (
    "This network has already seen this device; for best protection start the session "
    "before joining a network")
NETWORK_TIMEOUT = 45  # seconds to wait for the interface to rejoin a network
BASELINE_TIMEOUT = 30  # seconds to wait for a reading with a gateway and its MAC
ROUTE_PROBE = "192.0.2.1"  # TEST-NET-1: never a local address, so it follows the default route
STOP_TIMEOUT = 30  # seconds `session stop` waits for the session's own rollback

_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
# Generic tunnel interface names; deliberately no provider-specific ones.
_TUNNEL_IF = re.compile(r"(utun|tun|tap|wg|ppp|ipsec)\d*$")
_DURATION = re.compile(r"\s*(\d+)\s*([smh])\s*", re.IGNORECASE)
_UNITS = {"s": 1, "m": 60, "h": 3600}
_USER_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}")

_LABELS = {
    "tunnel": "WireGuard tunnel",
    "pf_token": "pf enable reference",
    "killswitch": "kill switch rules",
    "mac": "MAC address",
    "hostname": "host name",
    "inbound": "inbound firewall settings",
    "dns": "DNS settings",
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
    """Interfaces that carry traffic for the rest of the world.

    macOS: from ``route -n get 192.0.2.1``. Linux: from ``ip -4 route show
    table all`` (wg-quick keeps its default route in a table of its own)
    followed by ``ip -4 route get 192.0.2.1``. Besides ``default``, the two
    half-routes ``0.0.0.0/1`` and ``128.0.0.0/1`` count: that is how
    WireGuard-style VPNs take over routing without replacing the default.
    """
    if platform == "darwin":
        return re.findall(r"^\s*interface:\s*(\S+)", output, re.MULTILINE)
    found = []
    wanted = rf"(?:default|0\.0\.0\.0/1|128\.0\.0\.0/1|{re.escape(ROUTE_PROBE)})"
    for line in output.splitlines():
        match = re.match(rf"\s*{wanted}\s.*?\bdev\s+(\S+)", line)
        if match and match.group(1) not in found:
            found.append(match.group(1))
    return found


def _applescript_string(text: str) -> str:
    """``text`` as the inside of an AppleScript double-quoted string."""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in str(text))
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def _sudo_user(environ) -> tuple[str, str] | None:
    """(uid, user name) of whoever ran sudo, when both are set and sane."""
    uid, user = str(environ.get("SUDO_UID", "")), str(environ.get("SUDO_USER", ""))
    if uid.isdigit() and int(uid) > 0 and _USER_NAME.fullmatch(user):
        return uid, user
    return None


def _notify_bus(uid: str) -> str:
    return f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"


def build_notify_command(title: str, message: str, platform: str | None = None,
                         which: Callable[[str], Any] = shutil.which,
                         environ=None) -> list[str] | None:
    """The argument list that shows a desktop notification, or None if this
    platform has no way to. Never goes through a shell.

    Under sudo the notification has to be sent as the user who owns the
    desktop: root has no access to their notification centre (macOS) or
    session bus (Linux). On Linux sudo resets the environment, so the bus
    address is also handed over through ``env``.
    """
    platform = sys.platform if platform is None else platform
    sudo = _sudo_user(os.environ if environ is None else environ)
    if platform == "darwin":
        script = (f'display notification "{_applescript_string(message)}" '
                  f'with title "{_applescript_string(title)}"')
        command = ["osascript", "-e", script]
        if sudo:
            return ["launchctl", "asuser", sudo[0], "sudo", "-u", sudo[1], *command]
        return command
    if platform.startswith("linux") and which("notify-send"):
        command = ["notify-send", "--", str(title), str(message)]
        if sudo:
            return ["sudo", "-u", sudo[1], "env", _notify_bus(sudo[0]), *command]
        return command
    return None


def build_notify_env(platform: str | None = None, environ=None) -> dict[str, str]:
    """The environment for the notification command: the fixed one every
    command gets, plus the invoking user's session bus on Linux."""
    platform = sys.platform if platform is None else platform
    environ = os.environ if environ is None else environ
    env = command_env("notify", environ)
    sudo = _sudo_user(environ)
    if platform.startswith("linux"):
        if sudo:
            name, _, value = _notify_bus(sudo[0]).partition("=")
            env[name] = value
        else:
            for name in ("DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "XDG_RUNTIME_DIR"):
                if name in environ:
                    env[name] = environ[name]
    return env


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
            # Not ``backends.base.run``: this needs a timeout and extra
            # variables. Same fixed environment otherwise.
            subprocess.run(command, capture_output=True, timeout=5, check=False,
                           env=build_notify_env())
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
    carries traffic for the rest of the world; None if there is none.
    Generic on purpose: it recognizes tunnel interfaces, not providers.

    The probe is a route lookup for a public address, not for ``default``:
    WireGuard-style VPNs leave the default route alone and add 0.0.0.0/1 and
    128.0.0.0/1, which only a lookup shows."""
    if sys.platform == "darwin":
        output = runner("route", "-n", "get", ROUTE_PROBE, check=False)
    else:
        output = (runner("ip", "-4", "route", "show", "table", "all", check=False) + "\n"
                  + runner("ip", "-4", "route", "get", ROUTE_PROBE, check=False))
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


class _Hangup(BaseException):
    """The terminal went away (SIGHUP). Nobody is watching, so this must not
    end in a rollback: see ``_Session.abandon``."""


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


def _raise_hangup(signum, frame):
    raise _Hangup


def _install_stop_handlers() -> dict:
    """SIGTERM (``session stop``) ends the session the way Ctrl-C does: an
    explicit stop. SIGHUP (terminal closed) is not one."""
    saved = {}
    for signum, handler in ((signal.SIGTERM, _raise_interrupt), (signal.SIGHUP, _raise_hangup)):
        try:
            saved[signum] = signal.signal(signum, handler)
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


def _manages_dns() -> bool:
    """Whether bringing a tunnel up rewrites system DNS settings that nothing
    but the tunnel's own helper would restore. True on macOS only."""
    return sys.platform == "darwin"


def _networksetup_values(output: str) -> list[str]:
    """Entries from ``networksetup -getdnsservers`` / ``-getsearchdomains``.
    Addresses and domains never contain a space; the "There aren't any ...
    set on <service>." message does, and means empty (automatic). This is
    the same test wg-quick itself applies."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if any(" " in line for line in lines):
        return []
    return lines


def _network_services(runner=None) -> list[str]:
    """Every network service name, disabled ones included (wg-quick changes
    those too). The first line of the listing is an explanation."""
    runner = run if runner is None else runner
    names = []
    for line in runner("networksetup", "-listallnetworkservices").splitlines()[1:]:
        name = line.strip()
        if name.startswith("*"):
            name = name[1:].strip()
        if name and name not in names:
            names.append(name)
    return names


def read_dns_settings(runner=None) -> dict[str, dict[str, list[str]]]:
    """Each network service's DNS servers and search domains, as needed to
    set them back. An empty list means none set (automatic). Read-only."""
    runner = run if runner is None else runner
    settings = {}
    for name in _network_services(runner):
        settings[name] = {
            "servers": _networksetup_values(runner("networksetup", "-getdnsservers", name)),
            "search": _networksetup_values(runner("networksetup", "-getsearchdomains", name)),
        }
    return settings


def _undo_dns(undo: dict, backend_factory) -> None:
    """Set every recorded service's DNS servers and search domains back.
    A service that no longer exists is skipped; any other failure raises
    after the rest have been tried."""
    failed = []
    for name, saved in (undo.get("services") or {}).items():
        try:
            run("networksetup", "-setdnsservers", name, *(saved.get("servers") or ["Empty"]))
            run("networksetup", "-setsearchdomains", name, *(saved.get("search") or ["Empty"]))
        except BackendError:
            failed.append(name)
    if failed:
        try:
            present = set(_network_services())
        except BackendError:
            present = set(failed)
        failed = [name for name in failed if name in present]
    if failed:
        raise BackendError(
            f"Could not restore the DNS settings of {len(failed)} network service(s): "
            + ", ".join(failed))


journal.register_undo("dns", _undo_dns)
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
        if not failures:
            _remove_staged()  # no tunnel entry is left that needs a staged config
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
    configs: dict  # staged config path -> tunnel.TunnelConfig, primary first
    endpoints: list
    strict: bool
    strict_on: frozenset
    lockdown_rules: str
    strict_rules: str
    portal_rules: str | None
    silent_rules: str


def staging_dir() -> Path:
    """Root-only directory holding the validated copies of the WireGuard
    configs. Only these copies are parsed, brought up, taken down and
    journaled; the user's own files are read exactly once."""
    return _state_dir() / "configs"


def _remove_staged() -> None:
    """Delete the staged configs (they hold the private key). Best effort."""
    directory = staging_dir()
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        try:
            os.unlink(directory / name)  # never follows a link
        except OSError:
            pass
    try:
        os.rmdir(directory)
    except OSError:
        pass


def _load_config(path: str) -> tunnel.TunnelConfig:
    """Parse a *staged* config."""
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


def _stage_configs(paths: list[str], local: list[str]) -> dict:
    """Validate and stage every config; staged path -> parsed config."""
    names = [Path(p).name for p in paths]
    if len(set(names)) != len(names):
        raise SessionError(
            "WG_CONFIG and WG_CONFIG_FALLBACK must have different file names.")
    directory = staging_dir()
    directory.parent.mkdir(mode=journal.DIR_MODE, parents=True, exist_ok=True)
    directory.mkdir(mode=journal.DIR_MODE, exist_ok=True)
    os.chmod(directory, journal.DIR_MODE)
    configs = {}
    for path in paths:
        try:
            staged = str(tunnel.stage_config(path, directory, local))
        except tunnel.ConfigError as e:
            problems = list(getattr(e, "problems", None) or [str(e)])
            raise SessionError(
                f"WireGuard config {path} cannot be used:\n  - " + "\n  - ".join(problems)) from None
        configs[staged] = _load_config(staged)
    return configs


def _preflight(options: Options, backend, environ) -> _Plan:
    """Every check that can refuse a session. Changes nothing on the system;
    the one thing it writes is the staged copy of each config, which it
    removes again if it refuses."""
    if options.duration <= 0 or options.poll <= 0 or options.portal_seconds < 0:
        raise SessionError("Duration and poll interval must be greater than zero.")
    for command in ("wg-quick", "wg"):
        if not _have(command):
            raise SessionError(
                f"`{command}` was not found on PATH. Install wireguard-tools first.")

    paths = list(dict.fromkeys(p for p in (options.config, options.fallback) if p))
    if not paths or not options.config:
        raise SessionError("No WireGuard config given: set WG_CONFIG.")

    # Before anything is staged: a pending tunnel entry still needs the
    # staged config it names.
    pending = journal.pending()
    if pending:
        raise SessionError(
            f"{len(pending)} change(s) from an earlier session are still applied. "
            f"Run `{PANIC_HINT}` to undo them before starting a new session.")

    other = default_route_tunnel(options.interface)
    if other:
        raise SessionError(
            f"Another tunnel ({other}) already carries the default route. Disconnect "
            "that VPN first: its own kill switch would conflict with this one.")

    try:
        strict, strict_on = detect.strict_settings(options.strict, environ)
        ks = killswitch.platform_module()
    except (ValueError, NotImplementedError) as e:
        raise SessionError(str(e)) from None

    try:
        associated = bool(backend.gateway())
    except BackendError:
        associated = False

    _remove_staged()  # leftovers of a crashed session; nothing pending needs them
    try:
        configs = _stage_configs(paths, _local_addresses(backend))
        endpoints = [(c.endpoint_ip, c.endpoint_port) for c in configs.values()]
        iface = options.interface
        try:
            lockdown_rules = ks.build_rules(iface, None, endpoints, False,
                                            silent=True, allow_dhcp=False)
            strict_rules = ks.build_rules(iface, None, endpoints, False)
            portal_rules = (ks.build_rules(iface, None, endpoints, True)
                            if options.portal else None)
            silent_rules = ks.build_rules(iface, None, endpoints, False, silent=True)
        except (ValueError, NotImplementedError) as e:
            raise SessionError(str(e)) from None
    except BaseException:
        _remove_staged()
        raise

    if associated:
        _say(SEEN_NOTICE + ".")
    return _Plan(ks, configs, endpoints, strict, strict_on, lockdown_rules, strict_rules,
                 portal_rules, silent_rules)


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
        self.current_rules: str | None = None  # what the kill switch should hold
        self.tunnel_journaled = False
        self.tunnel_up = False
        self.killswitch_loaded: bool | None = None
        # ``silent``: the decision to block everything until ``session stop``.
        # ``silent_pending``: the work for it (silent rules loaded, tunnel
        # down) has not all succeeded yet and is retried on every poll.
        self.silent = False
        self.silent_pending = False
        self._silent_rules_ok = False
        self._silent_tunnel_ok = False
        self.seen: set[str] = set()

        self.baseline = None
        self.previous = None
        self.history: list[set[str]] = []
        self._said: set[str] = set()
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

    def _alert_once(self, key: str, message: str) -> None:
        """An alert for a failure that is retried every poll: said once."""
        if key not in self._said:
            self._said.add(key)
            self.alert(message)

    # -- kill switch

    def _load(self, rules: str, ensure_enabled: bool = False) -> None:
        """Reload the kill switch with ``rules`` (the first load is in
        ``setup``). ``current_rules`` is updated first, so a load that fails
        is what the next poll's check retries. With ``ensure_enabled``, pf is
        also enabled again if something disabled it; the new enable reference
        is journaled with stop signals held back, like the first one."""
        ks = self.plan.ks
        self.current_rules = rules
        ks.load(rules, self.ks_undo)
        enable = getattr(ks, "ensure_enabled", None) if ensure_enabled else None
        if enable is not None:
            with _signals_blocked():
                token = enable()
                if token is not None:
                    journal.record("pf_token", {"anchor": (self.ks_undo or {}).get("anchor"),
                                                "token": str(token)})

    # -- steps 2-5

    def setup(self) -> None:
        options, backend, plan, ks = self.options, self.backend, self.plan, self.plan.ks
        iface = options.interface

        # 2. Kill switch first, in lockdown: only loopback passes, on every
        # interface, so nothing at all leaves the machine while its identity
        # changes. Being the oldest entry, it is also the last thing a
        # rollback removes, so the tunnel, address and names are put back
        # while it still blocks traffic. The entry is journaled before the
        # first load; the pf enable token is journaled on its own as soon as
        # it exists, with stop signals held back so the two cannot be
        # separated.
        journal.record("killswitch", {"platform_undo": _platform_undo(ks)})
        with _signals_blocked():
            self.current_rules = plan.lockdown_rules
            self.ks_undo = ks_undo = ks.load(plan.lockdown_rules)
            if ks_undo.get("token") is not None:
                journal.record("pf_token", {"anchor": ks_undo.get("anchor"),
                                            "token": str(ks_undo["token"])})
        self.killswitch_loaded = True
        _say("Kill switch is up: nothing leaves this machine while its identity changes.")
        self.write_status()

        # 3. Inbound exposure, host name, MAC address: all under lockdown.
        # Without it the new host name could go out (DHCP, mDNS) from the old
        # address and tie the two identities together.
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

        original_mac = backend.current_mac()
        new_mac = _cli.rotate(backend, journal=journal)
        _say(f"{iface} MAC address is now {new_mac}.")

        # 4. Strict rules: DHCP and the tunnel endpoints only, so the
        # interface can rejoin the network under the new identity.
        self._load(plan.strict_rules)
        self._wait_for_network()

        # Captive portal: the exception is open only for this window, under the
        # new identity, and the strict rules come back whatever happens in it.
        # That reload also drops the connections the window opened (pf states).
        if options.portal:
            try:
                self._load(plan.portal_rules)
                _say(f"WARNING: for up to {options.portal_seconds:g} s, web traffic (TCP 80/443) "
                     "and DNS on this network are NOT protected.")
                _say("Log in to the network's portal page now, and nothing else. "
                     "Press Enter as soon as you are done.")
                self.wait_enter(options.portal_seconds, self.clock, self.sleep)
            finally:
                self._load(plan.strict_rules)
                _say("Portal window closed; strict kill switch rules are loaded.")

        # 5. Tunnel. On macOS ``wg-quick up`` rewrites every network service's
        # DNS settings and only its own monitor process restores them, so they
        # are journaled first. Then every config that may be brought up.
        if _manages_dns():
            services = read_dns_settings()
            if services:
                journal.record("dns", {"services": services})
        for path in plan.configs:
            journal.record("tunnel", {"config_path": path})
        self.tunnel_journaled = True
        paths = list(plan.configs)
        self.config_used, self.tunnel_if = tunnel.up_with_fallback(
            paths[0], paths[1] if len(paths) > 1 else None)
        self._load(ks.build_rules(iface, self.tunnel_if, plan.endpoints, False))
        self.tunnel_up = True
        _say(f"Tunnel is up on {self.tunnel_if}.")
        self.write_status()

        self.baseline = self.previous = self._take_baseline()

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

    def _take_baseline(self):
        """The reading every later one is judged against. It must name the
        gateway and at least one hardware address answering for it; a
        baseline without them would make ARP spoofing invisible, so the
        session does not start on one."""
        deadline = self.clock() + BASELINE_TIMEOUT
        while True:
            try:
                reading = detect.reading_from(self.backend)
                if detect.usable_as_baseline(reading):
                    return reading
            except BackendError:
                pass
            if self.clock() >= deadline:
                raise SessionError(
                    "Could not read the gateway and its hardware address within "
                    f"{BASELINE_TIMEOUT} s, so there is nothing to detect changes against.")
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
            if not self.silent and remaining <= 0:
                # Nobody may be watching, and the machine may still be on the
                # hostile network: block everything rather than put the real
                # address and name back on a timer.
                self.go_silent(TIME_UP_NOTICE)
                self.write_status()
            if self.silent:
                # Stay blocked until someone stops us.
                self.sleep(self.options.poll)
            else:
                self.sleep(min(self.options.poll, remaining))
            self.poll_once()
            self.write_status()

    def poll_once(self) -> None:
        self._silent_work()  # whatever an earlier poll's attempt could not finish

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
            self.history = (self.history + [found])[-3:]
            self.previous = reading
            self.seen |= found
            for action, finding in actions:
                text = _FINDING_TEXT.get(finding, finding)
                if action == detect.WARN:
                    self.alert(f"Warning ({finding}): {text} Your traffic stays encrypted.")
                elif action == detect.GO_SILENT:
                    self.go_silent(f"Strict mode ({finding}): stopping the tunnel. All traffic "
                                   "is blocked until you run `session stop`.")

        self._check_killswitch()

        self.tunnel_up = bool(self.tunnel_if) and tunnel.is_up(self.tunnel_if)
        if self.tunnel_up:
            self._tunnel_warned = False
        elif not self.silent and not self._tunnel_warned:
            self._tunnel_warned = True
            self.alert("The tunnel is down. All traffic is blocked by the kill switch "
                       "until it reconnects or you stop the session.")

    def _killswitch_state(self) -> bool | None:
        try:
            return bool(self.plan.ks.is_loaded())
        except Exception:
            return None

    def _check_killswitch(self) -> None:
        """Not loaded, or not checkable: load the current rules again, now.
        If that fails, stop the tunnel and keep trying on every poll."""
        loaded = self._killswitch_state()
        if loaded is True:
            self._killswitch_warned = False
            self._said -= {"ks_reload", "ks_reloaded"}
            self.killswitch_loaded = True
            return
        if not self._killswitch_warned:
            self._killswitch_warned = True
            self.alert("WARNING: the kill switch rules are no longer loaded"
                       + (" " if loaded is False else ", or could not be checked ")
                       + "(traffic could leave outside the tunnel). Reloading them now.")
        try:
            self._load(self.current_rules, ensure_enabled=True)
        except Exception as e:
            self._alert_once("ks_reload", f"Could not reload the kill switch: {e}")
            self.go_silent("The kill switch could not be reloaded: stopping the tunnel so "
                           "nothing leaves outside it. Leave this network. Retrying every "
                           f"{self.options.poll:g} s.")
        else:
            if self.silent:
                self._silent_rules_ok = True
            if "ks_reloaded" not in self._said:
                self._said.add("ks_reloaded")
                _say("Kill switch rules reloaded.")
        self.killswitch_loaded = self._killswitch_state()

    def go_silent(self, why: str | None) -> None:
        """Block everything and stop the tunnel, until ``session stop``.
        Idempotent. The work is attempted now and, for whatever part fails,
        again on every poll (``silent_pending``)."""
        if not self.silent:
            self.silent = True
            self.silent_pending = True
            self._silent_rules_ok = self._silent_tunnel_ok = False
            if why:
                self.alert(why)
        self.current_rules = self.plan.silent_rules
        self._silent_work()

    def _silent_work(self) -> None:
        if not self.silent_pending:
            return
        # Rules first: no tunnel interface and no endpoint exception, so a
        # tunnel that is still running has no way out. On macOS the load also
        # drops the states the old rules created.
        if not self._silent_rules_ok and self.ks_undo is not None:
            try:
                self._load(self.plan.silent_rules, ensure_enabled=True)
                self._silent_rules_ok = True
            except Exception as e:
                self._alert_once("silent_rules",
                                 f"Could not tighten the kill switch (will keep trying): {e}")
        if not self._silent_tunnel_ok:
            if self.config_used:
                paths = [self.config_used]
            else:  # stopped part-way through bringing the tunnel up
                paths = list(self.plan.configs) if self.tunnel_journaled else []
            try:
                for path in paths:
                    _undo_tunnel({"config_path": path}, None)  # already down is fine
                self._silent_tunnel_ok = True
            except Exception as e:
                self._alert_once("silent_tunnel",
                                 f"Could not stop the tunnel (will keep trying): {e}")
        if self._silent_tunnel_ok:
            self.tunnel_up = False
        rules_done = self._silent_rules_ok or self.ks_undo is None
        self.silent_pending = not (rules_done and self._silent_tunnel_ok)

    def abandon(self, reason: str) -> None:
        """End the process without anyone having asked for a stop (terminal
        closed, unexpected error): go silent and leave every change, and the
        journal, in place. Rolling back here would put the real address and
        name back on a network that may be hostile, with nobody watching."""
        with _signals_ignored():
            self.go_silent(None)
            for _ in range(3):  # no later poll will retry, so try a little harder now
                if not self.silent_pending:
                    break
                try:
                    self.sleep(1)
                except BaseException:
                    pass
                self._silent_work()
            self.alert(f"{reason} {LEAVE_HINT}")
            if self.silent_pending:
                _say("WARNING: the kill switch or the tunnel could not be put into the "
                     f"blocked state. Turn Wi-Fi off now, then run `{STOP_HINT}`.")


def _roll_back_now(session: "_Session", backend_factory, opening: str) -> int:
    """The explicit stop: say what is about to become visible, then undo
    everything. Returns the number of changes that could not be undone."""
    with _signals_ignored():  # a second Ctrl-C must not cut the rollback short
        session.phase = "stopping"
        session.write_status()
        _say(opening)
        _say(STOP_NOTICE)
        entries, failures = _rollback(backend_factory)
        _report(entries, failures)
    return len(failures)


def start(options: Options, *, backend_factory=get_backend, notifier=notify,
          clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
          wait_enter=wait_for_enter, environ=None) -> int:
    """Run a whole session.

    Returns 0 when it was stopped (``session stop`` or Ctrl-C) and everything
    was put back; 1 when a change could not be undone, or when the session
    ended on its own (terminal closed) and left its changes, the kill switch
    in silent mode and the journal in place for ``session stop``.

    Raises ``SessionError`` (or the original exception) if the session could
    not be set up; by then it has been rolled back. An unexpected error while
    holding is re-raised too, but with the changes left in place and all
    traffic blocked.
    """
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
        except _Hangup:
            if session.ks_undo is None:  # nothing is protecting anything yet
                _roll_back_now(session, backend_factory,
                               "The terminal was closed; undoing every change made so far.")
            else:
                session.abandon("The terminal was closed while the session was starting.")
            return 1
        except BaseException as e:
            reason = "was interrupted" if isinstance(e, KeyboardInterrupt) else "failed"
            _roll_back_now(session, backend_factory,
                           f"The session {reason}; undoing every change made so far.")
            raise

        try:
            session.hold()
        except KeyboardInterrupt:  # Ctrl-C, or SIGTERM from `session stop`
            _say("Stop requested.")
        except _Hangup:
            session.abandon("The terminal was closed.")
            return 1
        except Exception as e:
            session.abandon(f"The session hit an unexpected error ({type(e).__name__}).")
            raise
        failed = _roll_back_now(session, backend_factory, "Stopping: undoing every change.")
        return 1 if failed else 0
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
    in ``journal`` itself and the rest (``killswitch``, ``pf_token``,
    ``inbound``, ``hostname``, ``dns``, ``tunnel``) are registered by this
    module, so importing this module is what does the work."""
    from . import journal as _journal  # noqa: F401


def _panic_without_journal(error: Exception) -> int:
    """The journal cannot be read, so nothing in it can be trusted. Our
    anchor / table has a fixed name, so it can still be removed; nothing
    else is touched and no pf enable reference is released."""
    _say(f"The journal is unreadable: {error}")
    try:
        ks = killswitch.platform_module()
        with _signals_ignored():
            warnings = ks.unload(_platform_undo(ks))
        for warning in warnings:
            _say(f"Kill switch: {warning}")
        _say("  removed   kill switch rules (by name, without the journal)")
    except Exception as e:
        _say(f"  FAILED    kill switch rules: {e}")
    _say("Nothing else was undone: the MAC address, host name, inbound firewall, DNS "
         f"settings and tunnel are as the session left them. Inspect {journal.journal_path()} "
         "and restore those by hand; a reboot restores the hardware MAC address.")
    return 1


def panic(backend_factory=get_backend, *, kill=os.kill,
          clock: Callable[[], float] = time.time,
          sleep: Callable[[float], None] = time.sleep,
          timeout: float = STOP_TIMEOUT) -> int:
    """Undo everything in the journal, past individual failures, whatever
    state the previous session was left in. Returns 1 if anything failed.
    With an unreadable journal it still removes our kill switch rules, by
    name, reports that nothing else was undone, and returns 1."""
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

    try:
        entries, failures = _rollback(backend_factory)
    except journal.JournalCorrupt as e:
        return _panic_without_journal(e)
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
