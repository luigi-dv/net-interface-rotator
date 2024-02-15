"""Command-line interface: status, rotate, restore, watch, session, audit, panic."""
import argparse
import os
import signal
import sys
import time

from dotenv import load_dotenv

from . import mac as macmod
from . import state
from .backends import Backend, BackendError, get_backend

DEFAULT_INTERFACE = "en0" if sys.platform == "darwin" else "wlan0"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit("This command changes the interface and must be run with sudo.")


def rotate(backend: Backend, new_mac: str | None = None, journal=None) -> str:
    """Apply a new MAC and return it.

    ``journal`` is the ``rotator.journal`` module (or an object with the same
    ``record``) when called from a session: the address in use is journaled,
    and synced to disk, before it is replaced, so ``journal.rollback`` can put
    it back. Standalone ``rotate`` passes nothing and relies on ``state`` alone.
    """
    current = backend.current_mac()
    state.remember_original(backend.interface, current)
    target = macmod.normalize(new_mac) if new_mac else macmod.generate(exclude=current)
    if journal is not None:
        journal.record("mac", {"interface": backend.interface, "mac": current})
    backend.set_mac(target)
    return target


def cmd_status(backend: Backend, _args) -> None:
    current = backend.current_mac()
    hardware = backend.hardware_mac()
    original = state.original_mac(backend.interface)
    print(f"Interface:    {backend.interface}")
    print(f"Current MAC:  {current}" + ("  (randomized)" if macmod.is_locally_administered(current) else ""))
    print(f"Hardware MAC: {hardware or 'unknown'}")
    print(f"Saved MAC:    {original or 'none (not rotated by this tool yet)'}")
    print(f"Network:      {backend.network_id() or 'not connected'}")


def cmd_rotate(backend: Backend, args) -> None:
    require_root()
    log(f"{backend.interface} -> {rotate(backend, args.mac)}")


def cmd_restore(backend: Backend, args) -> None:
    require_root()
    target = backend.hardware_mac() if args.hardware else state.original_mac(backend.interface)
    target = target or backend.hardware_mac()
    if not target:
        sys.exit("No saved or hardware MAC known for this interface.")
    backend.set_mac(target)
    log(f"{backend.interface} restored to {target}")


def next_action(
    prev_network: str | None,
    network: str | None,
    now: float,
    last_rotation: float,
    interval: float,
    cooldown: float,
) -> str | None:
    """Decide whether the watcher should rotate on this poll.

    Returns the reason to log, or None to leave the address alone. Pure: no
    clock, no backend. `now` and `last_rotation` are monotonic seconds.
    """
    elapsed = now - last_rotation
    # Our own rotation drops and rejoins the network; ignore that churn.
    settling = elapsed < cooldown

    if not settling and prev_network and not network:
        # Rotate while disconnected so the next network sees a fresh address.
        return "Disconnected"
    if not settling and network and prev_network and network != prev_network:
        return f"Network changed to {network}"
    if interval and elapsed >= max(interval, cooldown):
        return "Interval elapsed"
    return None


def cmd_watch(backend: Backend, args) -> None:
    require_root()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))

    def do_rotate(reason: str) -> float:
        try:
            log(f"{reason}: {backend.interface} -> {rotate(backend)}")
        except BackendError as e:
            log(f"Rotation failed: {e}")
        return time.monotonic()

    # Start "settled" so the first poll can react, but don't fire the interval at once.
    last_rotation = do_rotate("Startup") if args.rotate_now else time.monotonic() - args.cooldown
    last_network = backend.network_id()
    log(f"Watching {backend.interface} (network: {last_network or 'not connected'})")
    try:
        while True:
            time.sleep(args.poll)
            network = backend.network_id()
            reason = next_action(
                last_network, network, time.monotonic(), last_rotation, args.interval, args.cooldown
            )
            if reason:
                last_rotation = do_rotate(reason)
            if network != last_network:
                log(f"Network: {network or 'not connected'}")
            last_network = network
    except KeyboardInterrupt:
        if args.restore_on_exit:
            cmd_restore(backend, argparse.Namespace(hardware=False))
        log("Stopped.")


def _duration(text: str) -> float:
    from . import session
    try:
        return session.parse_duration(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _exit_with(call) -> None:
    """Run a session-level action and turn its result into an exit status."""
    from . import journal, session
    try:
        code = call()
    except (session.SessionError, journal.JournalError) as e:
        sys.exit(f"Error: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
    if code:
        sys.exit(code)


def session_options(args, environ=None):
    """Build ``session.Options`` from parsed arguments and the environment."""
    from . import session
    environ = os.environ if environ is None else environ
    config = (environ.get("WG_CONFIG") or "").strip()
    if not config:
        sys.exit(
            "WG_CONFIG is not set. Put the path of your WireGuard config in .env "
            "(see .env.example), for example WG_CONFIG=/etc/wireguard/nir.conf.")
    return session.Options(
        interface=args.interface,
        duration=args.duration,
        config=config,
        fallback=(environ.get("WG_CONFIG_FALLBACK") or "").strip() or None,
        portal=args.portal,
        portal_seconds=args.portal_seconds,
        strict=args.strict,
        keep_hostname=args.keep_hostname,
        keep_firewall=args.keep_firewall,
        poll=args.poll,
    )


def cmd_session(backend: Backend, args) -> None:
    from . import journal, session
    require_root()
    if args.session_command == "start":
        options = session_options(args)
        _exit_with(lambda: session.start(
            options, backend_factory=get_backend, notifier=session.notify,
            clock=time.time, sleep=time.sleep))
    elif args.session_command == "stop":
        _exit_with(lambda: session.stop_running(get_backend))
    else:
        def show() -> int:
            data = session.status()
            if data is not None:
                print(session.format_status(data, time.time()))
                return 0
            print("No session is running.")
            left = len(journal.pending())
            if left:
                print(f"{left} change(s) from an earlier session are still applied. "
                      f"Run `{session.PANIC_HINT}` to undo them.")
            return 0
        _exit_with(show)


def cmd_audit(backend: Backend, _args) -> None:
    from . import audit, session
    require_root()

    def check() -> int:
        results = audit.run_checks(session.audit_context(backend))
        print(audit.format_table(results))
        return 0 if audit.all_ok(results) else 1
    _exit_with(check)


def cmd_panic(_backend: Backend, _args) -> None:
    from . import session
    require_root()
    _exit_with(lambda: session.panic(get_backend))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="net-interface-rotator", description=__doc__)
    p.add_argument("-i", "--interface", default=os.getenv("NETWORK_INTERFACE") or DEFAULT_INTERFACE)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show current, hardware and saved MAC addresses")

    r = sub.add_parser("rotate", help="Apply a new random MAC now")
    r.add_argument("--mac", help="Use this address instead of a random one")

    rs = sub.add_parser("restore", help="Return to the MAC saved before the first rotation")
    rs.add_argument("--hardware", action="store_true", help="Restore the burned-in address instead")

    w = sub.add_parser("watch", help="Rotate on disconnect, network change and/or a timer")
    w.add_argument("--interval", type=int, default=int(os.getenv("ROTATE_INTERVAL") or 0),
                   help="Also rotate every N seconds while connected (0 = off; drops the connection briefly)")
    w.add_argument("--poll", type=float, default=float(os.getenv("POLL_SECONDS") or 3),
                   help="Seconds between network checks (default 3)")
    w.add_argument("--cooldown", type=float, default=30,
                   help="Ignore network changes for N seconds after a rotation (default 30)")
    w.add_argument("--rotate-now", action="store_true", help="Rotate once at startup")
    w.add_argument("--restore-on-exit", action="store_true", help="Restore the saved MAC on Ctrl-C")

    s = sub.add_parser("session", help="Protected, fully reversible session on an untrusted network")
    ssub = s.add_subparsers(dest="session_command", required=True)
    st = ssub.add_parser("start", help="Set everything up, hold it for --duration, then undo it all")
    st.add_argument("--duration", type=_duration, required=True,
                    help="How long to hold the session: 90s, 15m, 2h")
    st.add_argument("--portal", action="store_true",
                    help="Open a short, UNPROTECTED window first to log in to a captive portal")
    st.add_argument("--portal-seconds", type=float, default=120,
                    help="Longest the portal window may stay open (default 120)")
    st.add_argument("--strict", action=argparse.BooleanOptionalAction, default=None,
                    help="On a confirmed hostile-network finding, stop the tunnel and block all "
                         "traffic (default: STRICT in .env, else on)")
    st.add_argument("--keep-hostname", action="store_true", help="Do not randomize the host name")
    st.add_argument("--keep-firewall", action="store_true",
                    help="Do not change the inbound firewall settings")
    st.add_argument("--poll", type=float, default=3,
                    help="Seconds between network and tunnel checks (default 3)")
    ssub.add_parser("stop", help="Stop the running session and undo its changes")
    ssub.add_parser("status", help="Show time left, tunnel and kill-switch state, and findings")

    sub.add_parser("audit", help="Read-only leak checks; exits 1 if any fails")
    sub.add_parser("panic", help="Undo every recorded change, even after a crash or reboot")
    return p


COMMANDS = {
    "status": cmd_status, "rotate": cmd_rotate, "restore": cmd_restore, "watch": cmd_watch,
    "session": cmd_session, "audit": cmd_audit, "panic": cmd_panic,
}


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    args = build_parser().parse_args(argv)
    try:
        COMMANDS[args.command](get_backend(args.interface), args)
    except BackendError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
