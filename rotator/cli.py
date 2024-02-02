"""Command-line interface: status, rotate, restore, watch."""
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


def rotate(backend: Backend, new_mac: str | None = None) -> str:
    current = backend.current_mac()
    state.remember_original(backend.interface, current)
    target = macmod.normalize(new_mac) if new_mac else macmod.generate(exclude=current)
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
            now = time.monotonic()
            # Our own rotation drops and rejoins the network; ignore that churn.
            settling = now - last_rotation < args.cooldown

            if not settling and last_network and not network:
                # Rotate while disconnected so the next network sees a fresh address.
                last_rotation = do_rotate("Disconnected")
            elif not settling and network and last_network and network != last_network:
                last_rotation = do_rotate(f"Network changed to {network}")
            elif args.interval and now - last_rotation >= max(args.interval, args.cooldown):
                last_rotation = do_rotate("Interval elapsed")
            if network != last_network:
                log(f"Network: {network or 'not connected'}")
            last_network = network
    except KeyboardInterrupt:
        if args.restore_on_exit:
            cmd_restore(backend, argparse.Namespace(hardware=False))
        log("Stopped.")


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
    return p


COMMANDS = {"status": cmd_status, "rotate": cmd_rotate, "restore": cmd_restore, "watch": cmd_watch}


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    args = build_parser().parse_args(argv)
    try:
        COMMANDS[args.command](get_backend(args.interface), args)
    except BackendError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
