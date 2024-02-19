"""Platform backend interface."""
import os
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod


class BackendError(RuntimeError):
    pass


# Commands run as root, so nothing about how they are found or how they format
# their output may come from the caller's environment.
_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# Where Homebrew and source installs put WireGuard. Searched last, and only
# for the commands below.
_WIREGUARD_DIRS = "/opt/homebrew/bin:/usr/local/bin"
_WIREGUARD_COMMANDS = frozenset({"wg", "wg-quick", "bash"})
_KEPT_VARIABLES = ("HOME", "SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND")


def command_env(command: str, environ=None) -> dict[str, str]:
    """The complete environment ``run`` gives ``command``.

    A fixed ``PATH`` and the C locale, plus ``HOME`` and sudo's ``SUDO_*`` when
    set. Everything else is dropped, including every ``WG_*`` variable.
    """
    environ = os.environ if environ is None else environ
    path = _SYSTEM_PATH
    if command in _WIREGUARD_COMMANDS:
        path += ":" + _WIREGUARD_DIRS
    env = {"PATH": path, "LC_ALL": "C", "LANG": "C"}
    for name in _KEPT_VARIABLES:
        if name in environ:
            env[name] = environ[name]
    return env


def _argv(args: tuple[str, ...]) -> tuple[str, ...]:
    """macOS only: start ``wg-quick`` with the bash from a WireGuard directory.

    ``wg-quick`` is a ``#!/usr/bin/env bash`` script that needs bash 4 or
    newer. With system directories first on ``PATH``, ``env`` would pick
    /bin/bash (3.2) and the script would refuse to run.
    """
    if sys.platform != "darwin" or not args or args[0] != "wg-quick":
        return args
    script = shutil.which("wg-quick", path=f"{_SYSTEM_PATH}:{_WIREGUARD_DIRS}")
    bash = shutil.which("bash", path=_WIREGUARD_DIRS)
    if script and bash:
        return (bash, script, *args[1:])
    return args


def run(*args: str, check: bool = True, input: str | None = None) -> str:
    """Run a command without a shell and return its stdout.

    The command gets the fixed environment from ``command_env``. ``input`` is
    text for its standard input.
    """
    try:
        result = subprocess.run(
            _argv(args), capture_output=True, text=True, errors="replace",
            check=check, input=input, env=command_env(args[0]))
    except FileNotFoundError as e:
        raise BackendError(f"Command not found: {args[0]}") from e
    except subprocess.CalledProcessError as e:
        raise BackendError(f"`{' '.join(args)}` failed: {e.stderr.strip() or e.returncode}") from e
    return result.stdout


class Backend(ABC):
    def __init__(self, interface: str):
        self.interface = interface

    @abstractmethod
    def current_mac(self) -> str:
        """The address the interface is using right now."""

    @abstractmethod
    def hardware_mac(self) -> str | None:
        """The burned-in address, if the OS can report it."""

    @abstractmethod
    def set_mac(self, mac: str) -> None:
        """Apply ``mac`` to the interface. Requires root."""

    @abstractmethod
    def network_id(self) -> str | None:
        """A fingerprint of the connected network, or None when disconnected."""

    @abstractmethod
    def get_hostname(self) -> dict[str, str | None]:
        """The machine's host names, keyed by backend-specific names.

        A name the OS has not set is reported as None.
        """

    @abstractmethod
    def set_hostname(self, names: dict[str, str | None]) -> None:
        """Apply the host names in ``names``. Requires root.

        Keys whose value is None are skipped: this never unsets a name.
        """

    @abstractmethod
    def get_inbound(self) -> dict[str, bool]:
        """The current inbound-exposure settings, as needed to restore them.

        Backends with nothing to manage here return an empty dict.
        """

    @abstractmethod
    def harden_inbound(self) -> dict[str, bool]:
        """Block unsolicited inbound connections. Requires root.

        Returns the settings as they were *before* hardening: the value a
        session journals and later passes to ``restore_inbound``.
        """

    @abstractmethod
    def restore_inbound(self, previous: dict[str, bool]) -> None:
        """Set the inbound settings back to ``previous``. Requires root.

        Keys missing from ``previous`` are left alone.
        """

    @abstractmethod
    def gateway(self) -> str | None:
        """The default gateway IP on this interface, or None when there is none."""

    @abstractmethod
    def neighbours(self) -> dict[str, set[str]]:
        """IP -> MAC addresses seen for it on this interface.

        MACs are normalized with ``rotator.mac.normalize``. Incomplete and
        FAILED entries are skipped. Only this interface's entries are returned.
        """

    @abstractmethod
    def dhcp_dns(self) -> list[str]:
        """DNS servers handed out by DHCP on this interface, in order."""

    @abstractmethod
    def ssid(self) -> str | None:
        """The Wi-Fi network name, or None when unknown or not on Wi-Fi."""

    @abstractmethod
    def bssid(self) -> str | None:
        """The access-point MAC of the Wi-Fi network, or None when unknown."""
