"""Platform backend interface."""
import subprocess
from abc import ABC, abstractmethod


class BackendError(RuntimeError):
    pass


def run(*args: str, check: bool = True) -> str:
    """Run a command without a shell and return its stdout."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=check)
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
