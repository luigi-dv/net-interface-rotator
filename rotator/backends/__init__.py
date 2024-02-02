import sys

from .base import Backend, BackendError


def get_backend(interface: str) -> Backend:
    if sys.platform == "darwin":
        from .macos import MacOSBackend
        return MacOSBackend(interface)
    if sys.platform.startswith("linux"):
        from .linux import LinuxBackend
        return LinuxBackend(interface)
    raise BackendError(f"Unsupported platform: {sys.platform}")


__all__ = ["Backend", "BackendError", "get_backend"]
