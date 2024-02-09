"""Firewall kill switch: nothing leaves the physical interface outside the tunnel.

Each platform module exposes the same three functions:

    build_rules(iface, tunnel_if, endpoints, allow_portal) -> str   (pure)
    load(rules, undo=None) -> dict      undo info for the caller to journal
    unload(undo) -> list[str]           non-fatal warnings

Pass the dict from the first ``load`` as ``undo`` when reloading.
"""
import sys


def platform_module():
    """The kill-switch module for this operating system."""
    if sys.platform == "darwin":
        from . import macos_pf
        return macos_pf
    if sys.platform.startswith("linux"):
        from . import linux_nft
        return linux_nft
    raise NotImplementedError(f"No kill switch for platform {sys.platform!r}")
