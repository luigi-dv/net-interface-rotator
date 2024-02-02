"""Remembers each interface's original MAC so it can always be restored."""
import json
import os
import pwd
from pathlib import Path


def _state_path() -> Path:
    # Under sudo, keep state in the invoking user's home, not root's.
    sudo_user = os.environ.get("SUDO_USER")
    home = Path(pwd.getpwnam(sudo_user).pw_dir) if sudo_user else Path.home()
    return home / ".config" / "net-interface-rotator" / "state.json"


def _load() -> dict:
    try:
        return json.loads(_state_path().read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def original_mac(interface: str) -> str | None:
    return _load().get(interface)


def remember_original(interface: str, mac: str) -> None:
    """Store ``mac`` as the interface's original, unless one is already stored."""
    data = _load()
    if interface in data:
        return
    data[interface] = mac
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    sudo_uid, sudo_gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if sudo_uid and sudo_gid:
        for p in (path.parent, path):
            os.chown(p, int(sudo_uid), int(sudo_gid))
