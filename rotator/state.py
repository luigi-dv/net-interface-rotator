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
    # The file holds the original MAC address, so only its owner may read it.
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(fd, 0o600)  # an older, wider file is tightened too
        handle.write(json.dumps(data, indent=2))
    sudo_uid, sudo_gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if sudo_uid and sudo_gid:
        for p in (path.parent, path):
            os.chown(p, int(sudo_uid), int(sudo_gid))
