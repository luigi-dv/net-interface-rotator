"""Remembers each interface's original MAC so it can always be restored.

Standalone ``rotate`` and ``watch`` only; a session keeps its originals in the
root-only journal instead.

The file lives in the invoking user's home, and under sudo this code runs as
root. The user (or anything running as the user) could plant a symbolic link
there to make root write somewhere else, so every step below is taken relative
to an open directory and refuses links rather than following them.
"""
import errno
import json
import os
import pwd
import stat
from pathlib import Path

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_MAX_BYTES = 1 << 20


def _invoking_user():
    """The password entry of the user who ran sudo; None when not under sudo.

    Raises ``OSError`` if sudo's variables name nobody.
    """
    name, uid = os.environ.get("SUDO_USER"), os.environ.get("SUDO_UID", "")
    if not name and not uid:
        return None
    if name:
        try:
            return pwd.getpwnam(name)
        except KeyError:
            pass
    if uid.isdigit():
        try:
            return pwd.getpwuid(int(uid))
        except KeyError:
            pass
    raise OSError(
        "Cannot tell which user ran sudo (SUDO_USER and SUDO_UID name no known "
        "user), so the saved-address file cannot be located.")


def _state_path() -> Path:
    # Under sudo, keep state in the invoking user's home, not root's.
    user = _invoking_user()
    home = Path(user.pw_dir) if user else Path.home()
    return home / ".config" / "net-interface-rotator" / "state.json"


def _refuse(path: Path, what: str) -> OSError:
    return OSError(errno.ELOOP, f"Refusing to use {path}: it is {what}")


def _open_dir(parent_fd: int, name: str, path: Path, create: bool, owner) -> tuple[int, bool]:
    """Open directory ``name`` inside ``parent_fd`` without following a link.

    Returns ``(fd, created)``. ``path`` is only used in messages.
    """
    created = False
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass  # appeared meanwhile; the checks below still apply to it
        info = os.lstat(name, dir_fd=parent_fd)
    if stat.S_ISLNK(info.st_mode):
        raise _refuse(path, "a symbolic link")
    if not stat.S_ISDIR(info.st_mode):
        raise _refuse(path, "not a directory")
    try:
        # O_NOFOLLOW covers a link swapped in after the lstat above.
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
            raise _refuse(path, "a symbolic link or not a directory") from None
        raise
    if created and owner is not None:
        try:
            os.fchown(fd, owner.pw_uid, owner.pw_gid)
        except OSError:
            os.close(fd)
            raise
    return fd, created


def _open_config_dir(path: Path, create: bool, owner) -> int:
    """An open descriptor for ``path.parent`` (``~/.config/net-interface-rotator``).

    The home directory itself is trusted; ``.config`` and the tool's own
    directory below it must be real directories.
    """
    app_dir = path.parent
    config_dir = app_dir.parent
    parent_fd = os.open(config_dir.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for directory in (config_dir, app_dir):
            fd, _ = _open_dir(parent_fd, directory.name, directory, create, owner)
            os.close(parent_fd)
            parent_fd = fd
        if create:
            # The file holds the original MAC address: owner-only directory.
            os.fchmod(parent_fd, 0o700)
            if owner is not None:
                os.fchown(parent_fd, owner.pw_uid, owner.pw_gid)
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def _open_file(dir_fd: int, path: Path, flags: int) -> int:
    """Open the state file inside ``dir_fd``; it must be a plain, unlinked-to file."""
    try:
        fd = os.open(path.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise _refuse(path, "a symbolic link") from None
        raise
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise _refuse(path, "not a regular file of its own (special file or hard link)")
    return fd


def _load() -> dict:
    path = _state_path()
    try:
        dir_fd = _open_config_dir(path, create=False, owner=None)
    except FileNotFoundError:
        return {}
    try:
        fd = _open_file(dir_fd, path, os.O_RDONLY)
    except FileNotFoundError:
        return {}
    finally:
        os.close(dir_fd)
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read(_MAX_BYTES)
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError:  # bad UTF-8 or bad JSON
        return {}
    return data if isinstance(data, dict) else {}


def original_mac(interface: str) -> str | None:
    return _load().get(interface)


def remember_original(interface: str, mac: str) -> None:
    """Store ``mac`` as the interface's original, unless one is already stored.

    Raises ``OSError`` and writes nothing if ``~/.config``, the tool's
    directory or the file is a symbolic link, or if the user who ran sudo
    cannot be identified.
    """
    data = _load()
    if interface in data:
        return
    data[interface] = mac
    owner = _invoking_user()
    path = _state_path()
    dir_fd = _open_config_dir(path, create=True, owner=owner)
    try:
        # No O_TRUNC: the file is emptied only after it is known to be a
        # plain file with no other name.
        fd = _open_file(dir_fd, path, os.O_WRONLY | os.O_CREAT)
    finally:
        os.close(dir_fd)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        os.fchmod(fd, 0o600)  # an older, wider file is tightened too
        if owner is not None:
            os.fchown(fd, owner.pw_uid, owner.pw_gid)
        os.ftruncate(fd, 0)
        handle.write(json.dumps(data, indent=2))
