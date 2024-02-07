"""Crash-safe record of every change a session makes, so it can be undone.

The journal is an append-only JSON-lines file. Two kinds of line exist:

    {"op": "record", "id": "<hex>", "kind": "mac", "undo": {...}}
    {"op": "undone", "id": "<hex>"}

Nothing is ever rewritten in place: undoing an entry appends a marker. Every
append is synced to disk before the function returns.

The contract callers must keep:

1. Call ``record()`` **before** applying the change it describes. When
   ``record()`` returns, the entry is on disk, so a crash at any later point
   still leaves enough to restore the machine. A crash *during* ``record()``
   leaves at most a torn final line, which is ignored on read; that is safe
   because the change had not been applied yet.
2. Call ``mark_undone()`` only **after** the undo has succeeded. A crash
   between the two means the undo runs again next time, so undo functions must
   be idempotent ("set the old value back", never "toggle").
3. ``undo`` holds only what is needed to restore, and never a secret: no
   private keys, no config contents. The file is root-only, but it outlives
   the session if the machine crashes.

Undo functions are looked up by ``kind`` in a registry. Modules that add a
kind register it themselves with ``register_undo``; this file knows only
``"mac"``. A module must be imported for its kind to be known, so whatever
drives ``rollback`` (``session stop``, ``panic``) imports them all first.

The journal assumes one writer at a time (one session per machine).
"""
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Callable

try:
    import fcntl
except ImportError:  # pragma: no cover - not a supported platform anyway
    fcntl = None

DIR_MODE = 0o700
FILE_MODE = 0o600

# (undo dict, backend_factory) -> None. backend_factory(interface) -> Backend.
UndoFn = Callable[[dict, Callable[[str], Any]], None]


class JournalError(RuntimeError):
    """The journal was used in a way that would lose track of a change."""


class JournalCorrupt(JournalError):
    """A line other than a torn final one cannot be read."""


def journal_path() -> Path:
    base = "/var/db" if sys.platform == "darwin" else "/var/lib"
    return Path(base) / "net-interface-rotator" / "journal.jsonl"


# --- durable appends -------------------------------------------------------

def _fsync(fd: int) -> None:
    # On macOS fsync() does not force the drive to flush; F_FULLFSYNC does.
    full = getattr(fcntl, "F_FULLFSYNC", None)
    if full is not None:
        try:
            fcntl.fcntl(fd, full)
            return
        except OSError:
            pass  # filesystem without support; fall back to plain fsync
    os.fsync(fd)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    while data:
        data = data[os.write(fd, data):]


def _repair_tail(fd: int) -> None:
    """Make sure the file ends at a line boundary before appending to it.

    A crash mid-write can leave a final line with no newline. Appending after
    it would fuse two lines into one unreadable line in the middle of the
    file. A torn line is dropped (its change was never applied, see the module
    docstring); a complete line that only lost its newline gets one.
    """
    size = os.fstat(fd).st_size
    if size == 0:
        return
    data = os.pread(fd, size, 0)
    if data.endswith(b"\n"):
        return
    start = data.rfind(b"\n") + 1
    try:
        _parse(data[start:])
    except JournalCorrupt:
        os.ftruncate(fd, start)
    else:
        _write_all(fd, b"\n")


def _append(obj: dict) -> None:
    line = json.dumps(obj, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    path = journal_path()
    path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    os.chmod(path.parent, DIR_MODE)

    flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, FILE_MODE)
        created = True
    except FileExistsError:
        fd = os.open(path, flags)
        created = False
    try:
        os.fchmod(fd, FILE_MODE)  # the umask or an earlier owner may differ
        if not created:
            _repair_tail(fd)
        _write_all(fd, line)  # unbuffered, so there is nothing to flush
        _fsync(fd)
    finally:
        os.close(fd)
    if created:
        _fsync_dir(path.parent)


# --- reading ---------------------------------------------------------------

def _parse(raw: bytes) -> dict:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except ValueError as e:  # includes JSONDecodeError and UnicodeDecodeError
        raise JournalCorrupt(str(e)) from e
    if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
        raise JournalCorrupt("not a journal line")
    op = obj.get("op")
    if op == "record":
        if not isinstance(obj.get("kind"), str) or not isinstance(obj.get("undo"), dict):
            raise JournalCorrupt("record line without kind/undo")
    elif op != "undone":
        raise JournalCorrupt(f"unknown op {op!r}")
    return obj


def _read() -> list[dict]:
    try:
        data = journal_path().read_bytes()
    except FileNotFoundError:
        return []
    lines = data.split(b"\n")
    tail = lines.pop()  # b"" when the file ends with a newline, as it should
    out = []
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            out.append(_parse(raw))
        except JournalCorrupt as e:
            raise JournalCorrupt(
                f"{journal_path()} line {number} is unreadable ({e}). "
                "Refusing to guess which changes are still applied."
            ) from e
    if tail.strip():
        try:
            out.append(_parse(tail))
        except JournalCorrupt:
            pass  # torn final line from a crash mid-write
    return out


# --- public API ------------------------------------------------------------

def record(kind: str, undo: dict) -> str:
    """Journal a change that is *about to be* made, and return the entry's id.

    Call this before applying the change. It returns only once the entry has
    been written and fsynced, so from then on a crash cannot lose it. If this
    raises, do not apply the change.

    ``undo`` must be JSON-serializable and hold only what the kind's undo
    function needs, e.g. ``{"interface": "en0", "mac": "aa:bb:..."}``. Never
    put a secret in it.
    """
    if not isinstance(kind, str) or not kind:
        raise ValueError("kind must be a non-empty string")
    if not isinstance(undo, dict):
        raise TypeError("undo must be a dict")
    entry_id = secrets.token_hex(8)
    _append({"op": "record", "id": entry_id, "kind": kind, "undo": undo})
    return entry_id


def mark_undone(id: str) -> None:
    """Note that entry ``id`` has been undone. Call after the undo succeeded."""
    lines = _read()
    if not any(line["op"] == "record" and line["id"] == id for line in lines):
        raise JournalError(f"No journal entry with id {id!r}")
    if any(line["op"] == "undone" and line["id"] == id for line in lines):
        return
    _append({"op": "undone", "id": id})


def pending() -> list[dict]:
    """Entries not yet undone, newest first: ``{"id", "kind", "undo"}`` each."""
    lines = _read()
    undone = {line["id"] for line in lines if line["op"] == "undone"}
    return [
        {"id": line["id"], "kind": line["kind"], "undo": line["undo"]}
        for line in reversed(lines)
        if line["op"] == "record" and line["id"] not in undone
    ]


def clear() -> None:
    """Remove the journal file. Refuses while any entry is still pending."""
    left = pending()
    if left:
        raise JournalError(f"{len(left)} change(s) not undone yet; refusing to clear the journal")
    path = journal_path()
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_dir(path.parent)


# --- undo registry ---------------------------------------------------------

_UNDO: dict[str, UndoFn] = {}


def register_undo(kind: str, fn: UndoFn) -> None:
    """Register ``fn(undo, backend_factory)`` as the way to undo ``kind``.

    ``fn`` must be idempotent and must raise if it could not restore.
    Registering a different function for a kind that already has one is an
    error; registering the same one again is harmless.
    """
    existing = _UNDO.get(kind)
    if existing is not None and existing is not fn:
        raise ValueError(f"An undo function for {kind!r} is already registered")
    _UNDO[kind] = fn


def undo_entry(entry: dict, backend_factory: Callable[[str], Any]) -> None:
    """Undo one journal entry. Does not mark it undone; ``rollback`` does."""
    fn = _UNDO.get(entry["kind"])
    if fn is None:
        raise JournalError(f"Don't know how to undo a {entry['kind']!r} change")
    fn(entry["undo"], backend_factory)


def rollback(
    backend_factory: Callable[[str], Any], keep_going: bool = False
) -> list[tuple[dict, Exception]]:
    """Undo every pending entry, newest first, and return the failures.

    Each entry is marked undone only after its undo succeeded. With
    ``keep_going=False`` the first failure is re-raised and everything older
    stays pending. With ``keep_going=True`` (``panic``) later entries are still
    attempted and the failures come back as ``(entry, exception)`` pairs; those
    entries stay pending for another run. The journal file is removed once
    nothing is pending.
    """
    failures: list[tuple[dict, Exception]] = []
    for entry in pending():
        try:
            undo_entry(entry, backend_factory)
            mark_undone(entry["id"])
        except Exception as e:
            if not keep_going:
                raise
            failures.append((entry, e))
    if not failures:
        clear()
    return failures


def _undo_mac(undo: dict, backend_factory: Callable[[str], Any]) -> None:
    backend_factory(undo["interface"]).set_mac(undo["mac"])


register_undo("mac", _undo_mac)
