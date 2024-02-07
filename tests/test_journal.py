"""Tests for the crash-safe journal. Everything lives under tmp_path."""
import json
import stat

import pytest

from rotator import journal


@pytest.fixture
def jpath(tmp_path, monkeypatch):
    path = tmp_path / "db" / "journal.jsonl"
    monkeypatch.setattr(journal, "journal_path", lambda: path)
    return path


def test_default_path_is_root_only_system_location():
    path = journal.journal_path()
    assert path.name == "journal.jsonl"
    assert path.parent.name == "net-interface-rotator"
    assert str(path).startswith(("/var/db/", "/var/lib/"))


def test_pending_is_empty_without_file(jpath):
    assert journal.pending() == []
    assert not jpath.exists()


def test_record_then_pending_is_newest_first(jpath):
    a = journal.record("mac", {"interface": "en0", "mac": "aa:bb:cc:dd:ee:ff"})
    b = journal.record("hostname", {"names": {"HostName": None}})
    c = journal.record("mac", {"interface": "en1", "mac": "11:22:33:44:55:66"})
    assert journal.pending() == [
        {"id": c, "kind": "mac", "undo": {"interface": "en1", "mac": "11:22:33:44:55:66"}},
        {"id": b, "kind": "hostname", "undo": {"names": {"HostName": None}}},
        {"id": a, "kind": "mac", "undo": {"interface": "en0", "mac": "aa:bb:cc:dd:ee:ff"}},
    ]


def test_record_is_on_disk_when_it_returns(jpath):
    entry_id = journal.record("mac", {"interface": "en0", "mac": "aa:bb:cc:dd:ee:ff"})
    lines = jpath.read_text().splitlines()
    assert [json.loads(line)["id"] for line in lines] == [entry_id]
    assert jpath.read_bytes().endswith(b"\n")


def test_ids_are_unique(jpath):
    ids = [journal.record("mac", {"n": n}) for n in range(50)]
    assert len(set(ids)) == 50
    assert all(isinstance(i, str) and i for i in ids)


def test_mark_undone_removes_from_pending_by_appending(jpath):
    a = journal.record("mac", {"n": 1})
    b = journal.record("mac", {"n": 2})
    before = jpath.read_bytes()
    journal.mark_undone(a)
    assert [e["id"] for e in journal.pending()] == [b]
    after = jpath.read_bytes()
    assert after.startswith(before) and len(after) > len(before)


def test_mark_undone_twice_is_harmless(jpath):
    a = journal.record("mac", {"n": 1})
    journal.mark_undone(a)
    size = jpath.stat().st_size
    journal.mark_undone(a)
    assert jpath.stat().st_size == size
    assert journal.pending() == []


def test_mark_undone_unknown_id_raises(jpath):
    journal.record("mac", {"n": 1})
    with pytest.raises(journal.JournalError):
        journal.mark_undone("nope")


def test_file_mode_is_0600_and_dir_0700(jpath, monkeypatch):
    import os
    old = os.umask(0)  # prove the mode does not depend on a friendly umask
    try:
        a = journal.record("mac", {"n": 1})
        journal.mark_undone(a)
    finally:
        os.umask(old)
    assert stat.S_IMODE(jpath.stat().st_mode) == 0o600
    assert stat.S_IMODE(jpath.parent.stat().st_mode) == 0o700


def test_loose_existing_file_mode_is_tightened(jpath):
    journal.record("mac", {"n": 1})
    jpath.chmod(0o644)
    journal.record("mac", {"n": 2})
    assert stat.S_IMODE(jpath.stat().st_mode) == 0o600


def test_truncated_final_line_is_ignored(jpath):
    a = journal.record("mac", {"n": 1})
    with open(jpath, "ab") as f:
        f.write(b'{"op":"record","id":"deadbeef","kind":"ma')
    assert [e["id"] for e in journal.pending()] == [a]


def test_appending_after_a_torn_line_keeps_the_journal_readable(jpath):
    a = journal.record("mac", {"n": 1})
    with open(jpath, "ab") as f:
        f.write(b'{"op":"record","id":"deadbeef","kind":"ma')
    b = journal.record("mac", {"n": 2})
    journal.mark_undone(a)
    assert [e["id"] for e in journal.pending()] == [b]
    for line in jpath.read_text().splitlines():
        json.loads(line)


def test_complete_final_line_missing_only_its_newline_is_kept(jpath):
    a = journal.record("mac", {"n": 1})
    jpath.write_bytes(jpath.read_bytes().rstrip(b"\n"))
    assert [e["id"] for e in journal.pending()] == [a]
    b = journal.record("mac", {"n": 2})
    assert [e["id"] for e in journal.pending()] == [b, a]


def test_mid_file_corruption_raises(jpath):
    journal.record("mac", {"n": 1})
    with open(jpath, "ab") as f:
        f.write(b"{garbage\n")
    with pytest.raises(journal.JournalCorrupt):
        journal.pending()
    journal_bytes = jpath.read_bytes()
    with pytest.raises(journal.JournalCorrupt):
        journal.clear()
    assert jpath.read_bytes() == journal_bytes


def test_corrupt_line_followed_by_valid_line_raises(jpath):
    journal.record("mac", {"n": 1})
    good = jpath.read_bytes()
    jpath.write_bytes(b'{"op":"record","id":\n' + good)
    with pytest.raises(journal.JournalCorrupt):
        journal.pending()


def test_valid_json_that_is_not_a_journal_line_raises(jpath):
    journal.record("mac", {"n": 1})
    with open(jpath, "ab") as f:
        f.write(b'{"hello":"world"}\n')
    with pytest.raises(journal.JournalCorrupt):
        journal.pending()


def test_clear_refuses_with_pending_entries(jpath):
    journal.record("mac", {"n": 1})
    with pytest.raises(journal.JournalError):
        journal.clear()
    assert jpath.exists()


def test_clear_removes_file_when_nothing_pending(jpath):
    a = journal.record("mac", {"n": 1})
    journal.mark_undone(a)
    journal.clear()
    assert not jpath.exists()
    journal.clear()  # no file: still fine
    assert journal.pending() == []


def test_record_rejects_unserializable_undo_without_writing(jpath):
    with pytest.raises(TypeError):
        journal.record("mac", {"bad": object()})
    with pytest.raises(TypeError):
        journal.record("mac", "not a dict")
    with pytest.raises(ValueError):
        journal.record("", {})
    assert not jpath.exists()


def test_journal_refuses_to_follow_a_symlink(jpath, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("")
    jpath.parent.mkdir()
    jpath.symlink_to(target)
    with pytest.raises(OSError):
        journal.record("mac", {"n": 1})
    assert target.read_text() == ""
