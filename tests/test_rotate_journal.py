"""`rotate` journaling its MAC change, and `journal.rollback` putting it back.

FakeBackend only; state.json and the journal both live under tmp_path.
"""
import pytest

from rotator import journal, state
from rotator.cli import rotate
from tests.fakes import FakeBackend

ORIGINAL = "aa:bb:cc:dd:ee:ff"


@pytest.fixture(autouse=True)
def tmp_files(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "journal_path", lambda: tmp_path / "db" / "journal.jsonl")
    monkeypatch.setattr(state, "_state_path", lambda: tmp_path / "state.json")
    for var in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


@pytest.fixture
def restore_registry(monkeypatch):
    monkeypatch.setattr(journal, "_UNDO", dict(journal._UNDO))


class CheckingBackend(FakeBackend):
    """Records what the journal held at the moment set_mac was called."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_at_set: list[list[dict]] = []

    def set_mac(self, m):
        self.pending_at_set.append(journal.pending())
        super().set_mac(m)


def factory_for(*backends):
    by_name = {b.interface: b for b in backends}
    return lambda interface: by_name[interface]


def test_rotate_journals_previous_mac_before_set_mac():
    backend = CheckingBackend(mac=ORIGINAL)
    target = rotate(backend, journal=journal)
    assert backend.mac == target != ORIGINAL
    (seen,) = backend.pending_at_set
    assert [(e["kind"], e["undo"]) for e in seen] == [
        ("mac", {"interface": "en0", "mac": ORIGINAL})
    ]
    assert journal.pending() == seen


def test_rotate_with_journal_still_remembers_original_in_state():
    backend = FakeBackend(mac=ORIGINAL)
    rotate(backend, journal=journal)
    assert state.original_mac("en0") == ORIGINAL


def test_rotate_with_bad_mac_journals_nothing():
    backend = FakeBackend(mac=ORIGINAL)
    with pytest.raises(ValueError):
        rotate(backend, new_mac="not-a-mac", journal=journal)
    assert journal.pending() == []
    assert backend.set_calls == []


def test_rotate_without_journal_writes_no_journal():
    backend = FakeBackend(mac=ORIGINAL)
    rotate(backend)
    assert backend.mac != ORIGINAL
    assert state.original_mac("en0") == ORIGINAL
    assert not journal.journal_path().exists()
    assert journal.pending() == []


def test_rollback_restores_mac_and_clears_journal():
    backend = FakeBackend(mac=ORIGINAL)
    rotate(backend, journal=journal)
    assert journal.rollback(factory_for(backend)) == []
    assert backend.mac == ORIGINAL
    assert journal.pending() == []
    assert not journal.journal_path().exists()


def test_rollback_undoes_newest_first():
    backend = FakeBackend(mac=ORIGINAL)
    first = rotate(backend, journal=journal)
    rotate(backend, journal=journal)
    backend.set_calls.clear()
    journal.rollback(factory_for(backend))
    assert backend.set_calls == [first, ORIGINAL]
    assert backend.mac == ORIGINAL


def test_rollback_with_empty_journal_is_a_no_op():
    assert journal.rollback(factory_for()) == []


def test_rollback_stops_and_reraises_at_first_failure(restore_registry):
    backend = FakeBackend(mac=ORIGINAL)
    rotate(backend, journal=journal)
    boom = RuntimeError("boom")

    def fail(undo, backend_factory):
        raise boom

    journal.register_undo("broken", fail)
    journal.record("broken", {})
    with pytest.raises(RuntimeError) as excinfo:
        journal.rollback(factory_for(backend))
    assert excinfo.value is boom
    # The older MAC entry was not reached, and nothing was marked undone.
    assert backend.mac != ORIGINAL
    assert [e["kind"] for e in journal.pending()] == ["broken", "mac"]


def test_rollback_keep_going_collects_failures(restore_registry):
    backend = FakeBackend(mac=ORIGINAL)
    rotate(backend, journal=journal)
    boom = RuntimeError("boom")

    def fail(undo, backend_factory):
        raise boom

    journal.register_undo("broken", fail)
    broken_id = journal.record("broken", {"x": 1})
    unknown_id = journal.record("never-registered", {})

    failures = journal.rollback(factory_for(backend), keep_going=True)

    assert backend.mac == ORIGINAL  # the entry after the failures still ran
    assert [entry["id"] for entry, _ in failures] == [unknown_id, broken_id]
    assert isinstance(failures[0][1], journal.JournalError)
    assert failures[1][1] is boom
    # Failed entries stay pending for the next attempt; the file is kept.
    assert [e["id"] for e in journal.pending()] == [unknown_id, broken_id]
    assert journal.journal_path().exists()


def test_failed_entries_are_retried_on_the_next_rollback(restore_registry):
    calls = []
    state_ = {"fail": True}

    def flaky(undo, backend_factory):
        calls.append(undo)
        if state_["fail"]:
            raise RuntimeError("not yet")

    journal.register_undo("flaky", flaky)
    journal.record("flaky", {"n": 1})
    assert len(journal.rollback(factory_for(), keep_going=True)) == 1
    state_["fail"] = False
    assert journal.rollback(factory_for(), keep_going=True) == []
    assert calls == [{"n": 1}, {"n": 1}]
    assert not journal.journal_path().exists()


def test_register_undo_refuses_to_replace_a_kind(restore_registry):
    with pytest.raises(ValueError):
        journal.register_undo("mac", lambda undo, backend_factory: None)
    journal.register_undo("mac", journal._UNDO["mac"])  # same function: fine


def test_undo_entry_does_not_mark_undone():
    backend = FakeBackend(mac=ORIGINAL)
    rotate(backend, journal=journal)
    (entry,) = journal.pending()
    journal.undo_entry(entry, factory_for(backend))
    assert backend.mac == ORIGINAL
    assert journal.pending() == [entry]
