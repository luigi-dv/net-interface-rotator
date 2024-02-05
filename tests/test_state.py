import json

import pytest

from rotator import state


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    monkeypatch.setattr(state, "_state_path", lambda: path)
    for var in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
        monkeypatch.delenv(var, raising=False)
    return path


def test_original_mac_is_none_without_file(state_file):
    assert not state_file.exists()
    assert state.original_mac("en0") is None


def test_first_remember_original_is_stored(state_file):
    state.remember_original("en0", "aa:bb:cc:dd:ee:ff")
    assert state.original_mac("en0") == "aa:bb:cc:dd:ee:ff"


def test_second_remember_original_does_not_overwrite(state_file):
    state.remember_original("en0", "aa:bb:cc:dd:ee:ff")
    state.remember_original("en0", "11:22:33:44:55:66")
    assert state.original_mac("en0") == "aa:bb:cc:dd:ee:ff"
    assert json.loads(state_file.read_text()) == {"en0": "aa:bb:cc:dd:ee:ff"}


def test_corrupt_json_is_treated_as_empty(state_file):
    state_file.write_text("{not valid json")
    assert state.original_mac("en0") is None
    state.remember_original("en0", "aa:bb:cc:dd:ee:ff")
    assert state.original_mac("en0") == "aa:bb:cc:dd:ee:ff"
