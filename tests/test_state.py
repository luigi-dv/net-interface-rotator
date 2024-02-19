import json
import os
import stat
from types import SimpleNamespace

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


def test_non_object_json_is_treated_as_empty(state_file):
    state_file.write_text("[1, 2]")
    assert state.original_mac("en0") is None


# ------------------------------------------------- links planted in the home

MAC = "aa:bb:cc:dd:ee:ff"


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A made-up home directory; state.json goes in its real default place."""
    home = tmp_path / "home"
    home.mkdir()
    for var in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(state.Path, "home", classmethod(lambda cls: home))
    return home


def state_json(home):
    return home / ".config" / "net-interface-rotator" / "state.json"


def test_creates_private_directories_and_file(home):
    state.remember_original("en0", MAC)
    path = state_json(home)
    assert json.loads(path.read_text()) == {"en0": MAC}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert state.original_mac("en0") == MAC


def test_existing_wider_file_and_directory_are_tightened(home):
    path = state_json(home)
    path.parent.mkdir(parents=True)
    path.write_text("{}")
    path.chmod(0o644)
    path.parent.chmod(0o755)
    state.remember_original("en0", MAC)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_refuses_symlinked_dot_config(home, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (home / ".config").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(OSError, match="symbolic link"):
        state.remember_original("en0", MAC)
    assert list(elsewhere.iterdir()) == []


def test_refuses_symlinked_app_directory(home, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (home / ".config").mkdir()
    (home / ".config" / "net-interface-rotator").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(OSError, match="symbolic link"):
        state.remember_original("en0", MAC)
    assert list(elsewhere.iterdir()) == []
    with pytest.raises(OSError, match="symbolic link"):
        state.original_mac("en0")


def test_refuses_symlinked_state_file(home, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    victim.chmod(0o644)
    path = state_json(home)
    path.parent.mkdir(parents=True)
    path.symlink_to(victim)
    with pytest.raises(OSError, match="symbolic link"):
        state.remember_original("en0", MAC)
    assert victim.read_text() == "keep me"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    with pytest.raises(OSError, match="symbolic link"):
        state.original_mac("en0")


def test_refuses_dangling_symlink_as_state_file(home, tmp_path):
    target = tmp_path / "not-there-yet"
    path = state_json(home)
    path.parent.mkdir(parents=True)
    path.symlink_to(target)
    with pytest.raises(OSError, match="symbolic link"):
        state.remember_original("en0", MAC)
    assert not target.exists()


def test_refuses_hard_linked_state_file(home, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    path = state_json(home)
    path.parent.mkdir(parents=True)
    os.link(victim, path)
    with pytest.raises(OSError, match="hard link"):
        state.remember_original("en0", MAC)
    assert victim.read_text() == "keep me"


def test_refuses_file_where_directory_is_expected(home):
    (home / ".config").write_text("not a directory")
    with pytest.raises(OSError, match="not a directory"):
        state.remember_original("en0", MAC)


# ------------------------------------------------------------------ under sudo

@pytest.fixture
def sudo(home, monkeypatch):
    """Pretend to run under sudo; records ownership changes instead of making them."""
    entry = SimpleNamespace(pw_dir=str(home), pw_uid=501, pw_gid=20)
    users = {"alice": entry}
    uids = {501: entry}
    chowns = []

    def getpwnam(name):
        return users[name]

    def getpwuid(uid):
        return uids[uid]

    monkeypatch.setattr(state.pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(state.pwd, "getpwuid", getpwuid)
    monkeypatch.setattr(state.os, "fchown",
                        lambda fd, uid, gid: chowns.append((stat.S_ISDIR(os.fstat(fd).st_mode), uid, gid)))
    monkeypatch.setattr(state.os, "chown", lambda *a, **k: pytest.fail("chown follows links"))
    return chowns


def test_sudo_user_gets_ownership_through_descriptors(sudo, home, monkeypatch):
    monkeypatch.setenv("SUDO_USER", "alice")
    state.remember_original("en0", MAC)
    assert state_json(home).exists()
    # .config, the tool's directory (twice: created, then tightened), the file.
    assert sudo == [(True, 501, 20), (True, 501, 20), (True, 501, 20), (False, 501, 20)]


def test_bogus_sudo_user_falls_back_to_sudo_uid(sudo, home, monkeypatch):
    monkeypatch.setenv("SUDO_USER", "no-such-user")
    monkeypatch.setenv("SUDO_UID", "501")
    state.remember_original("en0", MAC)
    assert json.loads(state_json(home).read_text()) == {"en0": MAC}
    assert sudo[-1] == (False, 501, 20)


@pytest.mark.parametrize("uid", [None, "999", "not-a-number", "-1"])
def test_bogus_sudo_user_and_uid_is_refused(sudo, home, monkeypatch, uid):
    monkeypatch.setenv("SUDO_USER", "no-such-user")
    if uid is not None:
        monkeypatch.setenv("SUDO_UID", uid)
    with pytest.raises(OSError, match="which user ran sudo"):
        state.remember_original("en0", MAC)
    assert not (home / ".config").exists()
