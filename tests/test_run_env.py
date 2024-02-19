"""`run` gives every command a fixed environment; nothing is really executed."""
import subprocess

import pytest

from rotator.backends import base, macos
from rotator.backends.base import BackendError, run
from rotator.backends.macos import MacOSBackend

SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
WIREGUARD_PATH = SYSTEM_PATH + ":/opt/homebrew/bin:/usr/local/bin"


@pytest.fixture
def calls(monkeypatch):
    """Replaces subprocess.run; records (argv, keyword arguments)."""
    recorded = []

    def fake_run(args, **kwargs):
        recorded.append((tuple(args), kwargs))
        return subprocess.CompletedProcess(args, 0, "out\n", "")

    monkeypatch.setattr(base.subprocess, "run", fake_run)
    monkeypatch.setattr(base.sys, "platform", "linux")
    for name in list(base.os.environ):
        monkeypatch.delenv(name)
    return recorded


def test_run_uses_fixed_path_and_c_locale(calls, monkeypatch):
    monkeypatch.setenv("PATH", "/tmp/evil:/usr/bin")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_MESSAGES", "fr_FR.UTF-8")
    assert run("ifconfig", "en0") == "out\n"
    (argv, kwargs), = calls
    assert argv == ("ifconfig", "en0")
    assert kwargs["env"] == {"PATH": SYSTEM_PATH, "LC_ALL": "C", "LANG": "C"}
    assert not kwargs.get("shell")


def test_run_drops_everything_but_home_and_sudo_variables(calls, monkeypatch):
    monkeypatch.setenv("HOME", "/var/root")
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    monkeypatch.setenv("WG_QUICK_USERSPACE_IMPLEMENTATION", "/tmp/evil")
    monkeypatch.setenv("WG_ENDPOINT_RESOLUTION_RETRIES", "1")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
    monkeypatch.setenv("BASH_ENV", "/tmp/evil.sh")
    monkeypatch.setenv("IFS", "x")
    run("wg-quick", "up", "/etc/wireguard/nir.conf")
    assert calls[0][1]["env"] == {
        "PATH": WIREGUARD_PATH, "LC_ALL": "C", "LANG": "C",
        "HOME": "/var/root", "SUDO_USER": "alice", "SUDO_UID": "501", "SUDO_GID": "20",
    }


@pytest.mark.parametrize("command, path", [
    ("wg", WIREGUARD_PATH), ("wg-quick", WIREGUARD_PATH), ("bash", WIREGUARD_PATH),
    ("ifconfig", SYSTEM_PATH), ("route", SYSTEM_PATH), ("ip", SYSTEM_PATH),
    ("/usr/libexec/ApplicationFirewall/socketfilterfw", SYSTEM_PATH),
    ("/tmp/evil/wg", SYSTEM_PATH),
])
def test_wireguard_directories_only_for_wireguard_commands(calls, command, path):
    run(command)
    assert calls[0][1]["env"]["PATH"] == path


def test_command_env_ignores_the_given_environment_except_kept_names():
    env = base.command_env("wg", {"PATH": "/tmp/evil", "HOME": "/h", "WG_X": "1", "SUDO_UID": "7"})
    assert env == {"PATH": WIREGUARD_PATH, "LC_ALL": "C", "LANG": "C", "HOME": "/h", "SUDO_UID": "7"}


def test_run_passes_input_text(calls):
    run("nft", "-f", "-", input="flush ruleset\n")
    run("nft", "list", "ruleset")
    assert calls[0][1]["input"] == "flush ruleset\n"
    assert calls[0][1]["text"] is True
    assert calls[1][1]["input"] is None


def test_run_check_flag_and_errors(calls, monkeypatch):
    run("arp", "-an", check=False)
    assert calls[0][1]["check"] is False

    def missing(args, **kwargs):
        raise FileNotFoundError(args[0])

    monkeypatch.setattr(base.subprocess, "run", missing)
    with pytest.raises(BackendError, match="Command not found: wg"):
        run("wg", "show")

    def failing(args, **kwargs):
        raise subprocess.CalledProcessError(1, args, stderr="boom\n")

    monkeypatch.setattr(base.subprocess, "run", failing)
    with pytest.raises(BackendError, match="`wg show` failed: boom"):
        run("wg", "show")


def test_macos_wg_quick_runs_under_wireguard_directory_bash(calls, monkeypatch):
    found = {"wg-quick": "/opt/homebrew/bin/wg-quick", "bash": "/opt/homebrew/bin/bash"}
    searched = {}

    def which(name, path=None):
        searched[name] = path
        return found.get(name)

    monkeypatch.setattr(base.sys, "platform", "darwin")
    monkeypatch.setattr(base.shutil, "which", which)
    run("wg-quick", "up", "/x/nir.conf")
    run("wg", "show", "interfaces")
    assert calls[0][0] == ("/opt/homebrew/bin/bash", "/opt/homebrew/bin/wg-quick", "up", "/x/nir.conf")
    assert calls[0][1]["env"]["PATH"] == WIREGUARD_PATH
    assert calls[1][0] == ("wg", "show", "interfaces")
    # Neither lookup uses the caller's PATH; bash never comes from a system directory.
    assert searched == {"wg-quick": WIREGUARD_PATH, "bash": "/opt/homebrew/bin:/usr/local/bin"}


def test_macos_wg_quick_unchanged_without_a_newer_bash(calls, monkeypatch):
    monkeypatch.setattr(base.sys, "platform", "darwin")
    monkeypatch.setattr(base.shutil, "which", lambda name, path=None: None)
    run("wg-quick", "down", "/x/nir.conf")
    assert calls[0][0] == ("wg-quick", "down", "/x/nir.conf")


# ------------------------------------------------------- macOS set_mac failure

def test_macos_set_mac_failure_does_not_print_the_current_address(monkeypatch):
    original = "f0:18:98:12:34:56"

    def fake_run(*args, check=True):
        if args == ("ifconfig", "en0"):
            return f"en0: flags=8863<UP>\n\tether {original}\n"
        return ""

    monkeypatch.setattr(macos, "run", fake_run)
    monkeypatch.setattr(macos.time, "sleep", lambda seconds: None)
    with pytest.raises(BackendError) as err:
        MacOSBackend("en0").set_mac("02:aa:bb:cc:dd:ee")
    message = str(err.value)
    assert "did not accept the new address" in message
    assert original not in message
    assert "f0:18" not in message
