"""`.env` loading: only the tool's own settings reach the environment."""
import pytest

from rotator import cli

DOTENV = """\
NETWORK_INTERFACE=en7
ROTATE_INTERVAL=600
POLL_SECONDS=5
WG_CONFIG=/etc/wireguard/nir.conf
WG_CONFIG_FALLBACK=/etc/wireguard/alt.conf
STRICT=0
STRICT_ON=arp_conflict
WG_QUICK_USERSPACE_IMPLEMENTATION=/tmp/evil
PATH=/tmp/evil
LD_PRELOAD=/tmp/evil.so
PYTHONPATH=/tmp/evil
"""


@pytest.fixture
def dotenv(tmp_path):
    path = tmp_path / ".env"
    path.write_text(DOTENV)
    return path


def test_only_known_keys_are_loaded(dotenv):
    environ = {"PATH": "/usr/bin"}
    cli.load_env(dotenv, environ)
    assert environ == {
        "PATH": "/usr/bin",
        "NETWORK_INTERFACE": "en7", "ROTATE_INTERVAL": "600", "POLL_SECONDS": "5",
        "WG_CONFIG": "/etc/wireguard/nir.conf", "WG_CONFIG_FALLBACK": "/etc/wireguard/alt.conf",
        "STRICT": "0", "STRICT_ON": "arp_conflict",
    }


def test_wg_quick_variable_and_path_are_ignored_in_the_real_environment(dotenv, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.delenv("WG_QUICK_USERSPACE_IMPLEMENTATION", raising=False)
    monkeypatch.delenv("LD_PRELOAD", raising=False)
    for key in cli.ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(cli.os, "environ", dict(cli.os.environ))  # keep the real one clean
    cli.load_env(dotenv)
    assert cli.os.environ["PATH"] == "/usr/bin:/bin"
    assert "WG_QUICK_USERSPACE_IMPLEMENTATION" not in cli.os.environ
    assert "LD_PRELOAD" not in cli.os.environ
    assert cli.os.environ["WG_CONFIG"] == "/etc/wireguard/nir.conf"


def test_already_set_variables_win(dotenv):
    environ = {"WG_CONFIG": "/etc/wireguard/mine.conf", "STRICT": ""}
    cli.load_env(dotenv, environ)
    assert environ["WG_CONFIG"] == "/etc/wireguard/mine.conf"
    assert environ["STRICT"] == ""
    assert environ["STRICT_ON"] == "arp_conflict"


def test_missing_file_and_valueless_keys_load_nothing(tmp_path):
    environ = {}
    cli.load_env(tmp_path / "no-such.env", environ)
    assert environ == {}
    path = tmp_path / ".env"
    path.write_text("WG_CONFIG\nSTRICT=\n")
    cli.load_env(path, environ)
    assert environ == {"STRICT": ""}


def test_main_loads_env_through_the_allowlist(monkeypatch):
    monkeypatch.setattr(cli, "load_env", lambda: (_ for _ in ()).throw(SystemExit("loaded")))
    assert not hasattr(cli, "load_dotenv")
    with pytest.raises(SystemExit, match="loaded"):
        cli.main(["status"])
