import os
import stat
import subprocess
from types import SimpleNamespace

import pytest

from rotator import tunnel
from rotator.backends.base import BackendError

KEY = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="
PEER_KEY = "MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVY="

GOOD = f"""\
[Interface]
PrivateKey = {KEY}
Address = 198.51.100.7/32, 2001:db8:1::7/128
DNS = 198.51.100.1, 2001:db8:1::1

[Peer]
PublicKey = {PEER_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.10:51820
PersistentKeepalive = 25
"""

UID = 501
OK_STAT = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=UID)


def check(text=GOOD, st=OK_STAT, local=()):
    return tunnel.validate(text, st, local, owner_uid=UID)


# ------------------------------------------------------------ parse_config

def test_parse_config_reads_needed_fields():
    cfg = tunnel.parse_config(GOOD)
    assert cfg == tunnel.TunnelConfig(
        endpoint_ip="192.0.2.10",
        endpoint_port=51820,
        dns=["198.51.100.1", "2001:db8:1::1"],
        allowed_ips=["0.0.0.0/0", "::/0"],
        has_keepalive=True,
    )
    assert KEY not in repr(cfg)


def test_parse_config_ipv6_endpoint_comments_and_case():
    text = GOOD.replace("Endpoint = 192.0.2.10:51820", "endpoint=[2001:db8::10]:443  # alt port")
    text = text.replace("PersistentKeepalive = 25\n", "")
    cfg = tunnel.parse_config(text)
    assert (cfg.endpoint_ip, cfg.endpoint_port) == ("2001:db8::10", 443)
    assert cfg.has_keepalive is False


def test_parse_config_ignores_dns_search_domains():
    cfg = tunnel.parse_config(GOOD.replace("DNS = 198.51.100.1,", "DNS = example.invalid, 198.51.100.1,"))
    assert cfg.dns == ["198.51.100.1", "2001:db8:1::1"]


@pytest.mark.parametrize("endpoint", [
    "vpn.example.invalid:51820", "192.0.2.10", "2001:db8::10:51820",
    "[192.0.2.10]:51820", "192.0.2.10:0", "192.0.2.10:70000", "192.0.2.999:51820",
])
def test_parse_config_rejects_non_literal_endpoint(endpoint):
    with pytest.raises(tunnel.ConfigError) as err:
        tunnel.parse_config(GOOD.replace("192.0.2.10:51820", endpoint))
    assert KEY not in str(err.value)


def test_parse_config_requires_exactly_one_peer():
    with pytest.raises(tunnel.ConfigError):
        tunnel.parse_config(GOOD.split("[Peer]")[0])
    with pytest.raises(tunnel.ConfigError):
        tunnel.parse_config(GOOD + "\n[Peer]\nEndpoint = 192.0.2.11:51820\n")


# ---------------------------------------------------------------- validate

def test_validate_accepts_good_config():
    assert check() == []
    assert check(st=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)) == []
    assert check(local=["192.0.2.0/24", "2001:db8:ffff::/64"]) == []


def test_validate_accepts_split_default_routes():
    text = GOOD.replace("0.0.0.0/0, ::/0", "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1")
    assert check(text) == []


def only(problems, word):
    assert len(problems) == 1, problems
    assert word in problems[0]


@pytest.mark.parametrize("allowed, word", [
    ("0.0.0.0/0", "::/0"),
    ("::/0", "0.0.0.0/0"),
    ("0.0.0.0/1, ::/0", "0.0.0.0/0"),
])
def test_validate_allowed_ips_must_cover_everything(allowed, word):
    only(check(GOOD.replace("0.0.0.0/0, ::/0", allowed)), word)


def test_validate_dns_missing():
    only(check(GOOD.replace("DNS = 198.51.100.1, 2001:db8:1::1\n", "")), "DNS")
    only(check(GOOD.replace("DNS = 198.51.100.1, 2001:db8:1::1", "DNS = example.invalid")), "DNS")


def test_validate_dns_on_local_network():
    only(check(local=["198.51.100.0/24"]), "198.51.100.1")
    only(check(local=["2001:db8:1::/64"]), "2001:db8:1::1")


def test_validate_endpoint_ipv6_rejected():
    only(check(GOOD.replace("192.0.2.10:51820", "[2001:db8::10]:51820")), "IPv4 endpoint")


def test_validate_keepalive_required():
    only(check(GOOD.replace("PersistentKeepalive = 25\n", "")), "PersistentKeepalive")
    only(check(GOOD.replace("PersistentKeepalive = 25", "PersistentKeepalive = 0")), "PersistentKeepalive")
    only(check(GOOD.replace("PersistentKeepalive = 25", "PersistentKeepalive = off")), "PersistentKeepalive")


@pytest.mark.parametrize("line, word", [
    ("PreUp = /bin/echo marker-text", "PreUp"),
    ("PostUp = /bin/echo marker-text", "PostUp"),
    ("PreDown = /bin/echo marker-text", "PreDown"),
    ("postdown=/bin/echo marker-text", "PostDown"),
    ("SaveConfig = true", "SaveConfig"),
    ("SaveConfig = TRUE", "SaveConfig"),
    ("Table = off", "Table"),
    ("Table = 1234", "Table"),
])
def test_validate_rejects_dangerous_interface_keys(line, word):
    problems = check(GOOD.replace("[Interface]\n", f"[Interface]\n{line}\n"))
    only(problems, word)
    assert "marker-text" not in problems[0]


def test_validate_reports_each_dangerous_key_separately():
    extra = "PreUp = a\nPostUp = b\nPreDown = c\nPostDown = d\nSaveConfig = true\nTable = off\n"
    assert len(check(GOOD.replace("[Interface]\n", "[Interface]\n" + extra))) == 6


@pytest.mark.parametrize("line", ["Table = auto", "Table = Auto", "SaveConfig = false"])
def test_validate_allows_harmless_interface_keys(line):
    assert check(GOOD.replace("[Interface]\n", f"[Interface]\n{line}\n")) == []


def test_validate_endpoint_hostname():
    only(check(GOOD.replace("192.0.2.10:51820", "vpn.example.invalid:51820")), "Endpoint")
    only(check(GOOD.replace("Endpoint = 192.0.2.10:51820\n", "")), "Endpoint must be an IP literal")


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o700 | 0o020])
def test_validate_mode(mode):
    only(check(st=SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=UID)), "mode")


def test_validate_owner():
    only(check(st=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=UID + 1)), "owned")


def test_validate_owner_defaults_to_sudo_uid(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "777")
    st = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=777)
    assert tunnel.validate(GOOD, st) == []
    monkeypatch.setenv("SUDO_UID", "778")
    monkeypatch.setattr(os, "getuid", lambda: 0)
    only(tunnel.validate(GOOD, st), "owned")


def test_validate_never_reveals_private_key():
    bad_stat = SimpleNamespace(st_mode=stat.S_IFREG | 0o666, st_uid=UID + 1)
    broken = [
        GOOD.replace("0.0.0.0/0, ::/0", "10.0.0.0/8, bogus"),
        GOOD.replace("192.0.2.10:51820", "vpn.example.invalid:51820").replace("DNS", "XDNS"),
        GOOD.replace("PrivateKey = ", "PrivateKey "),          # malformed key line
        GOOD.replace("[Interface]\n", ""),                    # key outside any section
        GOOD.replace("[Interface]", "[Bogus]"),
        GOOD + f"\n[Peer]\nPresharedKey = {KEY}\n{KEY}\n",
    ]
    for text in broken:
        problems = tunnel.validate(text, bad_stat, ["198.51.100.0/24"], owner_uid=UID)
        assert problems
        assert KEY not in "\n".join(problems)


def test_validate_file(tmp_path, monkeypatch):
    path = tmp_path / "nir.conf"
    path.write_text(GOOD)
    path.chmod(0o600)
    monkeypatch.delenv("SUDO_UID", raising=False)
    assert tunnel.validate_file(path) == []
    path.chmod(0o644)
    only(tunnel.validate_file(path), "mode")
    only(tunnel.validate_file(tmp_path / "missing.conf"), "Cannot open")
    link = tmp_path / "link.conf"
    link.symlink_to(path)
    only(tunnel.validate_file(link), "Cannot open")


# ------------------------------------------------------------- handshakes

def test_parse_latest_handshakes():
    now = 1_800_000_000
    assert tunnel.parse_latest_handshakes(f"{PEER_KEY}\t{now - 42}\n", now) == 42.0
    assert tunnel.parse_latest_handshakes(f"{PEER_KEY}\t0\n", now) is None
    assert tunnel.parse_latest_handshakes("", now) is None
    assert tunnel.parse_latest_handshakes("garbage\n", now) is None
    two = f"{PEER_KEY}\t{now - 300}\n{KEY}\t{now - 5}\n"
    assert tunnel.parse_latest_handshakes(two, now) == 5.0
    assert tunnel.parse_latest_handshakes(f"{PEER_KEY}\t{now + 3}\n", now) == 0.0


def test_handshake_age_and_is_up(monkeypatch):
    calls = []

    def fake_run(*args, check=True):
        calls.append(args)
        return f"{PEER_KEY}\t1000\n"

    monkeypatch.setattr(tunnel, "run", fake_run)
    monkeypatch.setattr(tunnel.time, "time", lambda: 1100.0)
    assert tunnel.handshake_age("utun5") == 100.0
    assert calls == [("wg", "show", "utun5", "latest-handshakes")]
    assert tunnel.is_up("utun5") is True
    assert tunnel.is_up("utun5", max_age=100) is False


def test_handshake_age_missing_interface(monkeypatch):
    def fake_run(*args, check=True):
        raise BackendError("no such device")

    monkeypatch.setattr(tunnel, "run", fake_run)
    assert tunnel.handshake_age("utun5") is None
    assert tunnel.is_up("utun5") is False


# ---------------------------------------------------------------- up / down

def test_up_linux_returns_file_stem(monkeypatch):
    calls = []
    monkeypatch.setattr(tunnel, "run", lambda *a, check=True: calls.append(a) or "")
    monkeypatch.setattr(tunnel.sys, "platform", "linux")
    assert tunnel.up("/etc/wireguard/nir.conf") == "nir"
    tunnel.down("/etc/wireguard/nir.conf")
    assert calls == [("wg-quick", "up", "/etc/wireguard/nir.conf"),
                     ("wg-quick", "down", "/etc/wireguard/nir.conf")]


def test_up_macos_reads_real_interface_name(monkeypatch, tmp_path):
    (tmp_path / "nir.name").write_text("utun5\n")
    monkeypatch.setattr(tunnel, "run", lambda *a, check=True: "")
    monkeypatch.setattr(tunnel.sys, "platform", "darwin")
    monkeypatch.setattr(tunnel, "_NAME_DIR", tmp_path)
    assert tunnel.up("/opt/homebrew/etc/wireguard/nir.conf") == "utun5"
    with pytest.raises(BackendError):
        tunnel.up("/opt/homebrew/etc/wireguard/other.conf")


@pytest.mark.parametrize("path", ["/etc/wireguard/nir", "/etc/wireguard/a b.conf",
                                  "/etc/wireguard/much-too-long-a-name.conf"])
def test_up_rejects_bad_config_name(monkeypatch, path):
    monkeypatch.setattr(tunnel, "run", lambda *a, check=True: pytest.fail("must not run"))
    with pytest.raises(BackendError):
        tunnel.up(path)


def test_wg_quick_failure_is_scrubbed(monkeypatch, tmp_path):
    odd_secret = "not-base64-secret"
    path = tmp_path / "nir.conf"
    path.write_text(GOOD + f"PresharedKey = {odd_secret}\n")

    def fake_subprocess_run(args, **kwargs):
        raise subprocess.CalledProcessError(
            1, args, stderr=f"Key is not the correct length or format: `{KEY}' / {odd_secret}")

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    with pytest.raises(BackendError) as err:
        tunnel.up(path)
    assert KEY not in str(err.value)
    assert odd_secret not in str(err.value)
    assert "[redacted]" in str(err.value)
    assert err.value.__cause__ is None and err.value.__suppress_context__


# ------------------------------------------------------------ up_with_fallback

class FakeWg:
    """Stands in for up/down/is_up; ``working`` lists configs that handshake."""

    def __init__(self, monkeypatch, working=(), broken_up=(), broken_down=()):
        self.log, self.active, self.now = [], None, 0.0
        self.working, self.broken_up, self.broken_down = working, broken_up, broken_down
        monkeypatch.setattr(tunnel, "up", self.up)
        monkeypatch.setattr(tunnel, "down", self.down)
        monkeypatch.setattr(tunnel, "is_up", lambda tunnel_if, max_age=180: self.active in self.working)
        monkeypatch.setattr(tunnel.time, "monotonic", lambda: self.now)
        monkeypatch.setattr(tunnel.time, "sleep", self.sleep)

    def sleep(self, seconds):
        self.now += seconds

    def up(self, path):
        self.log.append(("up", path))
        if path in self.broken_up:
            raise BackendError("wg-quick failed")
        self.active = path
        return "utun5"

    def down(self, path):
        self.log.append(("down", path))
        if path in self.broken_down:
            raise BackendError("cannot stop")
        self.active = None


def test_fallback_not_needed(monkeypatch):
    wg = FakeWg(monkeypatch, working=("a.conf",))
    assert tunnel.up_with_fallback("a.conf", "b.conf") == ("a.conf", "utun5")
    assert wg.log == [("up", "a.conf")]


def test_fallback_used_after_timeout(monkeypatch):
    wg = FakeWg(monkeypatch, working=("b.conf",))
    assert tunnel.up_with_fallback("a.conf", "b.conf", timeout=15) == ("b.conf", "utun5")
    assert wg.log == [("up", "a.conf"), ("down", "a.conf"), ("up", "b.conf")]
    assert 15 <= wg.now < 16


def test_fallback_used_when_primary_fails_to_start(monkeypatch):
    wg = FakeWg(monkeypatch, working=("b.conf",), broken_up=("a.conf",))
    assert tunnel.up_with_fallback("a.conf", "b.conf") == ("b.conf", "utun5")
    assert wg.log == [("up", "a.conf"), ("down", "a.conf"), ("up", "b.conf")]


def test_both_fail_leaves_nothing_up(monkeypatch):
    wg = FakeWg(monkeypatch)
    with pytest.raises(BackendError, match="may block UDP"):
        tunnel.up_with_fallback("a.conf", "b.conf", timeout=2)
    assert wg.log == [("up", "a.conf"), ("down", "a.conf"), ("up", "b.conf"), ("down", "b.conf")]
    assert wg.active is None


def test_no_fallback_configured(monkeypatch):
    wg = FakeWg(monkeypatch)
    with pytest.raises(BackendError, match="may block UDP"):
        tunnel.up_with_fallback("a.conf", None, timeout=1)
    assert wg.log == [("up", "a.conf"), ("down", "a.conf")]


def test_fallback_not_tried_if_primary_cannot_be_stopped(monkeypatch):
    wg = FakeWg(monkeypatch, working=("b.conf",), broken_down=("a.conf",))
    with pytest.raises(BackendError, match="could not be stopped"):
        tunnel.up_with_fallback("a.conf", "b.conf", timeout=1)
    assert ("up", "b.conf") not in wg.log
