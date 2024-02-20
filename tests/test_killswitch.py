import re
import subprocess

import pytest

from rotator import killswitch
from rotator.backends.base import BackendError
from rotator.killswitch import linux_nft, macos_pf

ENDPOINTS = [("192.0.2.10", 51820), ("198.51.100.20", 443)]
PORTAL_PORT = re.compile(r"port (53|80|443)\b")


def pf(tunnel_if="utun5", portal=False, endpoints=ENDPOINTS, **kwargs):
    return macos_pf.build_rules("en0", tunnel_if, endpoints, portal, **kwargs)


def nft(tunnel_if="wg0", portal=False, endpoints=ENDPOINTS, **kwargs):
    return linux_nft.build_rules("eth0", tunnel_if, endpoints, portal, **kwargs)


def chain(rules, name):
    body = rules.split(f"chain {name} {{")[1].split("}")[0]
    return [line.strip() for line in body.strip().splitlines()]


# ------------------------------------------------------------------ macOS pf

def test_pf_strict_ruleset_exact():
    assert pf().splitlines() == [
        "pass quick on lo0 all no state",
        "pass quick on utun5 all no state",
        "pass out quick on en0 inet proto udp from any port 68 to any port 67 keep state",
        "pass out quick on en0 inet proto udp from any to 192.0.2.10 port 51820 keep state",
        "pass out quick on en0 inet proto udp from any to 198.51.100.20 port 443 keep state",
        "block drop quick all",
    ]
    assert pf().endswith("\n")
    assert pf() == pf()


def test_pf_every_rule_is_quick_and_block_everything_comes_last():
    for rules in (pf(), pf(portal=True), pf(tunnel_if=None), pf(silent=True),
                  pf(silent=True, allow_dhcp=False)):
        lines = rules.splitlines()
        assert all(" quick " in line for line in lines)
        # No interface and no address family: every interface, IPv4 and IPv6.
        assert lines[-1] == "block drop quick all"
        assert not any(line.startswith("block") for line in lines[:-1])


def test_pf_passes_name_only_loopback_tunnel_and_iface():
    for portal in (False, True):
        for line in pf(portal=portal).splitlines()[:-1]:
            words = line.split()
            assert words[0] == "pass"
            iface = words[words.index("on") + 1]
            assert iface in ("lo0", "utun5", "en0")
            if iface == "en0":
                assert line.startswith("pass out quick on en0 inet proto ")


def test_pf_lockdown_passes_only_loopback():
    assert pf(silent=True, allow_dhcp=False).splitlines() == [
        "pass quick on lo0 all no state",
        "block drop quick all",
    ]
    # silent ignores the tunnel, the endpoints and the portal flag.
    assert pf(portal=True, silent=True, allow_dhcp=False) == pf(None, False, [], silent=True, allow_dhcp=False)


def test_pf_silent_passes_loopback_and_dhcp():
    assert pf(silent=True).splitlines() == [
        "pass quick on lo0 all no state",
        "pass out quick on en0 inet proto udp from any port 68 to any port 67 keep state",
        "block drop quick all",
    ]


def test_pf_allow_dhcp_false_only_removes_the_dhcp_rule():
    dhcp = "pass out quick on en0 inet proto udp from any port 68 to any port 67 keep state"
    assert [l for l in pf().splitlines() if l != dhcp] == pf(allow_dhcp=False).splitlines()


def test_pf_never_passes_inbound_on_iface():
    for portal in (False, True):
        for line in pf(portal=portal).splitlines():
            if line.startswith("pass") and " on en0 " in line:
                assert line.startswith("pass out quick on en0 ")


def test_pf_strict_has_no_portal_ports():
    for line in pf(endpoints=[("192.0.2.10", 51820)]).splitlines():
        if " on en0 " in line and line.startswith("pass"):
            assert not PORTAL_PORT.search(line)


def test_pf_ipv6_blocked_everywhere_but_loopback_and_tunnel():
    rules = pf(portal=True)
    assert "inet6" not in rules  # no IPv6 pass; the final block has no family
    for line in rules.splitlines():
        if line.startswith("pass") and " on en0 " in line:
            assert " inet proto " in line
    assert "port 546" not in rules and "port 547" not in rules


def test_pf_portal_adds_web_and_dns_only():
    extra = [l for l in pf(portal=True).splitlines() if l not in pf().splitlines()]
    assert extra == [
        "pass out quick on en0 inet proto tcp from any to any port 80 flags S/SA keep state",
        "pass out quick on en0 inet proto tcp from any to any port 443 flags S/SA keep state",
        "pass out quick on en0 inet proto udp from any to any port 53 keep state",
        "pass out quick on en0 inet proto tcp from any to any port 53 flags S/SA keep state",
    ]


def test_pf_without_tunnel_has_no_tunnel_rule():
    rules = pf(tunnel_if=None)
    assert "utun" not in rules
    passes_all = [l for l in rules.splitlines() if l.startswith("pass quick on")]
    assert passes_all == ["pass quick on lo0 all no state"]
    assert set(pf().splitlines()) - set(rules.splitlines()) == {"pass quick on utun5 all no state"}


def test_pf_both_endpoints_present_and_deduplicated():
    rules = pf(endpoints=[("192.0.2.10", 51820), ("192.0.2.20", 443), ("192.0.2.10", 51820)])
    assert rules.count("to 192.0.2.10 port 51820") == 1
    assert rules.count("to 192.0.2.20 port 443") == 1


# ----------------------------------------------------------------- Linux nft

def test_nft_strict_ruleset_exact():
    assert nft() == (
        "add table inet net_interface_rotator\n"
        "delete table inet net_interface_rotator\n"
        "table inet net_interface_rotator {\n"
        "\tchain input {\n"
        "\t\ttype filter hook input priority -10; policy accept;\n"
        '\t\tiifname "lo" accept\n'
        '\t\tiifname "wg0" accept\n'
        '\t\tiifname "eth0" meta nfproto ipv4 udp sport 67 udp dport 68 ct state established accept\n'
        '\t\tiifname "eth0" ip saddr 192.0.2.10 udp sport 51820 ct state established accept\n'
        '\t\tiifname "eth0" ip saddr 198.51.100.20 udp sport 443 ct state established accept\n'
        "\t\tdrop\n"
        "\t}\n"
        "\n"
        "\tchain output {\n"
        "\t\ttype filter hook output priority -10; policy accept;\n"
        '\t\toifname "lo" accept\n'
        '\t\toifname "wg0" accept\n'
        '\t\toifname "eth0" meta nfproto ipv4 udp sport 68 udp dport 67 accept\n'
        '\t\toifname "eth0" ip daddr 192.0.2.10 udp dport 51820 accept\n'
        '\t\toifname "eth0" ip daddr 198.51.100.20 udp dport 443 accept\n'
        "\t\tdrop\n"
        "\t}\n"
        "\n"
        "\tchain forward {\n"
        "\t\ttype filter hook forward priority -10; policy accept;\n"
        "\t\tdrop\n"
        "\t}\n"
        "}\n"
    )


def test_nft_reload_is_atomic_replace():
    lines = nft().splitlines()
    assert lines[:3] == [
        "add table inet net_interface_rotator",
        "delete table inet net_interface_rotator",
        "table inet net_interface_rotator {",
    ]


def test_nft_chains_end_by_dropping_everything():
    for rules in (nft(), nft(portal=True), nft(tunnel_if=None), nft(silent=True),
                  nft(silent=True, allow_dhcp=False)):
        # A bare drop: no interface and no family, so every interface, v4 and v6.
        assert chain(rules, "input")[-1] == "drop"
        assert chain(rules, "output")[-1] == "drop"
        assert chain(rules, "forward")[1:] == ["drop"]
        for name in ("input", "output", "forward"):
            assert re.search(rf"hook {name} priority -?\d+; policy accept;", chain(rules, name)[0])
            assert not any("drop" in line for line in chain(rules, name)[1:-1])


def test_nft_accepts_name_only_loopback_tunnel_and_iface():
    for portal in (False, True):
        rules = nft(portal=portal)
        for name in ("input", "output"):
            for line in chain(rules, name)[1:-1]:
                assert line.endswith("accept")
                assert line.split()[1] in ('"lo"', '"wg0"', '"eth0"')


def test_nft_lockdown_accepts_only_loopback():
    rules = nft(silent=True, allow_dhcp=False)
    assert chain(rules, "input")[1:] == ['iifname "lo" accept', "drop"]
    assert chain(rules, "output")[1:] == ['oifname "lo" accept', "drop"]
    assert chain(rules, "forward")[1:] == ["drop"]
    assert "eth0" not in rules and "wg0" not in rules


def test_nft_silent_accepts_loopback_and_dhcp():
    rules = nft(silent=True)
    assert chain(rules, "input")[1:] == [
        'iifname "lo" accept',
        'iifname "eth0" meta nfproto ipv4 udp sport 67 udp dport 68 ct state established accept',
        "drop"]
    assert chain(rules, "output")[1:] == [
        'oifname "lo" accept',
        'oifname "eth0" meta nfproto ipv4 udp sport 68 udp dport 67 accept',
        "drop"]


def test_nft_inbound_on_iface_is_replies_only():
    for portal in (False, True):
        for line in chain(nft(portal=portal), "input"):
            if line.startswith('iifname "eth0"') and line.endswith("accept"):
                assert "ct state established accept" in line
                assert "dport" not in line or "udp sport 67 udp dport 68" in line


def test_nft_strict_has_no_portal_ports():
    for line in nft(endpoints=[("192.0.2.10", 51820)]).splitlines():
        assert not re.search(r"(sport|dport) (53|80|443)\b", line)


def test_nft_ipv6_is_never_accepted_on_iface():
    rules = nft(portal=True)
    assert "ip6" not in rules and "ipv6" not in rules
    for line in rules.splitlines():
        if "eth0" in line and line.strip().endswith("accept"):
            assert "nfproto ipv4" in line or " ip saddr " in line or " ip daddr " in line


def test_nft_portal_adds_web_and_dns_only():
    extra = [l.strip() for l in nft(portal=True).splitlines() if l not in nft().splitlines()]
    assert extra == [
        'iifname "eth0" meta nfproto ipv4 tcp sport 80 ct state established accept',
        'iifname "eth0" meta nfproto ipv4 tcp sport 443 ct state established accept',
        'iifname "eth0" meta nfproto ipv4 udp sport 53 ct state established accept',
        'iifname "eth0" meta nfproto ipv4 tcp sport 53 ct state established accept',
        'oifname "eth0" meta nfproto ipv4 tcp dport 80 accept',
        'oifname "eth0" meta nfproto ipv4 tcp dport 443 accept',
        'oifname "eth0" meta nfproto ipv4 udp dport 53 accept',
        'oifname "eth0" meta nfproto ipv4 tcp dport 53 accept',
    ]


def test_nft_without_tunnel_has_no_tunnel_rule():
    rules = nft(tunnel_if=None)
    assert "wg0" not in rules
    accepts_all = [l.strip() for l in rules.splitlines() if re.fullmatch(r'\s*[io]ifname "\S+" accept', l)]
    assert accepts_all == ['iifname "lo" accept', 'oifname "lo" accept']


def test_nft_both_endpoints_present():
    rules = nft(endpoints=[("192.0.2.10", 51820), ("192.0.2.20", 443)])
    assert "ip daddr 192.0.2.10 udp dport 51820 accept" in rules
    assert "ip daddr 192.0.2.20 udp dport 443 accept" in rules


# ------------------------------------------------------------- input checks

@pytest.mark.parametrize("build", [macos_pf.build_rules, linux_nft.build_rules])
@pytest.mark.parametrize("iface, tunnel_if, endpoints", [
    ("en0\npass quick all", None, ENDPOINTS),
    ("en0 all", None, ENDPOINTS),
    ('en0"', None, ENDPOINTS),
    ("", None, ENDPOINTS),
    ("en0", "utun5; drop", ENDPOINTS),
    ("en0", "en0", ENDPOINTS),
    ("en0", None, []),
    ("en0", None, [("vpn.example.invalid", 51820)]),
    ("en0", None, [("192.0.2.10 port 53", 51820)]),
    ("en0", None, [("192.0.2.10", 0)]),
    ("en0", None, [("2001:db8::10", 51820)]),
    ("en0", None, [("192.0.2.10", 51820), ("2001:db8::10", 51820)]),
    ("en0", None, [("192.0.2.10", "51820 accept")]),
])
def test_build_rules_rejects_unsafe_input(build, iface, tunnel_if, endpoints):
    with pytest.raises(ValueError):
        build(iface, tunnel_if, endpoints, False)


def test_platform_module(monkeypatch):
    monkeypatch.setattr(killswitch.sys, "platform", "darwin")
    assert killswitch.platform_module() is macos_pf
    monkeypatch.setattr(killswitch.sys, "platform", "linux")
    assert killswitch.platform_module() is linux_nft
    monkeypatch.setattr(killswitch.sys, "platform", "win32")
    with pytest.raises(NotImplementedError):
        killswitch.platform_module()


# ------------------------------------------------------- load / unload (fakes)

MAIN_RULES = 'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'


class FakeCommands:
    """Replaces subprocess.run; records calls and answers from a table."""

    def __init__(self, monkeypatch, module, answers=None):
        self.calls, self.inputs, self.answers = [], [], answers or {}
        monkeypatch.setattr(module.subprocess, "run", self)

    def __call__(self, cmd, input=None, capture_output=False, text=False, **kwargs):
        assert isinstance(cmd, list) and not kwargs.get("shell")
        # The fixed environment every root command gets, not the caller's.
        assert kwargs["env"]["LC_ALL"] == "C" and kwargs["env"]["PATH"].startswith("/usr/sbin")
        self.calls.append(cmd[1:])
        self.inputs.append(input)
        rc, out, err = self.answers.get(tuple(cmd[1:]), (0, "", ""))
        return subprocess.CompletedProcess(cmd, rc, out, err)


def pf_fake(monkeypatch, overrides=None):
    answers = {
        ("-sr",): (0, MAIN_RULES, ""),
        ("-E",): (0, "", "No ALTQ support in kernel\npf enabled\nToken : 1234567890123456789\n"),
    }
    answers.update(overrides or {})
    return FakeCommands(monkeypatch, macos_pf, answers)


A = macos_pf.ANCHOR


def test_pf_load_first_time(monkeypatch):
    fake = pf_fake(monkeypatch)
    rules = pf(tunnel_if=None)
    undo = macos_pf.load(rules)
    assert undo == {"anchor": "com.apple/000.net-interface-rotator", "token": "1234567890123456789"}
    assert fake.calls == [["-sr"], ["-a", A, "-f", "-"], ["-E"], ["-F", "states"]]
    assert fake.inputs[1] == rules


def test_pf_reload_takes_no_second_reference(monkeypatch):
    fake = pf_fake(monkeypatch)
    undo = macos_pf.load(pf(tunnel_if=None))
    fake.calls.clear()
    assert macos_pf.load(pf(), undo) == undo
    # No second -E, and the states of the looser ruleset are flushed again.
    assert fake.calls == [["-sr"], ["-a", A, "-f", "-"], ["-F", "states"]]


def test_pf_every_load_flushes_states_including_the_portal_window(monkeypatch):
    fake = pf_fake(monkeypatch)
    lockdown = pf(tunnel_if=None, silent=True, allow_dhcp=False)
    strict, portal = pf(tunnel_if=None), pf(tunnel_if=None, portal=True)
    undo = macos_pf.load(lockdown)
    for rules in (strict, portal, strict, pf(), pf(silent=True)):
        macos_pf.load(rules, undo)
    loads = [n for n, call in enumerate(fake.calls) if call == ["-a", A, "-f", "-"]]
    assert [fake.inputs[n] for n in loads] == [lockdown, strict, portal, strict, pf(), pf(silent=True)]
    # Each load is followed by a state flush before the next load starts, so a
    # connection opened in the portal window cannot outlive the strict reload.
    for n, nxt in zip(loads, loads[1:] + [len(fake.calls)]):
        assert ["-F", "states"] in fake.calls[n + 1:nxt]
    assert fake.calls.count(["-F", "states"]) == 6
    assert fake.calls.count(["-E"]) == 1


def test_pf_reload_reports_a_failed_state_flush(monkeypatch):
    fake = pf_fake(monkeypatch)
    undo = macos_pf.load(pf(tunnel_if=None))
    fake.answers[("-F", "states")] = (1, "", "boom")
    with pytest.raises(BackendError, match="boom"):
        macos_pf.load(pf(), undo)
    # The stricter rules stay loaded; nothing of ours is flushed or released.
    assert ["-a", A, "-F", "all"] not in fake.calls and not any("-X" in c for c in fake.calls)


def test_pf_load_refuses_when_parent_anchor_missing(monkeypatch):
    fake = pf_fake(monkeypatch, {("-sr",): (0, 'anchor "other/*" all\n', "")})
    with pytest.raises(BackendError, match="com.apple"):
        macos_pf.load(pf())
    assert fake.calls == [["-sr"]]


def test_pf_load_refuses_rules_that_do_not_end_by_blocking_everything(monkeypatch):
    fake = pf_fake(monkeypatch)
    for bad in ("pass quick on lo0 all no state\n",
                "block drop quick on en0 all\n",  # one interface only
                "block drop quick all\npass quick on en1 all\n",  # not the last rule
                ""):
        with pytest.raises(BackendError):
            macos_pf.load(bad)
    assert fake.calls == []


def test_pf_load_cleans_up_when_enable_gives_no_token(monkeypatch):
    fake = pf_fake(monkeypatch, {("-E",): (0, "", "pf enabled\n")})
    with pytest.raises(BackendError, match="token"):
        macos_pf.load(pf())
    assert fake.calls[-1] == ["-a", A, "-F", "all"]


def test_pf_load_cleans_up_when_state_flush_fails(monkeypatch):
    fake = pf_fake(monkeypatch, {("-F", "states"): (1, "", "boom")})
    with pytest.raises(BackendError):
        macos_pf.load(pf())
    assert fake.calls[-2:] == [["-a", A, "-F", "all"], ["-X", "1234567890123456789"]]


def test_pf_rule_load_failure_takes_no_reference(monkeypatch):
    fake = pf_fake(monkeypatch, {("-a", A, "-f", "-"): (1, "", "syntax error")})
    with pytest.raises(BackendError, match="syntax error"):
        macos_pf.load(pf())
    assert ["-E"] not in fake.calls


def test_pf_unload_touches_only_our_anchor_and_token(monkeypatch):
    fake = pf_fake(monkeypatch)
    assert macos_pf.unload({"anchor": A, "token": "42"}) == []
    assert fake.calls == [["-a", A, "-F", "all"], ["-X", "42"]]


def test_pf_unload_stale_token_is_a_warning(monkeypatch):
    fake = pf_fake(monkeypatch, {("-X", "42"): (1, "", "pfctl: DIOCSTOPREF: Invalid argument")})
    warnings = macos_pf.unload({"anchor": A, "token": "42"})
    assert len(warnings) == 1 and "token" in warnings[0]


def test_pf_unload_flush_failure_still_releases_token(monkeypatch):
    fake = pf_fake(monkeypatch, {("-a", A, "-F", "all"): (1, "", "boom")})
    with pytest.raises(BackendError):
        macos_pf.unload({"anchor": A, "token": "42"})
    assert ["-X", "42"] in fake.calls


def test_pf_never_runs_forbidden_commands(monkeypatch):
    fake = pf_fake(monkeypatch)
    undo = macos_pf.load(pf(tunnel_if=None))
    macos_pf.load(pf(), undo)
    macos_pf.is_loaded()
    macos_pf.unload(undo)
    for call in fake.calls:
        assert "-d" not in call and "/etc/pf.conf" not in call
        if "-f" in call or ("-F" in call and "states" not in call):
            assert call[:2] == ["-a", A]


def test_pf_is_loaded(monkeypatch):
    enabled = (0, "Status: Enabled for 0 days\n", "")
    listed = (0, pf(), "")
    good = {("-a", A, "-sr"): listed, ("-si",): enabled}
    pf_fake(monkeypatch, good)
    assert macos_pf.is_loaded() is True
    pf_fake(monkeypatch, {**good, ("-a", A, "-sr"): (0, pf(silent=True, allow_dhcp=False), "")})
    assert macos_pf.is_loaded() is True
    # Empty anchor, pf disabled.
    pf_fake(monkeypatch, {**good, ("-a", A, "-sr"): (0, "", "")})
    assert macos_pf.is_loaded() is False
    pf_fake(monkeypatch, {**good, ("-si",): (0, "Status: Disabled\n", "")})
    assert macos_pf.is_loaded() is False


def test_pf_is_loaded_needs_the_parent_anchor_and_our_final_block(monkeypatch):
    enabled = (0, "Status: Enabled for 0 days\n", "")
    good = {("-a", A, "-sr"): (0, pf(), ""), ("-si",): enabled}
    # The main ruleset was replaced and no longer evaluates com.apple/*.
    pf_fake(monkeypatch, {**good, ("-sr",): (0, 'anchor "other/*" all\n', "")})
    assert macos_pf.is_loaded() is False
    pf_fake(monkeypatch, {**good, ("-sr",): (1, "", "pfctl: /dev/pf: Permission denied")})
    assert macos_pf.is_loaded() is False
    # Our anchor holds rules, but not (or no longer last) the block of everything.
    without_block = "".join(l + "\n" for l in pf().splitlines()[:-1])
    pf_fake(monkeypatch, {**good, ("-a", A, "-sr"): (0, without_block, "")})
    assert macos_pf.is_loaded() is False
    pf_fake(monkeypatch, {**good, ("-a", A, "-sr"): (0, pf() + "pass quick on en1 all\n", "")})
    assert macos_pf.is_loaded() is False
    pf_fake(monkeypatch, {**good, ("-a", A, "-sr"): (0, "block drop quick on en0 all\n", "")})
    assert macos_pf.is_loaded() is False


def test_pf_ensure_enabled(monkeypatch):
    fake = pf_fake(monkeypatch, {("-si",): (0, "Status: Enabled for 0 days\n", "")})
    assert macos_pf.ensure_enabled() is None
    assert fake.calls == [["-si"]]  # still enabled: no second reference
    fake = pf_fake(monkeypatch, {("-si",): (0, "Status: Disabled\n", "")})
    assert macos_pf.ensure_enabled() == "1234567890123456789"
    assert fake.calls == [["-si"], ["-E"]]


def test_pf_drop_states_all_or_one_interface(monkeypatch):
    fake = pf_fake(monkeypatch)
    macos_pf.drop_states()
    macos_pf.drop_states("en0")
    assert fake.calls == [["-F", "states"], ["-i", "en0", "-F", "states"]]


def test_nft_load_and_reload(monkeypatch):
    fake = FakeCommands(monkeypatch, linux_nft)
    undo = linux_nft.load(nft(tunnel_if=None))
    assert undo == {"table": "net_interface_rotator"}
    assert linux_nft.load(nft(), undo) == undo
    assert fake.calls == [["-f", "-"], ["-f", "-"]]
    assert fake.inputs == [nft(tunnel_if=None), nft()]


def test_nft_load_failure_raises(monkeypatch):
    FakeCommands(monkeypatch, linux_nft, {("-f", "-"): (1, "", "syntax error")})
    with pytest.raises(BackendError, match="syntax error"):
        linux_nft.load(nft())
    with pytest.raises(BackendError):
        linux_nft.load("flush ruleset\n")


def test_nft_load_refuses_rules_whose_chains_do_not_drop_everything(monkeypatch):
    fake = FakeCommands(monkeypatch, linux_nft)
    good = nft()
    for bad in (good.replace("\t\tdrop\n", '\t\toifname "eth0" drop\n'),  # one interface only
                good.replace("\t\tdrop\n\t}\n}", "\t}\n}"),  # forward chain forwards
                good.replace("\t\tdrop\n", "\t\tdrop\n\t\taccept\n", 1)):
        with pytest.raises(BackendError):
            linux_nft.load(bad)
    assert fake.calls == []


def test_nft_unload_deletes_only_our_table(monkeypatch):
    fake = FakeCommands(monkeypatch, linux_nft)
    assert linux_nft.unload({"table": "net_interface_rotator"}) == []
    assert fake.calls == [["delete", "table", "inet", "net_interface_rotator"]]


def test_nft_unload_missing_table_is_ok_other_errors_raise(monkeypatch):
    cmd = ("delete", "table", "inet", "net_interface_rotator")
    FakeCommands(monkeypatch, linux_nft, {cmd: (1, "", "Error: No such file or directory")})
    assert linux_nft.unload({"table": "net_interface_rotator"}) == []
    FakeCommands(monkeypatch, linux_nft, {cmd: (1, "", "Operation not permitted")})
    with pytest.raises(BackendError):
        linux_nft.unload({"table": "net_interface_rotator"})


def test_missing_binary_is_backend_error(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(linux_nft.subprocess, "run", missing)
    with pytest.raises(BackendError, match="nft"):
        linux_nft.load(nft())
