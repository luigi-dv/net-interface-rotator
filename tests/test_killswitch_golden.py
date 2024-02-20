"""Golden-file tests for the kill-switch rule builders (PLAN.md task 2.6).

The files in tests/golden/ were generated from build_rules and checked by hand
against the policy: default deny on every interface, IPv4 and IPv6; loopback
and the tunnel interface pass; DHCP, the tunnel endpoints and (portal only)
web and DNS pass on the physical interface and nowhere else. To regenerate them after a deliberate policy
change, run:

    UPDATE_GOLDEN=1 venv/bin/python -m pytest tests/test_killswitch_golden.py

Without UPDATE_GOLDEN the tests only compare. The structural assertions read the
golden text line by line; they do not depend on regular expressions.
"""
import os
from pathlib import Path

import pytest

from rotator.killswitch import linux_nft, macos_pf

GOLDEN_DIR = Path(__file__).parent / "golden"

STRICT_ENDPOINTS = [("192.0.2.10", 51820), ("198.51.100.20", 51821)]
PORTAL_ENDPOINTS = [("192.0.2.10", 51820)]
FORBIDDEN_STRICT_PORTS = {"53", "80", "443"}
PORTAL_PORTS = ("53", "80", "443")

GOLDENS = {
    "pf_strict": lambda: macos_pf.build_rules("en0", "utun5", STRICT_ENDPOINTS, False),
    "pf_strict_no_tunnel": lambda: macos_pf.build_rules("en0", None, STRICT_ENDPOINTS, False),
    "pf_portal": lambda: macos_pf.build_rules("en0", None, PORTAL_ENDPOINTS, True),
    "nft_strict": lambda: linux_nft.build_rules("wlan0", "wg0", STRICT_ENDPOINTS, False),
    "nft_strict_no_tunnel": lambda: linux_nft.build_rules("wlan0", None, STRICT_ENDPOINTS, False),
    "nft_portal": lambda: linux_nft.build_rules("wlan0", None, PORTAL_ENDPOINTS, True),
    # silent ignores the tunnel interface, the endpoints and the portal flag.
    "pf_silent": lambda: macos_pf.build_rules("en0", "utun5", STRICT_ENDPOINTS, True, silent=True),
    "nft_silent": lambda: linux_nft.build_rules("wlan0", "wg0", STRICT_ENDPOINTS, True, silent=True),
    # lockdown: what is loaded while the host name and MAC address change.
    "pf_lockdown": lambda: macos_pf.build_rules(
        "en0", "utun5", STRICT_ENDPOINTS, True, silent=True, allow_dhcp=False),
    "nft_lockdown": lambda: linux_nft.build_rules(
        "wlan0", "wg0", STRICT_ENDPOINTS, True, silent=True, allow_dhcp=False),
}
STRICT = ["pf_strict", "pf_strict_no_tunnel", "nft_strict", "nft_strict_no_tunnel"]
PORTAL = ["pf_portal", "nft_portal"]
SILENT = ["pf_silent", "nft_silent"]
LOCKDOWN = ["pf_lockdown", "nft_lockdown"]
PF = sorted(n for n in GOLDENS if n.startswith("pf_"))
NFT = sorted(n for n in GOLDENS if n.startswith("nft_"))
# The only interfaces a golden may name: loopback, the tunnel, the physical one.
PF_TUNNEL = {"pf_strict": "utun5"}
NFT_TUNNEL = {"nft_strict": "wg0"}


def _golden(name: str, text: str) -> str:
    """Return the stored golden for ``name``; rewrite it first when UPDATE_GOLDEN is set."""
    path = GOLDEN_DIR / f"{name}.txt"
    if os.environ.get("UPDATE_GOLDEN"):
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return path.read_text(encoding="utf-8")


def _read(name: str) -> str:
    return (GOLDEN_DIR / f"{name}.txt").read_text(encoding="utf-8")


def _tokens(line: str) -> list[str]:
    return [tok.strip('"') for tok in line.split()]


def _has_seq(tokens: list[str], seq: list[str]) -> bool:
    n = len(seq)
    return any(tokens[i:i + n] == seq for i in range(len(tokens) - n + 1))


def _nft_chains(text: str) -> dict[str, list[str]]:
    """Map chain name -> its rule lines, in order."""
    chains, current = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("chain "):
            current = _tokens(line)[1]
            chains[current] = []
        elif line == "}":
            current = None
        elif current is not None and line and not line.startswith("type "):
            chains[current].append(line)
    return chains


# ------------------------------------------------------------ byte comparison

@pytest.mark.parametrize("name", sorted(GOLDENS))
def test_build_rules_matches_golden(name):
    assert GOLDENS[name]() == _golden(name, GOLDENS[name]())


# -------------------------------------------- every golden: default deny (pf)

PF_DHCP = ["from", "any", "port", "68", "to", "any", "port", "67"]
PF_BLOCK_ALL = ["block", "drop", "quick", "all"]


def _pf_iface(line: str) -> str | None:
    """The interface a pf rule is limited to; None when it applies to all."""
    t = _tokens(line)
    return t[t.index("on") + 1] if "on" in t else None


def _pf_passes_on_iface(text: str) -> list[str]:
    return [l for l in text.splitlines() if _tokens(l)[0] == "pass" and _pf_iface(l) == "en0"]


def _pf_is_dhcp(line: str) -> bool:
    t = _tokens(line)
    return t[:8] == ["pass", "out", "quick", "on", "en0", "inet", "proto", "udp"] and _has_seq(t, PF_DHCP)


def _pf_endpoint(line: str, endpoints) -> tuple | None:
    t = _tokens(line)
    if t[:8] != ["pass", "out", "quick", "on", "en0", "inet", "proto", "udp"]:
        return None
    for ep in endpoints:
        if _has_seq(t, ["from", "any", "to", ep[0], "port", str(ep[1])]):
            return ep
    return None


def _pf_is_portal(line: str) -> bool:
    t = _tokens(line)
    return (t[:7] == ["pass", "out", "quick", "on", "en0", "inet", "proto"]
            and _has_seq(t, ["from", "any", "to", "any", "port"])
            and t[t.index("port") + 1] in PORTAL_PORTS)


@pytest.mark.parametrize("name", PF)
def test_pf_final_rule_blocks_everything_on_every_interface(name):
    lines = _read(name).splitlines()
    # No "on <iface>" and no inet/inet6: all interfaces, both families.
    assert _tokens(lines[-1]) == PF_BLOCK_ALL
    # It is the only block, so nothing before it can be mistaken for the policy.
    assert [l for l in lines if _tokens(l)[0] == "block"] == [lines[-1]]
    assert all("quick" in _tokens(l) for l in lines)


@pytest.mark.parametrize("name", PF)
def test_pf_passes_only_on_loopback_tunnel_and_iface(name):
    tunnel = PF_TUNNEL.get(name)
    for line in _read(name).splitlines()[:-1]:
        t = _tokens(line)
        assert t[0] == "pass", line
        iface = _pf_iface(line)
        assert iface is not None, f"pass on every interface: {line!r}"
        if iface == "lo0" or (tunnel and iface == tunnel):
            assert t == ["pass", "quick", "on", iface, "all", "no", "state"]
        else:
            # Any other interface (Ethernet, tethering, awdl0) gets no pass at
            # all; the physical one only what the next tests allow.
            assert iface == "en0", f"pass on an unexpected interface: {line!r}"
            assert t[:6] == ["pass", "out", "quick", "on", "en0", "inet"], line
            assert "inet6" not in t


@pytest.mark.parametrize("name", PF)
def test_pf_passes_on_iface_are_dhcp_endpoints_or_portal(name):
    endpoints = PORTAL_ENDPOINTS if name in PORTAL else STRICT_ENDPOINTS
    if name in SILENT + LOCKDOWN:
        endpoints = []
    seen, dhcp, portal = set(), 0, 0
    for line in _pf_passes_on_iface(_read(name)):
        if _pf_is_dhcp(line):
            dhcp += 1
        elif _pf_endpoint(line, endpoints):
            seen.add(_pf_endpoint(line, endpoints))
        else:
            assert name in PORTAL and _pf_is_portal(line), f"unexpected pass on en0: {line!r}"
            portal += 1
    assert seen == set(endpoints), "every endpoint needs its pass rule"
    assert dhcp == (0 if name in LOCKDOWN else 1)
    assert portal == (4 if name in PORTAL else 0)


@pytest.mark.parametrize("name", [n for n in PF if n not in PORTAL])
def test_pf_no_portal_ports_outside_the_portal_golden(name):
    for line in _read(name).splitlines():
        assert FORBIDDEN_STRICT_PORTS.isdisjoint(_tokens(line)), line
        assert "tcp" not in _tokens(line)


def test_pf_tunnel_passes_only_when_given():
    assert "pass quick on utun5 all no state" in _read("pf_strict").splitlines()
    for name in PF:
        if name != "pf_strict":
            assert "utun5" not in _read(name)


# ------------------------------------------- every golden: default deny (nft)

NFT_DHCP_IN = ["udp", "sport", "67", "udp", "dport", "68"]
NFT_DHCP_OUT = ["udp", "sport", "68", "udp", "dport", "67"]


@pytest.mark.parametrize("name", NFT)
def test_nft_every_chain_ends_by_dropping_everything(name):
    chains = _nft_chains(_read(name))
    assert set(chains) == {"input", "output", "forward"}
    for chain, rules in chains.items():
        # A bare drop: no interface match and no family, so it covers every
        # interface and both IPv4 and IPv6.
        assert _tokens(rules[-1]) == ["drop"], f"{chain}: {rules[-1]!r}"
        assert all(_tokens(r)[-1] == "accept" for r in rules[:-1]), chain
    # Nothing at all is forwarded.
    assert chains["forward"] == ["drop"]


@pytest.mark.parametrize("name", NFT)
def test_nft_accepts_only_on_loopback_tunnel_and_iface(name):
    chains = _nft_chains(_read(name))
    tunnel = NFT_TUNNEL.get(name)
    for chain, key in (("input", "iifname"), ("output", "oifname")):
        for line in chains[chain][:-1]:
            t = _tokens(line)
            assert t[0] == key, f"accept not tied to an interface ({chain}): {line!r}"
            iface = t[1]
            if iface == "lo" or (tunnel and iface == tunnel):
                assert t == [key, iface, "accept"]
            else:
                assert iface == "wlan0", f"accept on an unexpected interface: {line!r}"
                assert len(t) > 3, f"physical interface accepted wholesale: {line!r}"
                assert "ip6" not in t and "ipv6" not in t, line
                assert _has_seq(t, ["meta", "nfproto", "ipv4"]) or t[2] == "ip", line


@pytest.mark.parametrize("name", NFT)
def test_nft_accepts_on_iface_are_dhcp_endpoints_or_portal(name):
    chains = _nft_chains(_read(name))
    endpoints = PORTAL_ENDPOINTS if name in PORTAL else STRICT_ENDPOINTS
    if name in SILENT + LOCKDOWN:
        endpoints = []
    # input: replies from the endpoint (source ip, source port);
    # output: requests to the endpoint (destination ip, destination port).
    specs = (
        ("input", NFT_DHCP_IN, "saddr", "sport"),
        ("output", NFT_DHCP_OUT, "daddr", "dport"),
    )
    for chain, dhcp_seq, addr_key, port_key in specs:
        seen, dhcp, portal = set(), 0, 0
        for line in chains[chain]:
            t = _tokens(line)
            if "wlan0" not in t:
                continue
            if chain == "input":
                assert _has_seq(t, ["ct", "state", "established", "accept"]), line
            matched = [ep for ep in endpoints
                       if _has_seq(t, ["ip", addr_key, ep[0], "udp", port_key, str(ep[1])])]
            if _has_seq(t, dhcp_seq):
                dhcp += 1
            elif matched:
                seen.update(matched)
            else:
                assert name in PORTAL and t[t.index(port_key) + 1] in PORTAL_PORTS, (
                    f"unexpected accept on wlan0 ({chain}): {line!r}")
                portal += 1
        assert seen == set(endpoints), f"every endpoint needs a rule in {chain}"
        assert dhcp == (0 if name in LOCKDOWN else 1)
        assert portal == (4 if name in PORTAL else 0)


@pytest.mark.parametrize("name", [n for n in NFT if n not in PORTAL])
def test_nft_no_portal_ports_outside_the_portal_golden(name):
    for rules in _nft_chains(_read(name)).values():
        for line in rules:
            assert FORBIDDEN_STRICT_PORTS.isdisjoint(_tokens(line)), line
            assert "tcp" not in _tokens(line)


# ------------------------------------------------------------ portal goldens

@pytest.mark.parametrize("name", PORTAL)
def test_portal_passes_web_and_dns_on_iface(name):
    text = _read(name)
    if name.startswith("pf_"):
        rules = _pf_passes_on_iface(text)
    else:
        chains = _nft_chains(text)
        rules = [r for rs in chains.values() for r in rs
                 if "wlan0" in _tokens(r) and "accept" in _tokens(r)]
    for port in PORTAL_PORTS:
        assert any(port in _tokens(r) for r in rules), f"portal golden lacks port {port}"


# ------------------------------------------------- silent and lockdown goldens

def test_pf_silent_passes_only_loopback_and_dhcp():
    assert [_tokens(l) for l in _read("pf_silent").splitlines()] == [
        ["pass", "quick", "on", "lo0", "all", "no", "state"],
        ["pass", "out", "quick", "on", "en0", "inet", "proto", "udp", *PF_DHCP, "keep", "state"],
        PF_BLOCK_ALL,
    ]


def test_pf_lockdown_passes_only_loopback():
    assert [_tokens(l) for l in _read("pf_lockdown").splitlines()] == [
        ["pass", "quick", "on", "lo0", "all", "no", "state"],
        PF_BLOCK_ALL,
    ]


def test_nft_silent_accepts_only_loopback_and_dhcp():
    chains = _nft_chains(_read("nft_silent"))
    assert [_tokens(r) for r in chains["input"]] == [
        ["iifname", "lo", "accept"],
        ["iifname", "wlan0", "meta", "nfproto", "ipv4", *NFT_DHCP_IN, "ct", "state",
         "established", "accept"],
        ["drop"],
    ]
    assert [_tokens(r) for r in chains["output"]] == [
        ["oifname", "lo", "accept"],
        ["oifname", "wlan0", "meta", "nfproto", "ipv4", *NFT_DHCP_OUT, "accept"],
        ["drop"],
    ]
    assert [_tokens(r) for r in chains["forward"]] == [["drop"]]


def test_nft_lockdown_accepts_only_loopback():
    chains = _nft_chains(_read("nft_lockdown"))
    assert [_tokens(r) for r in chains["input"]] == [["iifname", "lo", "accept"], ["drop"]]
    assert [_tokens(r) for r in chains["output"]] == [["oifname", "lo", "accept"], ["drop"]]
    assert [_tokens(r) for r in chains["forward"]] == [["drop"]]


@pytest.mark.parametrize("name", SILENT + LOCKDOWN)
def test_silent_has_no_tunnel_endpoint_or_portal_rule(name):
    tokens = {tok for line in _read(name).splitlines() for tok in _tokens(line)}
    forbidden = {"utun5", "wg0", "53", "80", "443", "tcp"}
    forbidden |= {ep[0] for ep in STRICT_ENDPOINTS} | {str(ep[1]) for ep in STRICT_ENDPOINTS}
    if name in LOCKDOWN:
        forbidden |= {"en0", "wlan0", "67", "68", "udp"}
    assert forbidden.isdisjoint(tokens)


def test_silent_ignores_its_other_arguments():
    assert macos_pf.build_rules("en0", None, [], False, silent=True) == _read("pf_silent")
    assert linux_nft.build_rules("wlan0", None, [], False, silent=True) == _read("nft_silent")
    assert macos_pf.build_rules(
        "en0", None, [], False, silent=True, allow_dhcp=False) == _read("pf_lockdown")
    assert linux_nft.build_rules(
        "wlan0", None, [], False, silent=True, allow_dhcp=False) == _read("nft_lockdown")
    for build in (macos_pf.build_rules, linux_nft.build_rules):
        with pytest.raises(ValueError):
            build("en0; pass all", None, [], False, silent=True)


@pytest.mark.parametrize("name", sorted(GOLDENS))
def test_every_golden_passes_its_loaders_own_check(name):
    """Both loaders refuse rules that do not end by blocking everything."""
    text = _read(name)
    if name.startswith("pf_"):
        assert macos_pf._ends_with_block_all(text)
    else:
        assert f"table {linux_nft.FAMILY} {linux_nft.TABLE} {{" in text
        assert linux_nft._chains_end_with_drop(text)
