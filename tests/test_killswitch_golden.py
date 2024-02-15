"""Golden-file tests for the kill-switch rule builders (PLAN.md task 2.6).

The files in tests/golden/ were generated once from build_rules and checked by
hand against the Phase 2 policy. To regenerate them after a deliberate policy
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
}
STRICT = ["pf_strict", "pf_strict_no_tunnel", "nft_strict", "nft_strict_no_tunnel"]
PORTAL = ["pf_portal", "nft_portal"]
SILENT = ["pf_silent", "nft_silent"]


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


# ------------------------------------------------------ strict: pf (macOS)

PF_DHCP = ["from", "any", "port", "68", "to", "any", "port", "67"]


def _pf_passes_on_iface(text: str) -> tuple[list[str], list[str]]:
    lines = text.splitlines()
    iface_lines = [l for l in lines if "en0" in _tokens(l)]
    passes = [l for l in iface_lines if "pass" in _tokens(l)]
    return iface_lines, passes


@pytest.mark.parametrize("name", [n for n in STRICT if n.startswith("pf_")])
def test_pf_strict_passes_on_iface_are_dhcp_or_endpoint(name):
    _, passes = _pf_passes_on_iface(_read(name))
    assert passes, "strict ruleset must pass something on the physical interface"

    seen = set()
    for line in passes:
        t = _tokens(line)
        if "udp" in t and _has_seq(t, PF_DHCP):
            continue
        matched = [ep for ep in STRICT_ENDPOINTS
                   if "udp" in t and _has_seq(t, ["to", ep[0], "port", str(ep[1])])]
        assert matched, f"unexpected pass on physical interface: {line!r}"
        seen.update(matched)
    assert seen == set(STRICT_ENDPOINTS), "every endpoint needs its pass rule"


@pytest.mark.parametrize("name", [n for n in STRICT if n.startswith("pf_")])
def test_pf_strict_no_portal_ports_on_iface(name):
    _, passes = _pf_passes_on_iface(_read(name))
    for line in passes:
        assert FORBIDDEN_STRICT_PORTS.isdisjoint(_tokens(line)), line


@pytest.mark.parametrize("name", [n for n in STRICT if n.startswith("pf_")])
def test_pf_strict_ipv6_blocked_on_iface(name):
    text = _read(name)
    _, passes = _pf_passes_on_iface(text)
    assert "block drop quick on en0 inet6 all" in text.splitlines()
    assert not any("inet6" in _tokens(l) for l in passes)


@pytest.mark.parametrize("name", [n for n in STRICT if n.startswith("pf_")])
def test_pf_strict_last_rule_on_iface_is_block(name):
    iface_lines, _ = _pf_passes_on_iface(_read(name))
    assert _tokens(iface_lines[-1]) == ["block", "drop", "quick", "on", "en0", "all"]


# ------------------------------------------------------ strict: nft (Linux)

NFT_DHCP_IN = ["udp", "sport", "67", "udp", "dport", "68"]
NFT_DHCP_OUT = ["udp", "sport", "68", "udp", "dport", "67"]


@pytest.mark.parametrize("name", [n for n in STRICT if n.startswith("nft_")])
def test_nft_strict_accepts_on_iface_are_dhcp_or_endpoint(name):
    chains = _nft_chains(_read(name))
    assert set(chains) == {"input", "output", "forward"}
    # input: replies from the endpoint (source ip, source port);
    # output: requests to the endpoint (destination ip, destination port).
    specs = (
        ("input", NFT_DHCP_IN, "saddr", "sport"),
        ("output", NFT_DHCP_OUT, "daddr", "dport"),
    )
    for chain, dhcp, addr_key, port_key in specs:
        accepts = [r for r in chains[chain] if "wlan0" in _tokens(r) and "accept" in _tokens(r)]
        assert accepts, f"{chain} chain has no accept rule on the physical interface"
        seen = set()
        for line in accepts:
            t = _tokens(line)
            assert FORBIDDEN_STRICT_PORTS.isdisjoint(t), line
            if _has_seq(t, dhcp):
                continue
            matched = [ep for ep in STRICT_ENDPOINTS
                       if _has_seq(t, ["ip", addr_key, ep[0], "udp", port_key, str(ep[1])])]
            assert matched, f"unexpected accept on physical interface ({chain}): {line!r}"
            seen.update(matched)
        assert seen == set(STRICT_ENDPOINTS), f"every endpoint needs a rule in {chain}"


@pytest.mark.parametrize("name", [n for n in STRICT if n.startswith("nft_")])
def test_nft_strict_no_portal_ports_on_iface(name):
    chains = _nft_chains(_read(name))
    for rules in chains.values():
        for line in rules:
            if "wlan0" in _tokens(line):
                assert FORBIDDEN_STRICT_PORTS.isdisjoint(_tokens(line)), line


@pytest.mark.parametrize("name", [n for n in STRICT if n.startswith("nft_")])
def test_nft_strict_ipv6_blocked_on_iface(name):
    chains = _nft_chains(_read(name))
    for chain in ("input", "output"):
        for line in chains[chain]:
            t = _tokens(line)
            if "wlan0" in t and "accept" in t:
                assert "ip6" not in t and "ipv6" not in t, line
        # The final rule is a family-less drop, so it covers IPv6 too.
        direction = "iifname" if chain == "input" else "oifname"
        assert _tokens(chains[chain][-1]) == [direction, "wlan0", "drop"]
    assert _tokens(chains["forward"][-1]) == ["oifname", "wlan0", "drop"]


@pytest.mark.parametrize("name", [n for n in STRICT if n.startswith("nft_")])
def test_nft_strict_last_rule_touching_iface_is_drop(name):
    chains = _nft_chains(_read(name))
    for chain in ("input", "output", "forward"):
        touching = [r for r in chains[chain] if "wlan0" in _tokens(r)]
        assert touching, f"{chain} chain does not mention the physical interface"
        assert _tokens(touching[-1])[-1] == "drop", f"{chain}: {touching[-1]!r}"


# ------------------------------------------------------------ portal goldens

@pytest.mark.parametrize("name", PORTAL)
def test_portal_passes_web_and_dns_on_iface(name):
    text = _read(name)
    if name.startswith("pf_"):
        _, rules = _pf_passes_on_iface(text)
    else:
        chains = _nft_chains(text)
        rules = [r for rs in chains.values() for r in rs
                 if "wlan0" in _tokens(r) and "accept" in _tokens(r)]
    for port in PORTAL_PORTS:
        assert any(port in _tokens(r) for r in rules), f"portal golden lacks port {port}"


@pytest.mark.parametrize("name", PORTAL)
def test_portal_keeps_ipv6_blocked_on_iface(name):
    text = _read(name)
    if name.startswith("pf_"):
        assert "block drop quick on en0 inet6 all" in text.splitlines()
    else:
        for chain in ("input", "output"):
            rules = _nft_chains(text)[chain]
            assert not any("ip6" in _tokens(r) or "ipv6" in _tokens(r) for r in rules)


# ------------------------------------------------------------ silent goldens

def test_pf_silent_passes_only_dhcp_on_iface():
    text = _read("pf_silent")
    iface_lines, passes = _pf_passes_on_iface(text)
    assert [_tokens(l) for l in passes] == [
        ["pass", "out", "quick", "on", "en0", "inet", "proto", "udp", *PF_DHCP, "keep", "state"]]
    assert "block drop quick on en0 inet6 all" in text.splitlines()
    assert _tokens(iface_lines[-1]) == ["block", "drop", "quick", "on", "en0", "all"]
    # Apart from the interface's own rules, loopback is the only thing passed.
    others = [l for l in text.splitlines() if l not in iface_lines]
    assert others == ["pass quick on lo0 all no state"]


def test_nft_silent_accepts_only_dhcp_on_iface():
    chains = _nft_chains(_read("nft_silent"))
    assert set(chains) == {"input", "output", "forward"}
    assert [_tokens(r) for r in chains["input"]] == [
        ["iifname", "lo", "accept"],
        ["iifname", "wlan0", "meta", "nfproto", "ipv4", *NFT_DHCP_IN, "ct", "state",
         "established", "accept"],
        ["iifname", "wlan0", "drop"],
    ]
    assert [_tokens(r) for r in chains["output"]] == [
        ["oifname", "lo", "accept"],
        ["oifname", "wlan0", "meta", "nfproto", "ipv4", *NFT_DHCP_OUT, "accept"],
        ["oifname", "wlan0", "drop"],
    ]
    assert [_tokens(r) for r in chains["forward"]] == [
        ["iifname", "wlan0", "drop"], ["oifname", "wlan0", "drop"]]


@pytest.mark.parametrize("name", SILENT)
def test_silent_has_no_tunnel_endpoint_or_portal_rule(name):
    tokens = {tok for line in _read(name).splitlines() for tok in _tokens(line)}
    forbidden = {"utun5", "wg0", "53", "80", "443", "tcp"}
    forbidden |= {ep[0] for ep in STRICT_ENDPOINTS} | {str(ep[1]) for ep in STRICT_ENDPOINTS}
    assert forbidden.isdisjoint(tokens)


def test_silent_ignores_its_other_arguments():
    assert macos_pf.build_rules("en0", None, [], False, silent=True) == _read("pf_silent")
    assert linux_nft.build_rules("wlan0", None, [], False, silent=True) == _read("nft_silent")
    for build in (macos_pf.build_rules, linux_nft.build_rules):
        with pytest.raises(ValueError):
            build("en0; pass all", None, [], False, silent=True)


def test_silent_rules_are_loadable(monkeypatch):
    """Both loaders refuse rules without their block/drop; silent rules have it."""
    assert macos_pf._BLOCK_ALL.search(_read("pf_silent")).group(1) == "en0"
    nft = _read("nft_silent")
    assert f"table {linux_nft.FAMILY} {linux_nft.TABLE} {{" in nft and " drop" in nft
