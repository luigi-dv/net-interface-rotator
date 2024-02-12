"""Hostile-network detection and strict-mode policy. Pure: no commands run."""
from dataclasses import replace

import pytest

from rotator import detect
from rotator.detect import (
    ARP_CONFLICT,
    ARP_SPOOF_SUSPECTED,
    DEFAULT_STRICT_ON,
    NETWORK_RECONFIGURED,
    POSSIBLE_EVIL_TWIN,
    Reading,
    findings,
    react,
    reading_from,
    strict_settings,
)

GW = "192.0.2.1"
GW_MAC = "02:00:00:aa:bb:01"
ROGUE_MAC = "02:00:00:ee:ee:99"
DNS = ("192.0.2.53", "192.0.2.54")
AP_1 = "02:00:00:cc:00:01"
AP_2 = "02:00:00:cc:00:02"

BASE = Reading(
    gateway=GW,
    gateway_macs=frozenset({GW_MAC}),
    dns=DNS,
    ssid="Cafe",
    bssid=AP_1,
)
MAC_OS_BASE = replace(BASE, ssid=None, bssid=None)
DISCONNECTED = Reading(None, frozenset(), (), None, None)


def check(current, baseline=BASE):
    return findings(baseline, baseline, current)


# --- findings ---------------------------------------------------------------


def test_unchanged_reading_has_no_findings():
    assert check(BASE) == set()


def test_gateway_mac_replaced_is_arp_spoof():
    current = replace(BASE, gateway_macs=frozenset({ROGUE_MAC}))
    assert check(current) == {ARP_SPOOF_SUSPECTED}


def test_extra_gateway_mac_is_spoof_and_conflict():
    current = replace(BASE, gateway_macs=frozenset({GW_MAC, ROGUE_MAC}))
    assert check(current) == {ARP_SPOOF_SUSPECTED, ARP_CONFLICT}


def test_spoof_is_judged_against_baseline_not_previous():
    spoofed = replace(BASE, gateway_macs=frozenset({ROGUE_MAC}))
    assert findings(BASE, spoofed, spoofed) == {ARP_SPOOF_SUSPECTED}


def test_missing_neighbour_entry_is_not_a_spoof():
    assert check(replace(BASE, gateway_macs=frozenset())) == set()
    no_mac_baseline = replace(BASE, gateway_macs=frozenset())
    assert check(BASE, baseline=no_mac_baseline) == set()


def test_conflict_already_present_at_baseline_is_only_a_conflict():
    both = replace(BASE, gateway_macs=frozenset({GW_MAC, ROGUE_MAC}))
    assert check(both, baseline=both) == {ARP_CONFLICT}


def test_gateway_ip_change_is_reconfigured_not_spoof():
    current = replace(BASE, gateway="192.0.2.254", gateway_macs=frozenset({ROGUE_MAC}))
    assert check(current) == {NETWORK_RECONFIGURED}


@pytest.mark.parametrize(
    "dns",
    [("192.0.2.99",), DNS + ("192.0.2.99",), DNS[:1], ()],
)
def test_dns_change_is_reconfigured(dns):
    assert check(replace(BASE, dns=dns)) == {NETWORK_RECONFIGURED}


def test_dns_reorder_alone_is_not_a_finding():
    assert check(replace(BASE, dns=tuple(reversed(DNS)))) == set()


def test_bssid_change_with_same_ssid_is_possible_evil_twin():
    assert check(replace(BASE, bssid=AP_2)) == {POSSIBLE_EVIL_TWIN}


def test_bssid_change_with_different_ssid_is_not_evil_twin():
    assert check(replace(BASE, ssid="Other", bssid=AP_2)) == set()


@pytest.mark.parametrize(
    "baseline, current",
    [
        (MAC_OS_BASE, MAC_OS_BASE),
        (MAC_OS_BASE, BASE),
        (BASE, MAC_OS_BASE),
        (BASE, replace(BASE, bssid=None)),
        (replace(BASE, bssid=None), replace(BASE, bssid=AP_2)),
        (replace(BASE, ssid=None), replace(BASE, ssid=None, bssid=AP_2)),
    ],
)
def test_evil_twin_skipped_when_ssid_or_bssid_unknown(baseline, current):
    assert findings(baseline, baseline, current) == set()


def test_macos_readings_still_report_the_other_findings():
    current = replace(MAC_OS_BASE, gateway_macs=frozenset({ROGUE_MAC}), dns=("192.0.2.99",))
    assert check(current, baseline=MAC_OS_BASE) == {ARP_SPOOF_SUSPECTED, NETWORK_RECONFIGURED}


def test_disconnected_current_has_no_findings():
    assert check(DISCONNECTED) == set()
    # Even with leftovers that would otherwise trip every check.
    leftovers = Reading(None, frozenset({GW_MAC, ROGUE_MAC}), ("192.0.2.99",), "Cafe", AP_2)
    assert check(leftovers) == set()


def test_everything_at_once():
    current = Reading(GW, frozenset({GW_MAC, ROGUE_MAC}), ("192.0.2.99",), "Cafe", AP_2)
    assert check(current) == detect.ALL_FINDINGS


def test_reading_is_frozen():
    with pytest.raises(AttributeError):
        BASE.gateway = "192.0.2.2"


# --- reading_from -----------------------------------------------------------


class StubBackend:
    def __init__(self, gateway=GW, neighbours=None, dns=DNS, ssid="Cafe", bssid=AP_1):
        self._gateway = gateway
        self._neighbours = neighbours if neighbours is not None else {GW: {GW_MAC}}
        self._dns = list(dns)
        self._ssid = ssid
        self._bssid = bssid

    def gateway(self):
        return self._gateway

    def neighbours(self):
        return self._neighbours

    def dhcp_dns(self):
        return self._dns

    def ssid(self):
        return self._ssid

    def bssid(self):
        return self._bssid


def test_reading_from_collects_the_five_values():
    assert reading_from(StubBackend()) == BASE


def test_reading_from_keeps_only_the_gateways_macs_and_lowercases():
    backend = StubBackend(
        neighbours={GW: {GW_MAC.upper(), ROGUE_MAC}, "192.0.2.7": {"02:00:00:00:00:07"}},
        bssid=AP_1.upper(),
    )
    reading = reading_from(backend)
    assert reading.gateway_macs == frozenset({GW_MAC, ROGUE_MAC})
    assert reading.bssid == AP_1


def test_reading_from_gateway_absent_from_neighbour_table():
    assert reading_from(StubBackend(neighbours={})).gateway_macs == frozenset()


def test_reading_from_disconnected_macos():
    backend = StubBackend(gateway=None, neighbours={GW: {GW_MAC}}, dns=(), ssid=None, bssid=None)
    assert reading_from(backend) == DISCONNECTED


# --- react ------------------------------------------------------------------


def run_checks(sequence, strict=True, strict_on=DEFAULT_STRICT_ON):
    """Feed successive findings through react, as the session loop would."""
    history, out = [], []
    for current in sequence:
        out.append(react(set(current), history, strict, strict_on))
        history.append(set(current))
    return out


def test_no_findings_no_actions():
    assert react(set(), [], True, DEFAULT_STRICT_ON) == []
    assert react(set(), [{ARP_CONFLICT}], True, DEFAULT_STRICT_ON) == []


def test_first_appearance_warns_but_does_not_go_silent():
    assert react({ARP_CONFLICT}, [], True, DEFAULT_STRICT_ON) == [("warn", ARP_CONFLICT)]
    assert react({ARP_CONFLICT}, [set()], True, DEFAULT_STRICT_ON) == [("warn", ARP_CONFLICT)]


@pytest.mark.parametrize("finding", sorted(DEFAULT_STRICT_ON))
def test_second_consecutive_check_goes_silent_without_warning_again(finding):
    assert run_checks([{finding}, {finding}]) == [
        [("warn", finding)],
        [("go_silent", finding)],
    ]


def test_go_silent_and_warn_are_emitted_once_while_finding_persists():
    out = run_checks([{ARP_CONFLICT}] * 5)
    assert out[0] == [("warn", ARP_CONFLICT)]
    assert out[1] == [("go_silent", ARP_CONFLICT)]
    assert out[2:] == [[], [], []]


def test_non_consecutive_sightings_never_go_silent():
    out = run_checks([{ARP_CONFLICT}, set(), {ARP_CONFLICT}, set(), {ARP_CONFLICT}])
    assert out == [
        [("warn", ARP_CONFLICT)],
        [],
        [("warn", ARP_CONFLICT)],
        [],
        [("warn", ARP_CONFLICT)],
    ]


def test_only_the_immediately_previous_check_counts():
    history = [{ARP_CONFLICT}, {ARP_CONFLICT}, set()]
    assert react({ARP_CONFLICT}, history, True, DEFAULT_STRICT_ON) == [("warn", ARP_CONFLICT)]


def test_different_findings_on_consecutive_checks_do_not_combine():
    out = run_checks([{ARP_CONFLICT}, {NETWORK_RECONFIGURED}])
    assert out == [[("warn", ARP_CONFLICT)], [("warn", NETWORK_RECONFIGURED)]]


def test_finding_that_clears_and_returns_reacts_again():
    out = run_checks([{ARP_CONFLICT}, {ARP_CONFLICT}, set(), {ARP_CONFLICT}, {ARP_CONFLICT}])
    assert out == [
        [("warn", ARP_CONFLICT)],
        [("go_silent", ARP_CONFLICT)],
        [],
        [("warn", ARP_CONFLICT)],
        [("go_silent", ARP_CONFLICT)],
    ]


def test_evil_twin_only_warns_by_default():
    out = run_checks([{POSSIBLE_EVIL_TWIN}] * 3)
    assert out == [[("warn", POSSIBLE_EVIL_TWIN)], [], []]


def test_strict_off_only_warns():
    out = run_checks([set(DEFAULT_STRICT_ON)] * 3, strict=False)
    assert out == [[("warn", f) for f in sorted(DEFAULT_STRICT_ON)], [], []]


def test_custom_strict_on_with_evil_twin():
    strict_on = frozenset({POSSIBLE_EVIL_TWIN})
    both = {POSSIBLE_EVIL_TWIN, ARP_CONFLICT}
    out = run_checks([both, both, both], strict_on=strict_on)
    assert out == [
        [("warn", ARP_CONFLICT), ("warn", POSSIBLE_EVIL_TWIN)],
        [("go_silent", POSSIBLE_EVIL_TWIN)],
        [],
    ]


def test_empty_strict_on_never_goes_silent():
    out = run_checks([{ARP_CONFLICT}] * 2, strict_on=frozenset())
    assert out == [[("warn", ARP_CONFLICT)], []]


def test_new_finding_warns_while_older_one_goes_silent():
    out = run_checks([{ARP_CONFLICT}, {ARP_CONFLICT, ARP_SPOOF_SUSPECTED}, {ARP_CONFLICT, ARP_SPOOF_SUSPECTED}])
    assert out == [
        [("warn", ARP_CONFLICT)],
        [("warn", ARP_SPOOF_SUSPECTED), ("go_silent", ARP_CONFLICT)],
        [("go_silent", ARP_SPOOF_SUSPECTED)],
    ]


@pytest.mark.parametrize("strict", [True, False])
def test_unknown_strict_on_name_raises(strict):
    with pytest.raises(ValueError, match="arp_spoofed"):
        react(set(), [], strict, frozenset({ARP_CONFLICT, "arp_spoofed"}))


def test_react_does_not_mutate_its_inputs():
    current, history = {ARP_CONFLICT}, [{ARP_CONFLICT}]
    react(current, history, True, DEFAULT_STRICT_ON)
    assert current == {ARP_CONFLICT}
    assert history == [{ARP_CONFLICT}]


# --- strict_settings --------------------------------------------------------


def test_default_strict_set():
    assert DEFAULT_STRICT_ON == {ARP_SPOOF_SUSPECTED, ARP_CONFLICT, NETWORK_RECONFIGURED}
    assert strict_settings(None, {}) == (True, DEFAULT_STRICT_ON)


@pytest.mark.parametrize(
    "cli, env, expected",
    [
        (None, None, True),
        (None, "1", True),
        (None, "0", False),
        (None, "", True),
        (True, None, True),
        (True, "1", True),
        (True, "0", True),
        (False, None, False),
        (False, "1", False),
        (False, "0", False),
    ],
)
def test_strict_precedence_cli_over_env_over_default(cli, env, expected):
    environ = {} if env is None else {"STRICT": env}
    assert strict_settings(cli, environ) == (expected, DEFAULT_STRICT_ON)


@pytest.mark.parametrize("bad", ["yes", "true", "2", "on"])
def test_strict_env_must_be_0_or_1(bad):
    with pytest.raises(ValueError, match="STRICT"):
        strict_settings(None, {"STRICT": bad})


def test_strict_env_tolerates_whitespace():
    assert strict_settings(None, {"STRICT": " 0 "})[0] is False


def test_strict_on_overrides_the_default_set():
    environ = {"STRICT_ON": "possible_evil_twin"}
    assert strict_settings(None, environ) == (True, frozenset({POSSIBLE_EVIL_TWIN}))


def test_strict_on_is_whitespace_tolerant():
    environ = {"STRICT_ON": "  arp_conflict ,possible_evil_twin\t, ,arp_conflict, "}
    assert strict_settings(None, environ)[1] == {ARP_CONFLICT, POSSIBLE_EVIL_TWIN}


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_blank_strict_on_keeps_the_default(blank):
    assert strict_settings(None, {"STRICT_ON": blank})[1] == DEFAULT_STRICT_ON


def test_strict_on_unknown_name_raises_naming_it():
    with pytest.raises(ValueError, match="evil_twins"):
        strict_settings(None, {"STRICT_ON": "arp_conflict, evil_twins"})


def test_strict_on_is_validated_even_when_strict_is_off():
    with pytest.raises(ValueError, match="nope"):
        strict_settings(False, {"STRICT": "0", "STRICT_ON": "nope"})


@pytest.mark.parametrize(
    "cli, env, expected",
    [(None, "0", False), (None, "1", True), (True, "0", True), (False, "1", False)],
)
def test_strict_on_combines_with_every_switch_source(cli, env, expected):
    environ = {"STRICT": env, "STRICT_ON": "arp_conflict"}
    assert strict_settings(cli, environ) == (expected, frozenset({ARP_CONFLICT}))


def test_strict_settings_does_not_mutate_environ():
    environ = {"STRICT": "0", "STRICT_ON": "arp_conflict"}
    strict_settings(None, environ)
    assert environ == {"STRICT": "0", "STRICT_ON": "arp_conflict"}
