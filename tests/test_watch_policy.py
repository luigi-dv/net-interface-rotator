"""Tests for the watch decision, `rotator.cli.next_action`.

The function is pure, so nothing here touches a backend, the clock or the network.
"""
import pytest

from rotator.cli import next_action

COOLDOWN = 30
T0 = 1000.0  # time of the last rotation, in monotonic seconds


def act(prev, network, elapsed, interval=0, cooldown=COOLDOWN):
    return next_action(prev, network, T0 + elapsed, T0, interval, cooldown)


# --- disconnect ---------------------------------------------------------------

def test_disconnect_rotates_once_settled():
    assert act("cafe", None, 60) == "Disconnected"


def test_disconnect_reported_as_empty_string_also_rotates():
    assert act("cafe", "", 60) == "Disconnected"


def test_disconnect_suppressed_during_cooldown():
    assert act("cafe", None, 29.9) is None


def test_disconnect_fires_exactly_at_cooldown():
    assert act("cafe", None, COOLDOWN) == "Disconnected"


def test_disconnect_fires_with_zero_cooldown():
    assert act("cafe", None, 0, cooldown=0) == "Disconnected"


# --- network change -----------------------------------------------------------

def test_network_change_rotates_once_settled():
    assert act("cafe", "airport", 60) == "Network changed to airport"


def test_network_change_suppressed_during_cooldown():
    assert act("cafe", "airport", 29.9) is None


def test_network_change_fires_exactly_at_cooldown():
    assert act("cafe", "airport", COOLDOWN) == "Network changed to airport"


def test_same_network_does_not_rotate():
    assert act("cafe", "cafe", 60) is None


# --- nothing to react to ------------------------------------------------------

def test_startup_while_disconnected_does_not_rotate():
    assert act(None, None, 60) is None


def test_reconnect_from_none_does_not_rotate():
    # The rotation already happened on disconnect; joining must not trigger another.
    assert act(None, "airport", 60) is None


def test_reconnect_from_none_during_cooldown_does_not_rotate():
    assert act(None, "airport", 5) is None


# --- interval -----------------------------------------------------------------

def test_interval_zero_never_fires():
    assert act("cafe", "cafe", 10**9, interval=0) is None


def test_interval_not_yet_elapsed():
    assert act("cafe", "cafe", 299.9, interval=300) is None


def test_interval_fires_exactly_at_interval():
    assert act("cafe", "cafe", 300, interval=300) == "Interval elapsed"


def test_interval_fires_after_interval():
    assert act("cafe", "cafe", 301, interval=300) == "Interval elapsed"


def test_interval_fires_while_disconnected():
    assert act(None, None, 300, interval=300) == "Interval elapsed"


def test_interval_fires_on_reconnect_from_none():
    assert act(None, "airport", 300, interval=300) == "Interval elapsed"


def test_cooldown_does_not_block_interval_when_interval_equals_cooldown():
    assert act("cafe", "cafe", COOLDOWN, interval=COOLDOWN) == "Interval elapsed"


def test_cooldown_does_not_delay_interval_longer_than_cooldown():
    assert act("cafe", "cafe", 59.9, interval=60) is None
    assert act("cafe", "cafe", 60, interval=60) == "Interval elapsed"


def test_interval_shorter_than_cooldown_waits_for_cooldown():
    assert act("cafe", "cafe", 10, interval=5) is None
    assert act("cafe", "cafe", 29.9, interval=5) is None
    assert act("cafe", "cafe", COOLDOWN, interval=5) == "Interval elapsed"


# --- precedence ---------------------------------------------------------------

def test_disconnect_takes_precedence_over_interval():
    assert act("cafe", None, 300, interval=300) == "Disconnected"


def test_network_change_takes_precedence_over_interval():
    assert act("cafe", "airport", 300, interval=300) == "Network changed to airport"


@pytest.mark.parametrize("network", [None, "airport"])
def test_no_trigger_fires_during_cooldown_even_with_interval(network):
    assert act("cafe", network, 29.9, interval=5) is None


# --- startup initialisation used by cmd_watch -----------------------------------

def test_startup_seed_lets_first_poll_react_but_not_fire_interval():
    # cmd_watch seeds last_rotation = now - cooldown when not rotating at startup.
    now = 500.0
    seeded = now - COOLDOWN
    poll = 3
    assert next_action("cafe", None, now + poll, seeded, 300, COOLDOWN) == "Disconnected"
    assert next_action("cafe", "cafe", now + poll, seeded, 300, COOLDOWN) is None


def test_only_elapsed_time_matters():
    assert next_action("cafe", None, 60, 0, 0, COOLDOWN) == next_action(
        "cafe", None, 10**6 + 60, 10**6, 0, COOLDOWN
    )
