import re

from rotator import identity

PATTERN = re.compile(r"^[A-Za-z0-9-]{1,63}$")


def test_random_hostname_is_valid_and_bland():
    for _ in range(500):
        name = identity.random_hostname()
        assert PATTERN.match(name), name
        assert name in {"MacBook-Air", "MacBook-Pro", "iPhone", "iPad"} or (
            name.startswith("DESKTOP-") and len(name) == len("DESKTOP-") + 7
        ), name


def test_randomized_keeps_keys_and_none():
    out = identity.randomized({"ComputerName": "Real Mac", "LocalHostName": "Real-Mac",
                               "HostName": None})
    assert set(out) == {"ComputerName", "LocalHostName", "HostName"}
    assert out["HostName"] is None
    assert out["ComputerName"] is not None and out["LocalHostName"] is not None


def test_randomized_never_returns_original(monkeypatch):
    original = "iPhone"
    draws = iter([original, "MacBook-Pro"])
    monkeypatch.setattr(identity, "random_hostname", lambda: next(draws))

    out = identity.randomized({"LocalHostName": original})

    assert out == {"LocalHostName": "MacBook-Pro"}


def test_randomized_never_equals_original_over_many_runs():
    for _ in range(500):
        out = identity.randomized({"ComputerName": "iPad"})
        assert out["ComputerName"] != "iPad"
