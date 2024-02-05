import pytest

from rotator import mac


@pytest.mark.parametrize("raw, expected", [
    ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
    ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
    ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
    ("  aa:bb:cc:dd:ee:ff\n", "aa:bb:cc:dd:ee:ff"),
])
def test_normalize_accepts(raw, expected):
    assert mac.normalize(raw) == expected


@pytest.mark.parametrize("bad", [
    "aa:bb:cc:dd:ee",        # too short
    "aa:bb:cc:dd:ee:ff:00",  # too long
    "aa:bb:cc:dd:ee:fg",     # non-hex
    "zz-bb-cc-dd-ee-ff",     # non-hex with dashes
    "",                      # empty
    "   ",                   # whitespace only
])
def test_normalize_rejects(bad):
    with pytest.raises(ValueError):
        mac.normalize(bad)


def test_generate_is_unicast_and_locally_administered():
    for _ in range(1000):
        m = mac.generate()
        assert mac.is_unicast(m), m
        assert mac.is_locally_administered(m), m
        assert mac.normalize(m) == m


def test_generate_honours_exclude(monkeypatch):
    excluded = "02:11:22:33:44:55"
    responses = iter([
        bytes([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),  # would produce the excluded address
        bytes([0x06, 0x11, 0x22, 0x33, 0x44, 0x55]),  # a different valid address
    ])
    monkeypatch.setattr(mac.secrets, "token_bytes", lambda n: next(responses))

    assert mac.generate(exclude=excluded) == "06:11:22:33:44:55"
