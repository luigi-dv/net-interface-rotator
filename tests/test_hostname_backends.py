import pytest

from rotator.backends import linux, macos
from rotator.backends.linux import LinuxBackend
from rotator.backends.macos import MacOSBackend


class FakeRun:
    """Stands in for rotator.backends.*.run: canned output per argument tuple."""

    def __init__(self, responses: dict[tuple, str]):
        self.responses = responses
        self.calls: list[tuple] = []

    def __call__(self, *args: str, check: bool = True) -> str:
        self.calls.append(args)
        return self.responses.get(args, "")


def test_macos_get_hostname_reports_unset_as_none(monkeypatch):
    fake = FakeRun({
        ("scutil", "--get", "ComputerName"): "Luigi's Mac\n",
        ("scutil", "--get", "LocalHostName"): "Luigis-Mac\n",
        ("scutil", "--get", "HostName"): "HostName: not set\n",
    })
    monkeypatch.setattr(macos, "run", fake)

    names = MacOSBackend("en0").get_hostname()

    assert names == {"ComputerName": "Luigi's Mac", "LocalHostName": "Luigis-Mac", "HostName": None}
    assert all(c[:2] == ("scutil", "--get") for c in fake.calls)


def test_macos_set_hostname_skips_none_and_uses_argument_lists(monkeypatch):
    fake = FakeRun({})
    monkeypatch.setattr(macos, "run", fake)

    MacOSBackend("en0").set_hostname({"ComputerName": "MacBook-Air", "LocalHostName": None,
                                      "HostName": "iPad"})

    assert fake.calls == [
        ("scutil", "--set", "ComputerName", "MacBook-Air"),
        ("scutil", "--set", "HostName", "iPad"),
    ]


def test_linux_get_hostname_reads_proc_path(monkeypatch, tmp_path):
    path = tmp_path / "hostname"
    path.write_text("box-1\n")
    monkeypatch.setattr(linux, "HOSTNAME_PATH", path)

    assert LinuxBackend("eth0").get_hostname() == {"transient": "box-1"}


def test_linux_set_hostname_skips_none_and_uses_hostnamectl(monkeypatch):
    fake = FakeRun({})
    monkeypatch.setattr(linux, "run", fake)

    LinuxBackend("eth0").set_hostname({"transient": "iPhone"})
    LinuxBackend("eth0").set_hostname({"transient": None})

    assert fake.calls == [("hostnamectl", "set-hostname", "--transient", "iPhone")]
