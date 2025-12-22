#!/usr/bin/env python3
"""
RedAudit - Tests for scanner version helpers.
"""

from types import SimpleNamespace

from redaudit.core import scanner_versions
from redaudit.utils.constants import VERSION


class _DummyRunner:
    def __init__(self, stdout="", stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.calls = []

    def run(self, args, capture_output=True, text=True):
        self.calls.append(args)
        return SimpleNamespace(stdout=self.stdout, stderr=self.stderr)


def test_get_tool_version_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr(scanner_versions.shutil, "which", lambda _name: None)
    version = scanner_versions._get_tool_version(
        "nmap", scanner_versions.TOOL_CONFIGS["nmap"]
    )
    assert version is None


def test_get_tool_version_parses_version(monkeypatch):
    runner = _DummyRunner(stdout="Nmap version 7.93")
    monkeypatch.setattr(scanner_versions.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(scanner_versions, "CommandRunner", lambda **_kwargs: runner)

    version = scanner_versions._get_tool_version(
        "nmap", scanner_versions.TOOL_CONFIGS["nmap"]
    )

    assert version == "7.93"
    assert runner.calls


def test_get_tool_version_returns_detected_on_no_match(monkeypatch):
    runner = _DummyRunner(stdout="unknown output")
    monkeypatch.setattr(scanner_versions.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(scanner_versions, "CommandRunner", lambda **_kwargs: runner)

    version = scanner_versions._get_tool_version(
        "nmap", scanner_versions.TOOL_CONFIGS["nmap"]
    )

    assert version == "detected"


def test_get_tool_version_returns_detected_on_exception(monkeypatch):
    monkeypatch.setattr(scanner_versions.shutil, "which", lambda _name: "/usr/bin/nmap")

    def _boom(**_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner_versions, "CommandRunner", _boom)

    version = scanner_versions._get_tool_version(
        "nmap", scanner_versions.TOOL_CONFIGS["nmap"]
    )

    assert version == "detected"


def test_get_scanner_versions_uses_tool_config(monkeypatch):
    configs = {
        "nmap": {"names": ["nmap"], "version_args": ["--version"], "pattern": r"nmap"}
    }
    monkeypatch.setattr(scanner_versions, "TOOL_CONFIGS", configs)

    def _fake_get(tool_name, _config):
        return "1.2.3" if tool_name == "nmap" else None

    monkeypatch.setattr(scanner_versions, "_get_tool_version", _fake_get)

    versions = scanner_versions.get_scanner_versions()

    assert versions["redaudit"] == VERSION
    assert versions["nmap"] == "1.2.3"
