#!/usr/bin/env python3
"""
RedAudit - Tests for network discovery scan flow.
"""

import builtins
import sys
from types import SimpleNamespace

from redaudit.core import auditor_scan
from redaudit.core.auditor import InteractiveNetworkAuditor


class _DummyHost:
    def state(self):
        return "up"


class _DummyPortScanner:
    def __init__(self):
        self.scanned = False

    def scan(self, hosts=None, arguments=None):
        self.scanned = True
        self.hosts = hosts
        self.arguments = arguments

    def all_hosts(self):
        return ["10.0.0.1"]

    def __getitem__(self, _key):
        return _DummyHost()


class _DummyProgress:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.updated = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def add_task(self, *args, **kwargs):
        return 1

    def update(self, _task, **kwargs):
        self.updated.append(kwargs)


class _DummyActivity:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.entered = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_scan_network_discovery_rich(monkeypatch):
    app = InteractiveNetworkAuditor()
    monkeypatch.setattr(
        auditor_scan,
        "nmap",
        SimpleNamespace(PortScanner=_DummyPortScanner),
    )
    monkeypatch.setattr(auditor_scan, "get_nmap_arguments", lambda *_args, **_kwargs: "-sn")
    monkeypatch.setitem(
        sys.modules,
        "rich.progress",
        SimpleNamespace(Progress=_DummyProgress, SpinnerColumn=object, TimeElapsedColumn=object),
    )

    hosts = app.scan_network_discovery("10.0.0.0/24")
    assert hosts == ["10.0.0.1"]


def test_scan_network_discovery_fallback_activity(monkeypatch):
    app = InteractiveNetworkAuditor()
    monkeypatch.setattr(
        auditor_scan,
        "nmap",
        SimpleNamespace(PortScanner=_DummyPortScanner),
    )
    monkeypatch.setattr(auditor_scan, "get_nmap_arguments", lambda *_args, **_kwargs: "-sn")

    class _FailProgress(_DummyProgress):
        def __enter__(self):
            raise RuntimeError("boom")

    monkeypatch.setitem(
        sys.modules,
        "rich.progress",
        SimpleNamespace(Progress=_FailProgress, SpinnerColumn=object, TimeElapsedColumn=object),
    )

    activity = _DummyActivity()
    monkeypatch.setattr(auditor_scan, "_ActivityIndicator", lambda **_kwargs: activity)

    hosts = app.scan_network_discovery("10.0.0.0/24")
    assert activity.entered is True
    assert hosts == ["10.0.0.1"]


def test_scan_network_discovery_exception(monkeypatch):
    app = InteractiveNetworkAuditor()

    class _FailScanner(_DummyPortScanner):
        def scan(self, hosts=None, arguments=None):
            raise RuntimeError("scan failed")

    monkeypatch.setattr(
        auditor_scan,
        "nmap",
        SimpleNamespace(PortScanner=_FailScanner),
    )
    monkeypatch.setattr(auditor_scan, "get_nmap_arguments", lambda *_args, **_kwargs: "-sn")

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name.startswith("rich"):
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    hosts = app.scan_network_discovery("10.0.0.0/24")
    assert hosts == []
