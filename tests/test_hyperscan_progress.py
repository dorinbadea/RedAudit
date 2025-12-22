#!/usr/bin/env python3
"""
RedAudit - Tests for hyperscan progress helpers.
"""

import builtins
import sys
import shutil
from types import SimpleNamespace

from redaudit.core import hyperscan


class _DummyProgress:
    instances = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.updates = []
        _DummyProgress.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def add_task(self, *args, **kwargs):
        self.task_args = args
        self.task_kwargs = kwargs
        return 1

    def update(self, task_id, **kwargs):
        self.updates.append(kwargs)


class _DummyColumn:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class _DummyConsole:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def test_hyperscan_with_progress_rich(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "rich.progress",
        SimpleNamespace(
            Progress=_DummyProgress,
            SpinnerColumn=_DummyColumn,
            BarColumn=_DummyColumn,
            TextColumn=_DummyColumn,
            TimeElapsedColumn=_DummyColumn,
        ),
    )
    monkeypatch.setitem(sys.modules, "rich.console", SimpleNamespace(Console=_DummyConsole))

    def _fake_full_discovery(networks, logger=None, dry_run=None, progress_callback=None):
        if progress_callback:
            progress_callback(5, 10, "half")
        return {"ok": True}

    monkeypatch.setattr(hyperscan, "hyperscan_full_discovery", _fake_full_discovery)

    result = hyperscan.hyperscan_with_progress(["10.0.0.0/24"])
    assert result == {"ok": True}

    progress = _DummyProgress.instances[-1]
    assert any(update.get("completed") == 100 for update in progress.updates)


def test_hyperscan_with_progress_fallback(monkeypatch):
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name.startswith("rich"):
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    called = {}

    def _fake_full_discovery(networks, logger=None, dry_run=None, progress_callback=None):
        called["networks"] = networks
        return {"fallback": True}

    monkeypatch.setattr(hyperscan, "hyperscan_full_discovery", _fake_full_discovery)

    result = hyperscan.hyperscan_with_progress(["10.0.0.0/24"])
    assert result == {"fallback": True}
    assert called["networks"] == ["10.0.0.0/24"]


def test_hyperscan_with_nmap_enrichment(monkeypatch):
    discovery = {"tcp_hosts": {"10.0.0.1": [22, 80]}}

    def _fake_runner(*_args, **_kwargs):
        output = "22/tcp open ssh\n80/tcp open http\n"
        return SimpleNamespace(run=lambda *_a, **_kw: SimpleNamespace(stdout=output))

    monkeypatch.setattr(hyperscan, "_make_runner", lambda *a, **k: _fake_runner())
    monkeypatch.setattr(shutil, "which", lambda _name: "nmap")
    monkeypatch.setattr(
        hyperscan,
        "detect_potential_backdoors",
        lambda *_args, **_kwargs: [{"ip": "10.0.0.1", "port": 22, "reason": "test"}],
    )

    enriched = hyperscan.hyperscan_with_nmap_enrichment(discovery, extra_tools={})
    assert enriched["service_info"]["10.0.0.1"][22] == "ssh"
    assert enriched["potential_backdoors"][0]["port"] == 22


def test_hyperscan_with_nmap_enrichment_no_nmap(monkeypatch):
    discovery = {"tcp_hosts": {"10.0.0.1": [22]}}
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert hyperscan.hyperscan_with_nmap_enrichment(discovery, extra_tools={}) == discovery
