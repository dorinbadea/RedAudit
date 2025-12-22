#!/usr/bin/env python3
"""
RedAudit - Tests for scan_hosts_concurrent rich progress path.
"""

import sys
from contextlib import contextmanager
from types import SimpleNamespace

from redaudit.core.auditor import InteractiveNetworkAuditor


@contextmanager
def _noop_cm():
    yield


class _DummyProgress:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def add_task(self, *_args, **_kwargs):
        return 1

    def update(self, *_args, **_kwargs):
        return None


def test_scan_hosts_concurrent_uses_rich_progress(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["threads"] = 1
    app.rate_limit_delay = 0.0

    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_progress_columns", lambda **_kwargs: ())
    monkeypatch.setattr(app, "_progress_console", lambda: None)
    monkeypatch.setattr(app, "_get_ui_detail", lambda: "")
    monkeypatch.setattr(app, "scan_host_ports", lambda host: {"ip": host, "status": "up"})

    previous = sys.modules.get("rich.progress")
    sys.modules["rich.progress"] = SimpleNamespace(Progress=_DummyProgress)
    try:
        results = app.scan_hosts_concurrent(["10.0.0.1"])
    finally:
        if previous is None:
            sys.modules.pop("rich.progress", None)
        else:
            sys.modules["rich.progress"] = previous

    assert results == [{"ip": "10.0.0.1", "status": "up"}]
