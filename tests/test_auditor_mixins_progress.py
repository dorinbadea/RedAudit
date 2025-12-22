#!/usr/bin/env python3
"""
RedAudit - Tests for auditor mixins progress helpers.
"""

import builtins
import sys
from types import SimpleNamespace

from redaudit.core.auditor import InteractiveNetworkAuditor


class _DummyTextColumn:
    attempted_overflow = False

    def __init__(self, *args, **kwargs):
        if "overflow" in kwargs:
            _DummyTextColumn.attempted_overflow = True
            raise TypeError("unsupported")
        self.args = args
        self.kwargs = kwargs


class _DummyBarColumn:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class _DummyTimeElapsedColumn:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class _DummyConsole:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def test_progress_columns_and_safe_text(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "rich.progress",
        SimpleNamespace(
            TextColumn=_DummyTextColumn,
            BarColumn=_DummyBarColumn,
            TimeElapsedColumn=_DummyTimeElapsedColumn,
        ),
    )

    app = InteractiveNetworkAuditor()
    monkeypatch.setattr(app, "_terminal_width", lambda *_args, **_kwargs: 100)

    columns = app._progress_columns(show_detail=True, show_eta=True, show_elapsed=True)
    assert any(isinstance(col, _DummyBarColumn) for col in columns)
    assert any(isinstance(col, _DummyTimeElapsedColumn) for col in columns)
    assert any(isinstance(col, _DummyTextColumn) for col in columns)
    assert _DummyTextColumn.attempted_overflow is True


def test_progress_console_fallback(monkeypatch):
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.console":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    app = InteractiveNetworkAuditor()
    assert app._progress_console() is None


def test_progress_console_with_rich(monkeypatch):
    monkeypatch.setitem(sys.modules, "rich.console", SimpleNamespace(Console=_DummyConsole))
    app = InteractiveNetworkAuditor()
    console = app._progress_console()
    assert isinstance(console, _DummyConsole)


def test_progress_ui_context_toggles():
    app = InteractiveNetworkAuditor()
    assert app._ui_progress_active is False
    with app._progress_ui():
        assert app._ui_progress_active is True
    assert app._ui_progress_active is False


def test_format_and_get_ui_detail(monkeypatch):
    app = InteractiveNetworkAuditor()
    formatted = app._format_ui_detail("hello", "WARN")
    assert formatted.startswith("[yellow]")

    app._ui_detail = "custom"
    assert app._get_ui_detail() == "custom"

    app._ui_detail = ""
    app.current_phase = "vulns:nikto:10.0.0.1"
    assert app._get_ui_detail() == "nikto 10.0.0.1"
