#!/usr/bin/env python3
"""
Coverage for interactive update flow.
"""

import pytest
from unittest.mock import patch

from redaudit.core import updater


def test_interactive_update_no_latest_version(monkeypatch):
    monkeypatch.setattr(
        updater,
        "check_for_updates",
        lambda **_kwargs: (False, None, None, None, None, None),
    )
    messages = []
    result = updater.interactive_update_check(print_fn=lambda msg, *_a: messages.append(msg))
    assert result is False
    assert "update_check_failed" in messages[-1]


def test_interactive_update_current(monkeypatch):
    monkeypatch.setattr(
        updater,
        "check_for_updates",
        lambda **_kwargs: (False, "3.0.0", None, None, None, None),
    )
    messages = []
    result = updater.interactive_update_check(print_fn=lambda msg, *_a: messages.append(msg))
    assert result is False
    assert "update_current" in messages[-1]


def test_interactive_update_skipped(monkeypatch):
    monkeypatch.setattr(
        updater,
        "check_for_updates",
        lambda **_kwargs: (True, "3.0.1", "", "", "", None),
    )
    messages = []
    result = updater.interactive_update_check(
        print_fn=lambda msg, *_a: messages.append(msg), ask_fn=lambda *_a, **_k: False
    )
    assert result is False
    assert "update_skipped" in messages[-1]


def test_interactive_update_failed(monkeypatch):
    monkeypatch.setattr(
        updater,
        "check_for_updates",
        lambda **_kwargs: (True, "3.0.1", "", "", "", None),
    )
    monkeypatch.setattr(updater, "perform_git_update", lambda *_a, **_k: (False, "boom"))
    messages = []
    result = updater.interactive_update_check(
        print_fn=lambda msg, *_a: messages.append(msg), ask_fn=lambda *_a, **_k: True
    )
    assert result is False
    assert "boom" in messages[-1]


def test_interactive_update_success_exits(monkeypatch):
    monkeypatch.setattr(
        updater,
        "check_for_updates",
        lambda **_kwargs: (True, "3.0.1", "", "", "", None),
    )
    monkeypatch.setattr(updater, "perform_git_update", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(updater, "_show_restart_terminal_notice", lambda **_k: None)
    monkeypatch.setattr(updater, "_pause_for_restart_terminal", lambda **_k: None)

    with pytest.raises(SystemExit) as exc:
        updater.interactive_update_check(ask_fn=lambda *_a, **_k: True)
    assert exc.value.code == 0


def test_interactive_update_summary_prints(monkeypatch):
    monkeypatch.setattr(
        updater,
        "check_for_updates",
        lambda **_kwargs: (True, "3.0.1", "notes", "url", "2025-01-01", "en"),
    )
    monkeypatch.setattr(updater, "render_update_summary_for_cli", lambda **_k: "Summary")

    printed = []

    def _fake_print(*args, **_kwargs):
        printed.append(" ".join(str(a) for a in args))

    monkeypatch.setattr("builtins.print", _fake_print)
    monkeypatch.setattr(updater.sys.stdout, "isatty", lambda: True)
    with patch("shutil.get_terminal_size", side_effect=OSError("no tty")):
        result = updater.interactive_update_check(
            print_fn=lambda *_a, **_k: None,
            ask_fn=lambda *_a, **_k: False,
            t_fn=lambda key, *args: key,
        )
    assert result is False
    assert any("Summary" in line for line in printed)
