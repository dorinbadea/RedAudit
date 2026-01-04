#!/usr/bin/env python3
"""
Coverage for wizard banner and menu helpers.
"""

from __future__ import annotations

import sys

from redaudit.core.wizard import Wizard


class _DummyWizard(Wizard):
    def __init__(self):
        self.lang = "en"
        self.config = {"dry_run": False}
        from unittest.mock import MagicMock

        self.ui = MagicMock()
        self.ui.colors = {
            "FAIL": "",
            "BOLD": "",
            "HEADER": "",
            "ENDC": "",
            "CYAN": "",
            "OKBLUE": "",
            "OKGREEN": "",
            "WARNING": "",
        }
        # Ensure self.ui.t returns a string
        self.ui.t.side_effect = lambda k, *a: str(k) if k != "banner_subtitle" else "Subtitle"

    def t(self, key, *_args):
        # Kept for compatibility if Wizard uses self.t
        if key == "banner_subtitle":
            return "Subtitle"
        return key


def test_print_banner_outputs_subtitle(capsys):
    wiz = _DummyWizard()

    wiz.print_banner()

    captured = capsys.readouterr().out
    assert "Subtitle" in captured


def test_use_arrow_menu_respects_tty_and_env(monkeypatch):
    wiz = _DummyWizard()

    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert wiz._use_arrow_menu() is False

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("REDAUDIT_BASIC_PROMPTS", "1")
    assert wiz._use_arrow_menu() is False

    monkeypatch.delenv("REDAUDIT_BASIC_PROMPTS", raising=False)
    assert wiz._use_arrow_menu() is True


def test_read_key_returns_empty_on_termios_failure(monkeypatch):
    import termios

    wiz = _DummyWizard()

    def _raise_runtime_error(*_args, **_kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(termios, "tcgetattr", _raise_runtime_error)

    assert wiz._read_key() == ""
