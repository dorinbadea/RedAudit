#!/usr/bin/env python3
"""
RedAudit - Tests for wizard UI helpers.
"""

import os
from types import SimpleNamespace

from unittest.mock import patch

from redaudit.core.wizard import Wizard


class _DummyWizard(Wizard):
    def __init__(self):
        self.lang = "en"
        self.config = {}
        from unittest.mock import MagicMock

        self.ui = MagicMock()
        self.ui.colors = {
            "FAIL": "",
            "BOLD": "",
            "HEADER": "",
            "ENDC": "",
            "CYAN": "",
            "OKBLUE": "",
            "WARNING": "",
            "OKGREEN": "",
        }
        self.ui.t.side_effect = lambda k, *a: f"{k}:{','.join(str(s) for s in a)}" if a else str(k)
        self._messages = []

    def t(self, key, *args):
        # Kept for compatibility if Wizard uses self.t
        if args:
            return f"{key}:{','.join(str(a) for a in args)}"
        return key

    def print_status(self, message, _level="INFO"):
        self._messages.append(message)

    def signal_handler(self, *_args, **_kwargs):
        return None


def test_clear_screen_respects_dry_run():
    wiz = _DummyWizard()
    wiz.config["dry_run"] = True
    with patch("os.system") as mocked:
        wiz.clear_screen()
    mocked.assert_not_called()

    wiz.config["dry_run"] = False
    with patch("os.system") as mocked:
        wiz.clear_screen()
    mocked.assert_called_once()


def test_use_arrow_menu_flags(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    assert wiz._use_arrow_menu() is True

    monkeypatch.setenv("REDAUDIT_BASIC_PROMPTS", "1")
    assert wiz._use_arrow_menu() is False

    monkeypatch.delenv("REDAUDIT_BASIC_PROMPTS", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert wiz._use_arrow_menu() is False


def test_strip_and_truncate_menu_text():
    wiz = _DummyWizard()
    text = "\x1b[31mHello World\x1b[0m"
    assert wiz._strip_ansi(text) == "Hello World"
    truncated = wiz._truncate_menu_text(text, 5)
    assert truncated.endswith("...")


def test_menu_width_fallbacks(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(
        "redaudit.core.wizard.shutil",
        SimpleNamespace(get_terminal_size=lambda *args, **kwargs: os.terminal_size((1, 20))),
    )
    assert wiz._menu_width() == 1

    def _boom(*_args, **_kwargs):
        raise OSError("no tty")

    monkeypatch.setattr("redaudit.core.wizard.shutil", SimpleNamespace(get_terminal_size=_boom))
    assert wiz._menu_width() == 79


def test_truncate_menu_text_zero_width():
    wiz = _DummyWizard()
    assert wiz._truncate_menu_text("Hello", 0) == ""


def test_format_menu_option_colors():
    wiz = _DummyWizard()
    wiz.ui.colors["OKGREEN"] = "<G>"
    wiz.ui.colors["ENDC"] = "<E>"
    assert wiz._format_menu_option(wiz.t("yes_default")) == "<G>yes_default<E>"

    colored = "\x1b[31mAlready colored\x1b[0m"
    assert wiz._format_menu_option(colored) == colored


def test_show_main_menu_text(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: "2")
    assert wiz.show_main_menu() == 2


def test_show_main_menu_arrow(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)
    monkeypatch.setattr(wiz, "_arrow_menu", lambda *_args, **_kwargs: 2)
    assert wiz.show_main_menu() == 3


def test_ask_yes_no_defaults(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: "")
    assert wiz.ask_yes_no("q", default="yes") is True
    assert wiz.ask_yes_no("q", default="no") is False


def test_ask_number_and_choice(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)

    inputs = iter(["9999", "5"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(inputs))
    result = wiz.ask_number("q", default=10, min_val=1, max_val=100)
    assert result == 5

    inputs = iter(["", "2"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(inputs))
    assert wiz.ask_choice("q", ["a", "b"], default=1) == 1


def test_ask_choice_with_back(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    inputs = iter(["0"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(inputs))
    assert (
        wiz.ask_choice_with_back("q", ["a", "b"], default=0, step_num=2, total_steps=3)
        == wiz.WIZARD_BACK
    )


def test_ask_manual_network(monkeypatch):
    wiz = _DummyWizard()
    inputs = iter(["bad", "10.0.0.0/24"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(inputs))
    assert wiz.ask_manual_network() == "10.0.0.0/24"
