#!/usr/bin/env python3
"""
Consolidated tests for wizard flows, prompts, and UI helpers.
"""

from __future__ import annotations

import io
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest

from redaudit import InteractiveNetworkAuditor
from redaudit.core.wizard import Wizard
from redaudit.utils.constants import (
    DEFAULT_THREADS,
    MAX_CIDR_LENGTH,
    UDP_SCAN_MODE_QUICK,
    UDP_TOP_PORTS,
)


class _TextWizard(Wizard):
    def __init__(self):
        self.lang = "en"
        self.config = {"dry_run": False}
        self.COLORS = {
            "ENDC": "",
            "OKBLUE": "",
            "CYAN": "",
            "BOLD": "",
            "HEADER": "",
            "FAIL": "",
            "OKGREEN": "",
            "WARNING": "",
        }
        self._messages = []
        self.rate_limit_delay = 0.0
        # v4.0 UI composition support
        self.colors = self.COLORS
        self.ui = self

    def t(self, key, *args):
        return key.format(*args) if args else key

    def print_status(self, message, status="INFO", update_activity=True, *, force=False):
        self._messages.append((status, message, force))

    def signal_handler(self, *_args):
        self._messages.append(("signal", "called", False))


class _UIWizard(Wizard):
    def __init__(self):
        self.lang = "en"
        self.config = {}
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
        if args:
            return f"{key}:{','.join(str(a) for a in args)}"
        return key

    def print_status(self, message, _level="INFO"):
        self._messages.append(message)

    def signal_handler(self, *_args, **_kwargs):
        return None


def _set_inputs(monkeypatch, values):
    it = iter(values)
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(it))


# --- Arrow menu helpers ---


def test_arrow_menu_moves_down_and_selects(monkeypatch):
    wiz = _UIWizard()
    keys = iter(["down", "enter"])

    monkeypatch.setattr(wiz, "_read_key", lambda: next(keys))
    monkeypatch.setattr(wiz, "_menu_width", lambda: 80)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    choice = wiz._arrow_menu("q", ["one", "two"], default=0)
    assert choice == 1


def test_arrow_menu_digit_select(monkeypatch):
    wiz = _UIWizard()
    keys = iter(["2"])

    monkeypatch.setattr(wiz, "_read_key", lambda: next(keys))
    monkeypatch.setattr(wiz, "_menu_width", lambda: 80)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    choice = wiz._arrow_menu("q", ["one", "two"], default=0)
    assert choice == 1


def test_arrow_menu_esc_returns_current(monkeypatch):
    wiz = _UIWizard()
    keys = iter(["esc"])

    monkeypatch.setattr(wiz, "_read_key", lambda: next(keys))
    monkeypatch.setattr(wiz, "_menu_width", lambda: 80)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    choice = wiz._arrow_menu("q", ["one", "two"], default=1)
    assert choice == 1


def test_arrow_menu_empty_options_returns_zero():
    wiz = _UIWizard()
    assert wiz._arrow_menu("q", [], default=0) == 0


def test_arrow_menu_header_and_up_wrap(monkeypatch):
    wiz = _UIWizard()
    keys = iter(["up", "enter"])

    monkeypatch.setattr(wiz, "_read_key", lambda: next(keys))
    monkeypatch.setattr(wiz, "_menu_width", lambda: 80)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    choice = wiz._arrow_menu("q", ["one", "two"], default=0, header="Header")
    assert choice == 1


def test_arrow_menu_skips_empty_key(monkeypatch):
    wiz = _UIWizard()
    keys = iter(["", "enter"])

    monkeypatch.setattr(wiz, "_read_key", lambda: next(keys))
    monkeypatch.setattr(wiz, "_menu_width", lambda: 80)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    choice = wiz._arrow_menu("q", ["one", "two"], default=0)
    assert choice == 0


# --- Flow and prompt helpers ---


def test_show_main_menu_text(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["2"])
    assert wiz.show_main_menu() == 2


def test_show_main_menu_arrow(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)

    def fake_arrow_menu(*_args, **_kwargs):
        return 2

    monkeypatch.setattr(wiz, "_arrow_menu", fake_arrow_menu)
    assert wiz.show_main_menu() == 3


def test_show_main_menu_invalid_then_valid(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["bad", "1"])
    assert wiz.show_main_menu() == 1
    assert any(msg[1] == "menu_invalid_option" for msg in wiz._messages)


def test_show_main_menu_keyboard_interrupt(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)

    def _raise(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _raise)
    assert wiz.show_main_menu() == 0


def test_show_legal_warning(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: True)
    assert wiz.show_legal_warning() is True


def test_ask_yes_no_defaults_and_invalid(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["maybe", "n"])
    assert wiz.ask_yes_no("question", default="yes") is False
    _set_inputs(monkeypatch, [""])
    assert wiz.ask_yes_no("question", default="yes") is True


def test_ask_yes_no_arrow_menu(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)
    monkeypatch.setattr(wiz, "_arrow_menu", lambda *_args, **_kwargs: 1)
    assert wiz.ask_yes_no("question", default="yes") is False


def test_ask_yes_no_arrow_menu_exception_fallback(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(wiz, "_arrow_menu", _boom)
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: "")
    assert wiz.ask_yes_no("question", default="yes") is True


def test_ask_yes_no_keyboard_interrupt(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    wiz.signal_handler = MagicMock()

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _boom)
    with pytest.raises(SystemExit):
        wiz.ask_yes_no("question", default="yes")
    assert wiz.signal_handler.called


def test_ask_number_all(monkeypatch):
    wiz = _TextWizard()
    _set_inputs(monkeypatch, ["all"])
    assert wiz.ask_number("threads", default=10, min_val=1, max_val=100) == "all"


def test_ask_number_default_all_string(monkeypatch):
    wiz = _TextWizard()
    wiz.lang = "es"
    _set_inputs(monkeypatch, [""])
    assert wiz.ask_number("threads", default="all", min_val=1, max_val=100) == "all"


def test_ask_choice_with_back(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["0"])
    assert (
        wiz.ask_choice_with_back("pick", ["a", "b"], default=0, step_num=2, total_steps=3)
        == wiz.WIZARD_BACK
    )
    _set_inputs(monkeypatch, ["2"])
    assert wiz.ask_choice_with_back("pick", ["a", "b"], default=0, step_num=1, total_steps=3) == 1


def test_ask_choice_with_back_arrow_menu(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)
    monkeypatch.setattr(wiz, "_arrow_menu", lambda *_args, **_kwargs: 2)
    assert (
        wiz.ask_choice_with_back("pick", ["a", "b"], default=0, step_num=2, total_steps=3)
        == wiz.WIZARD_BACK
    )


def test_ask_choice_with_back_arrow_menu_returns_selection(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)
    monkeypatch.setattr(wiz, "_arrow_menu", lambda *_args, **_kwargs: 1)
    assert wiz.ask_choice_with_back("pick", ["a", "b"], default=0, step_num=2, total_steps=3) == 1


def test_ask_choice_with_back_arrow_menu_exception(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(wiz, "_arrow_menu", _boom)
    _set_inputs(monkeypatch, [""])
    assert wiz.ask_choice_with_back("pick", ["a", "b"], default=1, step_num=1, total_steps=3) == 1


def test_ask_choice_with_back_numeric_back(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["3"])
    assert (
        wiz.ask_choice_with_back("pick", ["a", "b"], default=0, step_num=2, total_steps=3)
        == wiz.WIZARD_BACK
    )


def test_ask_choice_with_back_invalid_input_continues(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["bad", "1"])
    assert wiz.ask_choice_with_back("pick", ["a", "b"], default=0, step_num=1, total_steps=3) == 0


def test_ask_choice_invalid_then_valid(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["invalid", "99", "1"])
    result = wiz.ask_choice("Pick", ["A", "B", "C"], default=0)
    assert result == 0


def test_ask_choice_arrow_menu(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)
    monkeypatch.setattr(wiz, "_arrow_menu", lambda *_args, **_kwargs: 1)
    assert wiz.ask_choice("Pick", ["A", "B"], default=0) == 1


def test_ask_choice_arrow_menu_exception_fallback(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: True)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(wiz, "_arrow_menu", _boom)
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: "")
    assert wiz.ask_choice("Pick", ["A", "B"], default=0) == 0


def test_ask_number_with_range(monkeypatch):
    wiz = _TextWizard()
    _set_inputs(monkeypatch, ["999", "abc", "5"])
    result = wiz.ask_number("threads", default=10, min_val=1, max_val=100)
    assert result == 5


def test_ask_number_default(monkeypatch):
    wiz = _TextWizard()
    _set_inputs(monkeypatch, [""])
    result = wiz.ask_number("threads", default=10, min_val=1, max_val=100)
    assert result == 10


def test_ask_number_keyboard_interrupt(monkeypatch):
    wiz = _TextWizard()
    wiz.signal_handler = MagicMock()

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _boom)
    with pytest.raises(SystemExit):
        wiz.ask_number("threads", default=10, min_val=1, max_val=100)
    assert wiz.signal_handler.called


def test_ask_manual_network_validation(monkeypatch):
    wiz = _TextWizard()
    _set_inputs(monkeypatch, ["bad", "10.0.0.0/24"])
    assert wiz.ask_manual_network() == ["10.0.0.0/24"]


def test_ask_manual_network_too_long(monkeypatch):
    wiz = _TextWizard()
    long_input = "a" * (MAX_CIDR_LENGTH + 1)
    _set_inputs(monkeypatch, [long_input, "10.0.0.0/24"])
    assert wiz.ask_manual_network() == ["10.0.0.0/24"]


def test_apply_run_defaults():
    wiz = _TextWizard()
    defaults = {
        "scan_mode": "full",
        "threads": DEFAULT_THREADS + 1,
        "rate_limit": -1,
        "scan_vulnerabilities": False,
        "cve_lookup_enabled": True,
        "output_dir": "~/Reports",
        "generate_txt": False,
        "generate_html": False,
        "udp_mode": UDP_SCAN_MODE_QUICK,
        "udp_top_ports": UDP_TOP_PORTS,
        "topology_enabled": True,
        "topology_only": True,
    }
    wiz._apply_run_defaults(defaults)
    assert wiz.config["scan_mode"] == "full"
    assert wiz.config["threads"] == DEFAULT_THREADS + 1
    assert wiz.config["scan_vulnerabilities"] is False
    assert wiz.config["cve_lookup_enabled"] is True
    assert wiz.config["save_txt_report"] is False
    assert wiz.config["save_html_report"] is False
    assert wiz.config["udp_mode"] == UDP_SCAN_MODE_QUICK
    assert wiz.config["udp_top_ports"] == UDP_TOP_PORTS
    assert wiz.config["topology_enabled"] is True
    assert wiz.config["topology_only"] is True


def test_show_defaults_summary_outputs_entries():
    wiz = _TextWizard()
    persisted = {
        "target_networks": [" 10.0.0.0/24 ", "", " "],
        "scan_mode": "normal",
        "threads": 4,
        "output_dir": "/tmp/reports",
        "rate_limit": 2,
        "udp_mode": UDP_SCAN_MODE_QUICK,
        "udp_top_ports": UDP_TOP_PORTS,
        "topology_enabled": True,
        "scan_vulnerabilities": False,
        "cve_lookup_enabled": True,
        "generate_txt": False,
        "generate_html": True,
    }
    wiz._show_defaults_summary(persisted)
    assert any("defaults_summary_title" in msg[1] for msg in wiz._messages)


def test_show_defaults_summary_handles_none_values():
    wiz = _TextWizard()
    persisted = {
        "target_networks": None,
        "topology_enabled": None,
        "scan_vulnerabilities": None,
        "cve_lookup_enabled": None,
        "generate_txt": None,
        "generate_html": None,
    }
    wiz._show_defaults_summary(persisted)
    assert any("defaults_summary_targets" in msg[1] for msg in wiz._messages)


def test_apply_run_defaults_invalid_threads_and_defaults(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr("redaudit.core.wizard.get_default_reports_base_dir", lambda: "/tmp/default")
    defaults = {"threads": "bad", "rate_limit": 5, "output_dir": ""}
    wiz._apply_run_defaults(defaults)
    assert wiz.config["threads"] == DEFAULT_THREADS
    assert wiz.rate_limit_delay == 5.0
    assert wiz.config["output_dir"] == "/tmp/default"


def test_webhook_url_skip(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: False)
    assert wiz.ask_webhook_url() == ""


def test_webhook_url_flow(monkeypatch):
    wiz = _TextWizard()
    answers = iter([True, True])

    def _ask_yes_no(*_args, **_kwargs):
        return next(answers)

    called = {}

    def _fake_test_webhook(url):
        called["url"] = url
        return True

    monkeypatch.setattr(wiz, "ask_yes_no", _ask_yes_no)
    monkeypatch.setattr(wiz, "_test_webhook", _fake_test_webhook)
    _set_inputs(monkeypatch, ["http://bad", "https://example.com/webhook"])

    assert wiz.ask_webhook_url() == "https://example.com/webhook"
    assert called["url"] == "https://example.com/webhook"


def test_webhook_url_empty_input(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: True)
    _set_inputs(monkeypatch, [""])
    assert wiz.ask_webhook_url() == ""


def test_webhook_url_keyboard_interrupt(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: True)

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _boom)
    assert wiz.ask_webhook_url() == ""


def test_test_webhook_success(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr("redaudit.utils.webhook.send_webhook", lambda *_args, **_kwargs: True)
    assert wiz._test_webhook("https://example.com") is True


def test_test_webhook_failure(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr("redaudit.utils.webhook.send_webhook", lambda *_args, **_kwargs: False)
    assert wiz._test_webhook("https://example.com") is False


def test_test_webhook_exception(monkeypatch):
    wiz = _TextWizard()

    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("redaudit.utils.webhook.send_webhook", _boom)
    assert wiz._test_webhook("https://example.com") is False


def test_net_discovery_options_default(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: False)
    opts = wiz.ask_net_discovery_options()
    assert opts["snmp_community"] == "public"
    assert opts["dns_zone"] == ""
    assert opts["redteam_max_targets"] == 50


def test_net_discovery_options_custom(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(wiz, "ask_number", lambda *_args, **_kwargs: 77)
    _set_inputs(monkeypatch, ["private", "corp.local"])
    opts = wiz.ask_net_discovery_options()
    assert opts["snmp_community"] == "private"
    assert opts["dns_zone"] == "corp.local"
    assert opts["redteam_max_targets"] == 77


def test_net_discovery_options_keyboard_interrupt(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: True)

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _boom)
    opts = wiz.ask_net_discovery_options()
    assert opts["snmp_community"] == "public"


def test_use_arrow_menu_env(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.delenv("REDAUDIT_BASIC_PROMPTS", raising=False)
    assert wiz._use_arrow_menu() is True
    monkeypatch.setenv("REDAUDIT_BASIC_PROMPTS", "1")
    assert wiz._use_arrow_menu() is False


def test_use_arrow_menu_non_tty(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.delenv("REDAUDIT_BASIC_PROMPTS", raising=False)
    assert wiz._use_arrow_menu() is False


def test_clear_screen_respects_dry_run():
    wiz = _UIWizard()
    wiz.config["dry_run"] = True
    with patch("os.system") as mocked:
        wiz.clear_screen()
    mocked.assert_not_called()

    wiz.config["dry_run"] = False
    with patch("os.system") as mocked:
        wiz.clear_screen()
    mocked.assert_called_once()


def test_print_banner_outputs_subtitle(capsys):
    wiz = _UIWizard()
    wiz.ui.t.side_effect = lambda k, *a: "Subtitle" if k == "banner_subtitle" else str(k)

    wiz.print_banner()

    captured = capsys.readouterr().out
    assert "Subtitle" in captured


def test_detect_os_banner_label_from_os_release_long(monkeypatch):
    wiz = _UIWizard()
    content = 'NAME="My Distro GNU/Linux Edition"\n'
    monkeypatch.setattr("redaudit.core.wizard.os.path.exists", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("builtins.open", mock_open(read_data=content))
    assert wiz._detect_os_banner_label() == "MY DISTRO"


def test_detect_os_banner_label_invalid_chars_defaults(monkeypatch):
    wiz = _UIWizard()
    content = 'NAME="@@@"\n'
    monkeypatch.setattr("redaudit.core.wizard.os.path.exists", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("builtins.open", mock_open(read_data=content))
    assert wiz._detect_os_banner_label() == "LINUX"


def test_detect_os_banner_label_fallback_platform(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr("redaudit.core.wizard.os.path.exists", lambda *_args, **_kwargs: False)
    monkeypatch.setattr("redaudit.core.wizard.platform.system", lambda: "FreeBSD")
    assert wiz._detect_os_banner_label() == "FREEBSD"


def test_detect_os_banner_label_truncates_long_single_word(monkeypatch):
    wiz = _UIWizard()
    content = 'NAME="SUPERCALIFRAGILISTICEXPIALIDOCIOUS"\n'
    monkeypatch.setattr("redaudit.core.wizard.os.path.exists", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("builtins.open", mock_open(read_data=content))
    assert len(wiz._detect_os_banner_label()) == 22


def test_detect_os_banner_label_ignores_invalid_lines(monkeypatch):
    wiz = _UIWizard()
    content = 'BADLINE\nNAME="Test"\n'
    monkeypatch.setattr("redaudit.core.wizard.os.path.exists", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("builtins.open", mock_open(read_data=content))
    assert wiz._detect_os_banner_label() == "TEST"


def test_detect_os_banner_label_os_release_error(monkeypatch):
    wiz = _UIWizard()

    def _boom(*_args, **_kwargs):
        raise OSError("no")

    monkeypatch.setattr("redaudit.core.wizard.os.path.exists", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("builtins.open", _boom)
    monkeypatch.setattr("redaudit.core.wizard.platform.system", lambda: "Linux")
    assert wiz._detect_os_banner_label() == "LINUX"


def test_read_key_returns_empty_on_termios_failure(monkeypatch):
    import termios

    wiz = _UIWizard()

    def _raise_runtime_error(*_args, **_kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(termios, "tcgetattr", _raise_runtime_error)

    assert wiz._read_key() == ""


def test_read_key_windows_sequences(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr("redaudit.core.wizard.os.name", "nt")
    seq = iter([b"\x00", b"H", b"\r", b"x"])

    def _getch():
        return next(seq)

    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(getch=_getch))
    assert wiz._read_key() == "up"
    assert wiz._read_key() == "enter"
    assert wiz._read_key() == "x"


def test_read_key_windows_ctrl_c(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr("redaudit.core.wizard.os.name", "nt")
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(getch=lambda: b"\x03"))
    with pytest.raises(KeyboardInterrupt):
        wiz._read_key()


def test_read_key_windows_decode_error(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr("redaudit.core.wizard.os.name", "nt")

    class _NoDecode:
        pass

    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(getch=lambda: _NoDecode()))
    assert wiz._read_key() == ""


def test_read_key_windows_exception(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr("redaudit.core.wizard.os.name", "nt")

    def _boom():
        raise RuntimeError("fail")

    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(getch=_boom))
    assert wiz._read_key() == ""


def test_read_key_posix_sequences(monkeypatch):
    wiz = _UIWizard()

    class _FakeStdin:
        def __init__(self, responses):
            self._responses = list(responses)

        def fileno(self):
            return 0

        def read(self, _n=1):
            return self._responses.pop(0)

    import termios
    import tty

    monkeypatch.setattr(termios, "tcgetattr", lambda *_args, **_kwargs: "old")
    monkeypatch.setattr(termios, "tcsetattr", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tty, "setraw", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("sys.stdin", _FakeStdin(["\x1b", "[A", "\n", "x"]))

    assert wiz._read_key() == "up"
    assert wiz._read_key() == "enter"
    assert wiz._read_key() == "x"


def test_read_key_posix_ctrl_c(monkeypatch):
    wiz = _UIWizard()

    class _FakeStdin:
        def __init__(self, responses):
            self._responses = list(responses)

        def fileno(self):
            return 0

        def read(self, _n=1):
            return self._responses.pop(0)

    import termios
    import tty

    monkeypatch.setattr(termios, "tcgetattr", lambda *_args, **_kwargs: "old")
    monkeypatch.setattr(termios, "tcsetattr", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tty, "setraw", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("sys.stdin", _FakeStdin(["\x03"]))

    with pytest.raises(KeyboardInterrupt):
        wiz._read_key()


def test_strip_and_truncate_menu_text():
    wiz = _UIWizard()
    text = "\x1b[31mHello World\x1b[0m"
    assert wiz._strip_ansi(text) == "Hello World"
    truncated = wiz._truncate_menu_text(text, 5)
    assert truncated.endswith("...")


def test_clear_menu_lines_zero(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr("sys.stdout", io.StringIO())
    wiz._clear_menu_lines(0)


def test_truncate_menu_text_short_width():
    wiz = _UIWizard()
    assert wiz._truncate_menu_text("Hello", 2) == "He"


def test_menu_width_fallbacks(monkeypatch):
    wiz = _UIWizard()
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
    wiz = _UIWizard()
    assert wiz._truncate_menu_text("Hello", 0) == ""


def test_format_menu_option_colors():
    wiz = _UIWizard()
    wiz.ui.colors["OKGREEN"] = "<G>"
    wiz.ui.colors["FAIL"] = "<F>"
    wiz.ui.colors["OKBLUE"] = "<B>"
    wiz.ui.colors["DIM"] = "<D>"
    wiz.ui.colors["BOLD"] = "<BO>"
    wiz.ui.colors["CYAN"] = "<C>"
    wiz.ui.colors["ENDC"] = "<E>"
    assert wiz._format_menu_option(wiz.t("yes_default")) == "<BO><G>yes_default<E>"
    assert wiz._format_menu_option(wiz.t("yes_option")) == "<D><G>yes_option<E>"
    assert wiz._format_menu_option(wiz.t("no_default")) == "<BO><F>no_default<E>"
    assert wiz._format_menu_option(wiz.t("no_option")) == "<D><F>no_option<E>"
    assert wiz._format_menu_option("Option") == "<B>Option<E>"
    assert wiz._format_menu_option("Selected", is_selected=True) == "<BO><C>Selected<E>"

    colored = "\x1b[31mAlready colored\x1b[0m"
    assert wiz._format_menu_option(colored) == colored


def test_format_menu_option_empty():
    wiz = _UIWizard()
    assert wiz._format_menu_option("") == ""


def test_ask_yes_no_defaults(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: "")
    assert wiz.ask_yes_no("q", default="yes") is True
    assert wiz.ask_yes_no("q", default="no") is False


def test_ask_yes_no_with_timeout_non_tty(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert wiz.ask_yes_no_with_timeout("q", default="yes", timeout_s=5) is True
    assert wiz.ask_yes_no_with_timeout("q", default="no", timeout_s=0) is False


def test_ask_yes_no_with_timeout_posix_input(monkeypatch):
    import select

    wiz = _UIWizard()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdin, "readline", lambda: "y\n")
    monkeypatch.setattr(select, "select", lambda *_a, **_k: ([sys.stdin], [], []))
    assert wiz.ask_yes_no_with_timeout("q", default="no", timeout_s=1) is True


def test_ask_number_and_choice(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)

    inputs = iter(["9999", "5"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(inputs))
    result = wiz.ask_number("q", default=10, min_val=1, max_val=100)
    assert result == 5

    inputs = iter(["", "2"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(inputs))
    assert wiz.ask_choice("q", ["a", "b"], default=1) == 1


def test_ask_choice_keyboard_interrupt(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    wiz.signal_handler = MagicMock()

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _boom)
    with pytest.raises(SystemExit):
        wiz.ask_choice("Pick", ["A", "B"], default=0)
    assert wiz.signal_handler.called


def test_ask_choice_with_back_text_mode(monkeypatch):
    wiz = _UIWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    inputs = iter(["0"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(inputs))
    assert (
        wiz.ask_choice_with_back("q", ["a", "b"], default=0, step_num=2, total_steps=3)
        == wiz.WIZARD_BACK
    )


def test_ask_choice_with_back_keyboard_interrupt(monkeypatch):
    wiz = _TextWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    wiz.signal_handler = MagicMock()

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _boom)
    with pytest.raises(SystemExit):
        wiz.ask_choice_with_back("q", ["a", "b"], default=0, step_num=2, total_steps=3)
    assert wiz.signal_handler.called


def test_ask_manual_network(monkeypatch):
    wiz = _UIWizard()
    inputs = iter(["bad", "10.0.0.0/24"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(inputs))
    assert wiz.ask_manual_network() == ["10.0.0.0/24"]


def test_ask_manual_network_multiple(monkeypatch):
    wiz = _TextWizard()
    _set_inputs(monkeypatch, ["10.0.0.0/24, 192.168.0.0/24,10.0.0.0/24"])
    assert wiz.ask_manual_network() == ["10.0.0.0/24", "192.168.0.0/24"]


def test_ask_manual_network_ips(monkeypatch):
    wiz = _TextWizard()
    _set_inputs(monkeypatch, ["192.168.0.10, 192.168.0.11"])
    assert wiz.ask_manual_network() == ["192.168.0.10/32", "192.168.0.11/32"]


def test_ask_manual_network_range(monkeypatch):
    wiz = _TextWizard()
    _set_inputs(monkeypatch, ["192.168.1.8-192.168.1.15"])
    assert wiz.ask_manual_network() == ["192.168.1.8/29"]


def test_ask_manual_network_keyboard_interrupt(monkeypatch):
    wiz = _TextWizard()
    wiz.signal_handler = MagicMock()

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _boom)
    with pytest.raises(SystemExit):
        wiz.ask_manual_network()
    assert wiz.signal_handler.called


# --- Prompt clarity and red team wiring ---


class TestWizardPrompts(unittest.TestCase):
    def test_net_discovery_snmp_prompt_shows_default_brackets(self):
        app = InteractiveNetworkAuditor()
        app.lang = "en"

        prompts = []

        def fake_input(prompt: str) -> str:
            prompts.append(prompt)
            return ""

        with patch("builtins.input", side_effect=fake_input):
            app.ask_yes_no = lambda q, default="yes": True
            opts = app.ask_net_discovery_options()

        self.assertEqual(opts.get("snmp_community"), "public")
        self.assertTrue(
            any("public" in p and "[" in p for p in prompts),
            "SNMP prompt should show the default value",
        )
        self.assertTrue(
            any("ENTER" in p.upper() for p in prompts),
            "Prompt should clarify ENTER behavior",
        )


class TestWizardRedTeam(unittest.TestCase):
    def test_wizard_redteam_options_are_applied(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.setup_encryption = lambda *args, **kwargs: None

        # Sequence: ScanMode(1=Normal), Hyperscan(0), Vuln(1=No), CVE(1=No), UDP(0), Topo(0), NetDisc(0=Yes), Auth(1=No), WinVerify(1=No)
        app.ask_choice_with_back = Mock(side_effect=[1, 0, 1, 1, 0, 0, 0, 1, 1] + [1] * 20)
        app.ask_choice = Mock(side_effect=[3, 1] + [0] * 20)
        app.ask_number = Mock(side_effect=["all", 6] + [5] * 20)
        app.ask_yes_no = Mock(
            side_effect=[
                False,  # Rate limit
                False,  # Low impact
                True,  # Trust HyperScan (NEW)
                True,  # Masscan
                True,  # Active L2
                True,  # Kerberos
                False,  # Advanced Net Discovery
                False,  # Webhook
            ]
            + [False] * 10  # Safe padding
        )

        with (
            patch("builtins.input", side_effect=["", "/tmp/users.txt", "", ""]),
            patch("redaudit.core.auditor.os.geteuid", return_value=0),
            patch("shutil.which", return_value="/usr/bin/mocktool"),
            patch("redaudit.core.auditor.is_nuclei_available", return_value=True),
        ):
            app._configure_scan_interactive(defaults_for_run={})

        self.assertTrue(app.config.get("net_discovery_enabled"))
        self.assertTrue(app.config.get("net_discovery_redteam"))
        self.assertTrue(app.config.get("net_discovery_active_l2"))
        self.assertIsNone(app.config.get("net_discovery_kerberos_realm"))
        self.assertEqual(app.config.get("net_discovery_kerberos_userlist"), "/tmp/users.txt")

    def test_wizard_redteam_is_disabled_without_root(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.setup_encryption = lambda *args, **kwargs: None

        # Sequence: ScanMode(1), Hyperscan(0), Vuln(1), CVE(1), UDP(0), Topo(0), NetDisc(0=Yes), Auth(1=No), WinVerify(1=No)
        app.ask_choice_with_back = Mock(side_effect=[1, 0, 1, 1, 0, 0, 0, 1, 1] + [1] * 20)
        app.ask_choice = Mock(side_effect=[3, 1] + [0] * 20)
        app.ask_number = Mock(side_effect=["all", 6] + [5] * 20)
        app.ask_yes_no = Mock(
            side_effect=[
                False,  # Rate limit
                False,  # Low impact
                True,  # Trust HyperScan (NEW)
                False,  # Webhook
                True,  # Save defaults
                True,  # Start audit
            ]
            + [False] * 10  # Safe padding
        )

        with (
            patch("builtins.input", side_effect=["", ""]),
            patch("redaudit.core.auditor.os.geteuid", return_value=1000),
        ):
            app._configure_scan_interactive(defaults_for_run={})

        self.assertTrue(app.config.get("net_discovery_enabled"))
        self.assertFalse(app.config.get("net_discovery_redteam"))
        self.assertFalse(app.config.get("net_discovery_active_l2"))
        self.assertIsNone(app.config.get("net_discovery_kerberos_userlist"))


if __name__ == "__main__":
    unittest.main()
