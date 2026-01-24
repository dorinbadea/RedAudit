#!/usr/bin/env python3
"""
Tests for UIManager - Phase 1 Architecture Refactoring.

These tests verify that UIManager works independently from the Auditor class.
"""

import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from redaudit.core.ui_manager import UIManager, create_ui_manager


class TestUIManagerCreation:
    """Test UIManager instantiation."""

    def test_default_creation(self):
        """Test UIManager with default parameters."""
        ui = UIManager()
        assert ui.lang == "en"
        assert ui.colors is not None
        assert ui.logger is None

    def test_custom_lang(self):
        """Test UIManager with custom language."""
        ui = UIManager(lang="es")
        assert ui.lang == "es"

    def test_custom_colors(self):
        """Test UIManager with custom colors."""
        colors = {"OKGREEN": "\033[92m", "ENDC": "\033[0m"}
        ui = UIManager(colors=colors)
        assert ui.colors == colors

    def test_with_logger(self):
        """Test UIManager with logger."""
        logger = MagicMock()
        ui = UIManager(logger=logger)
        assert ui.logger == logger

    def test_factory_function(self):
        """Test create_ui_manager factory."""
        ui = create_ui_manager(lang="es")
        assert isinstance(ui, UIManager)
        assert ui.lang == "es"


class TestUIManagerTranslation:
    """Test translation functionality."""

    def test_translation_english(self):
        """Test t() returns translated text."""
        ui = UIManager(lang="en")
        result = ui.t("start_audit")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_translation_spanish(self):
        """Test t() with Spanish."""
        ui = UIManager(lang="es")
        result = ui.t("start_audit")
        assert isinstance(result, str)


class TestUIManagerPrintStatus:
    """Test print_status functionality."""

    def test_print_status_basic(self, capsys):
        """Test basic print_status output."""
        ui = UIManager()
        ui.print_status("Test message", "INFO")
        captured = capsys.readouterr()
        assert "Test message" in captured.out
        assert "INFO" in captured.out

    def test_print_status_ok(self, capsys):
        """Test print_status with OK status."""
        ui = UIManager()
        ui.print_status("Success", "OKGREEN")
        captured = capsys.readouterr()
        assert "Success" in captured.out
        assert "OK" in captured.out

    def test_print_status_warning(self, capsys):
        """Test print_status with WARNING status."""
        ui = UIManager()
        ui.print_status("Caution", "WARNING")
        captured = capsys.readouterr()
        assert "Caution" in captured.out
        assert "WARN" in captured.out

    def test_print_status_fail(self, capsys):
        """Test print_status with FAIL status."""
        ui = UIManager()
        ui.print_status("Error occurred", "FAIL")
        captured = capsys.readouterr()
        assert "Error" in captured.out
        assert "FAIL" in captured.out

    def test_print_status_updates_activity(self):
        """Test that print_status updates last_activity."""
        ui = UIManager()
        before = ui.last_activity
        ui.print_status("Test", "INFO")
        assert ui.last_activity >= before


class TestUIManagerHelpers:
    """Test helper methods."""

    def test_format_eta_seconds(self):
        """Test format_eta with seconds."""
        assert UIManager.format_eta(65) == "1:05"
        assert UIManager.format_eta(59) == "0:59"
        assert UIManager.format_eta(0) == "0:00"

    def test_format_eta_hours(self):
        """Test format_eta with hours."""
        assert UIManager.format_eta(3661) == "1:01:01"
        assert UIManager.format_eta(3600) == "1:00:00"

    def test_format_eta_invalid(self):
        """Test format_eta with invalid input."""
        assert UIManager.format_eta("bad") == "--:--"
        assert UIManager.format_eta(None) == "--:--"

    def test_terminal_width(self):
        """Test _terminal_width returns int."""
        ui = UIManager()
        width = ui._terminal_width()
        assert isinstance(width, int)
        assert width > 0

    def test_condense_for_ui_nmap(self):
        """Test _condense_for_ui with nmap pattern."""
        ui = UIManager()
        result = ui._condense_for_ui("[nmap] 10.0.0.1 → nmap -A -sV -p-")
        assert "nmap" in result
        assert "10.0.0.1" in result
        assert "full scan" in result

    def test_condense_for_ui_quick(self):
        """Test _condense_for_ui with quick scan."""
        ui = UIManager()
        result = ui._condense_for_ui("[nmap] 10.0.0.1 → nmap -sV --top-ports 100")
        assert "quick scan" in result

    def test_condense_for_ui_empty(self):
        """Test _condense_for_ui with empty input."""
        ui = UIManager()
        assert ui._condense_for_ui("") == ""

    def test_condense_for_ui_regular(self):
        """Test _condense_for_ui with regular text."""
        ui = UIManager()
        result = ui._condense_for_ui("Regular message")
        assert result == "Regular message"


class TestUIManagerProgress:
    """Test progress context functionality."""

    def test_progress_context(self):
        """Test progress_context context manager."""
        ui = UIManager()
        assert ui._ui_progress_active is False

        with ui.progress_context():
            assert ui._ui_progress_active is True

        assert ui._ui_progress_active is False

    def test_progress_context_exception(self):
        """Test progress_context cleans up on exception."""
        ui = UIManager()

        try:
            with ui.progress_context():
                raise ValueError("Test error")
        except ValueError:
            pass

        assert ui._ui_progress_active is False

    def test_should_emit_during_progress_fail(self):
        """Test _should_emit_during_progress always emits FAIL."""
        ui = UIManager()
        assert ui._should_emit_during_progress("Any message", "FAIL") is True
        assert ui._should_emit_during_progress("Any message", "ERROR") is True

    def test_should_emit_during_progress_warn_signal(self):
        """Test _should_emit_during_progress emits WARN for signals."""
        ui = UIManager()
        assert ui._should_emit_during_progress("Backdoor detected", "WARN") is True
        assert ui._should_emit_during_progress("Scan complete", "WARN") is True

    def test_should_emit_during_progress_warn_routine(self):
        """Test _should_emit_during_progress suppresses routine WARN."""
        ui = UIManager()
        assert ui._should_emit_during_progress("Routine message", "WARN") is False

    def test_should_emit_during_progress_info(self):
        """Test _should_emit_during_progress suppresses INFO."""
        ui = UIManager()
        assert ui._should_emit_during_progress("Any message", "INFO") is False


class TestUIManagerUIDetail:
    """Test UI detail state management."""

    def test_set_get_ui_detail(self):
        """Test _set_ui_detail and _get_ui_detail."""
        ui = UIManager()
        ui._set_ui_detail("Test detail", "INFO")
        result = ui._get_ui_detail()
        assert "Test detail" in result or result == "Test detail"

    def test_ui_detail_truncation(self):
        """Test UI detail truncation for long messages."""
        ui = UIManager()
        long_msg = "A" * 100
        ui._set_ui_detail(long_msg, "INFO")
        result = ui._get_ui_detail()
        assert len(result) <= 63  # 60 + "..."

    def test_touch_activity(self):
        """Test touch_activity updates timestamp."""
        ui = UIManager()
        before = ui.last_activity
        ui.touch_activity()
        assert ui.last_activity >= before


class TestUIManagerEdgeCases:
    def test_progress_active_callback_exception(self):
        def _bad_callback():
            raise RuntimeError("boom")

        ui = UIManager(progress_active_callback=_bad_callback)
        assert ui._is_progress_active() is False

    def test_print_status_suppressed_detail_error(self):
        ui = UIManager()
        ui._ui_progress_active = True
        with (
            patch.object(ui, "_should_emit_during_progress", return_value=False),
            patch.object(ui, "_set_ui_detail", side_effect=RuntimeError("boom")),
        ):
            ui.print_status("detail", "INFO")

    def test_print_with_rich_console_and_lines(self):
        ui = UIManager()
        ui._active_progress_console = None

        class _DummyConsole:
            def __init__(self, **_kwargs):
                self.lines = []

            def print(self, value):
                self.lines.append(value)

        class _DummyText:
            def __init__(self):
                self.parts = []

            def append(self, value, **_kwargs):
                self.parts.append(value)

        dummy_console_module = type("DummyConsoleModule", (), {"Console": _DummyConsole})
        dummy_text_module = type("DummyTextModule", (), {"Text": _DummyText})

        with (
            patch.dict(
                sys.modules, {"rich.console": dummy_console_module, "rich.text": dummy_text_module}
            ),
            patch.object(ui, "get_progress_console", return_value=None),
        ):
            ui._print_with_rich("00:00:00", "INFO", "bright_blue", ["line1", "line2"])

    def test_print_with_rich_import_error(self):
        ui = UIManager()
        with (
            patch("builtins.__import__", side_effect=ImportError("no rich")),
            patch.object(ui, "_print_ansi") as fallback,
        ):
            ui._print_with_rich("00:00:00", "INFO", "bright_blue", ["line"])
        fallback.assert_called_once()

    def test_terminal_width_exception(self):
        ui = UIManager()
        with patch("shutil.get_terminal_size", side_effect=OSError("boom")):
            assert ui._terminal_width(fallback=80) == 80

    def test_get_standard_progress_import_error(self):
        ui = UIManager()
        with patch("builtins.__import__", side_effect=ImportError("no rich")):
            assert ui.get_standard_progress() is None

    def test_get_standard_progress_success(self):
        ui = UIManager()
        progress = ui.get_standard_progress()
        if progress is not None:
            assert progress.console is not None
