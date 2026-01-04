"""Edge-case tests for auditor components (UI, heartbeat, crypto, NVD)."""

import io
import logging
import os
import sys
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import pytest
from redaudit.core.auditor_components import (
    _ActivityIndicator,
    AuditorUI,
    AuditorLogging,
    AuditorCrypto,
    AuditorNVD,
)
from redaudit.utils.constants import HEARTBEAT_FAIL_THRESHOLD


def test_activity_indicator_edge_cases():
    """Test _ActivityIndicator with various edge cases (lines 59, 79, 89, 114, 120-121, 131-132)."""
    # 59: Terminal width failure
    with patch("shutil.get_terminal_size", side_effect=Exception()):
        ai = _ActivityIndicator(label="test")
        assert ai._terminal_width() == 80

    # 79: Exit with exception
    mock_touch = MagicMock()
    ai = _ActivityIndicator(label="test", touch_activity=mock_touch)
    with ai:
        pass
    assert mock_touch.called

    # 131: _run loop exception handling (mock stream write failure)
    ai = _ActivityIndicator(label="test")
    mock_stream = MagicMock()
    mock_stream.isatty.return_value = True
    mock_stream.write.side_effect = Exception("Write Fail")
    ai._stream = mock_stream
    with ai:
        time.sleep(0.3)  # Wait for a few ticks


class MockUI(AuditorUI):
    def __init__(self):
        self.COLORS = {
            "INFO": "",
            "WARNING": "",
            "FAIL": "",
            "ENDC": "",
            "OKGREEN": "",
            "OKBLUE": "",
            "HEADER": "",
        }
        self.logger = MagicMock()
        self.lang = "en"
        self._print_lock = threading.Lock()
        self._ui_detail_lock = threading.Lock()
        self.activity_lock = threading.Lock()
        self._ui_detail = ""
        self._ui_progress_active = False
        self.current_phase = ""
        self.last_activity = None


def test_ui_component_print_status_edge():
    """Test print_status with flags and noisy suppression."""
    ui = MockUI()
    # 196: Suppress during progress
    ui._ui_progress_active = True

    with patch("rich.console.Console.print") as mock_rich_print:
        with patch("builtins.print") as mock_print:
            ui.print_status("routine info", "INFO")
            assert not mock_rich_print.called
            assert not mock_print.called

            # 204: Force emit
            ui.print_status("force info", "INFO", force=True)
            assert mock_rich_print.called or mock_print.called


def test_ui_condense_truncation():
    """Test _condense_for_ui truncation."""
    ui = MockUI()
    # Very long command > 60 chars
    long_cmd = "nmap -sS -sV -A -T4 -p 1-65535 --script vuln 192.168.1.1 192.168.1.2 192.168.1.3"
    condensed = ui._condense_for_ui(long_cmd)
    assert len(condensed) <= 61
    assert condensed.endswith("…")


def test_ui_phase_detail():
    """Test _phase_detail with all phases."""
    ui = MockUI()
    ui.current_phase = "init"
    assert "init" in ui._phase_detail()
    ui.current_phase = "vulns:testssl:1.1.1.1"
    assert "testssl" in ui._phase_detail()


def test_ui_should_emit_details():
    """Test _should_emit_during_progress with specific levels."""
    ui = MockUI()
    assert ui._should_emit_during_progress("critical error", "FAIL") is True
    assert ui._should_emit_during_progress("routine info", "INFO") is False


def test_ui_format_eta():
    """Test _format_eta with various durations."""
    assert "1:40" in AuditorUI._format_eta(100)
    assert "1:00:00" in AuditorUI._format_eta(3600)


class MockLogger(AuditorLogging):
    def __init__(self):
        self.logger = MagicMock()
        self.heartbeat_thread = None
        self.heartbeat_stop = False
        self.last_activity = datetime.now()
        self.interrupted = False
        self.activity_lock = threading.Lock()
        self.current_phase = "scan"


def test_logging_component_heartbeat_warns_on_silence(monkeypatch):
    """Test heartbeat loop warns when activity is stale."""
    l = MockLogger()
    l.last_activity = datetime.now() - timedelta(seconds=HEARTBEAT_FAIL_THRESHOLD + 1)
    l.heartbeat_stop = False

    def _sleep(_seconds):
        l.heartbeat_stop = True

    monkeypatch.setattr("redaudit.core.auditor_components.time.sleep", _sleep)
    l._heartbeat_loop()
    assert l.logger.warning.called


class MockCrypto(AuditorCrypto):
    def __init__(self):
        self.config = {}
        self.encryption_enabled = False
        self.encryption_key = None
        self.cryptography_available = True
        self.lang = "en"
        self.COLORS = {"WARNING": "", "ENDC": "", "OKGREEN": ""}
        self.colors = self.COLORS
        self.ui = self

    def t(self, key):
        return key

    def print_status(self, *args, **kwargs):
        pass

    def ask_yes_no(self, *args, **kwargs):
        return True


def test_crypto_component_setup():
    """Test setup_encryption."""
    c = MockCrypto()
    with patch("redaudit.core.auditor_components.ask_password_twice", return_value="pwd"):
        with patch(
            "redaudit.core.auditor_components.derive_key_from_password", return_value=(b"key", b"salt")
        ):
            c.setup_encryption()
            assert c.encryption_enabled is True


class MockNVD(AuditorNVD):
    def __init__(self):
        self.config = {"cve_lookup_enabled": True}
        self.COLORS = {"WARNING": "", "ENDC": "", "CYAN": ""}
        self.lang = "en"
        self.colors = self.COLORS
        self.ui = self

    def t(self, key):
        return key

    def print_status(self, *args, **kwargs):
        pass

    def ask_choice(self, *args, **kwargs):
        return 2  # Skip


def test_nvd_component_setup():
    """Test setup_nvd_api_key."""
    n = MockNVD()
    with patch("redaudit.utils.config.get_nvd_api_key", return_value=None):
        n.setup_nvd_api_key()
        # Should exit early due to ask_choice skipping
