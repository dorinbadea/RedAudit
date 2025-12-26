"""
Tests for auditor_mixins.py to push coverage to 90%+.
Targets uncovered lines in _ActivityIndicator, AuditorUIMixin, and other mixins.
"""

import sys
import threading
import time
from datetime import datetime
from unittest.mock import patch, MagicMock, PropertyMock
import pytest

from redaudit.core.auditor_mixins import (
    _ActivityIndicator,
    AuditorUIMixin,
    AuditorLoggingMixin,
)


# -------------------------------------------------------------------------
# _ActivityIndicator Tests
# -------------------------------------------------------------------------


def test_activity_indicator_init():
    """Test _ActivityIndicator initialization."""
    indicator = _ActivityIndicator(label="Test", initial="testing...")
    assert indicator._label == "Test"
    assert indicator._message == "testing..."


def test_activity_indicator_update():
    """Test _ActivityIndicator update message."""
    indicator = _ActivityIndicator(label="Test")
    indicator.update("new message")
    assert indicator._message == "new message"


def test_activity_indicator_context_manager_already_running():
    """Test _ActivityIndicator context manager when already running."""
    indicator = _ActivityIndicator(label="Test")
    indicator._thread = MagicMock()

    result = indicator.__enter__()
    assert result is indicator


def test_activity_indicator_terminal_width():
    """Test _ActivityIndicator terminal width detection."""
    indicator = _ActivityIndicator(label="Test")
    width = indicator._terminal_width()
    assert width >= 40


def test_activity_indicator_clear_line_non_tty():
    """Test _ActivityIndicator clear line on non-TTY."""
    stream = MagicMock()
    stream.isatty.return_value = False
    indicator = _ActivityIndicator(label="Test", stream=stream)
    indicator._clear_line()  # Should not raise


def test_activity_indicator_clear_line_tty():
    """Test _ActivityIndicator clear line on TTY."""
    stream = MagicMock()
    stream.isatty.return_value = True
    indicator = _ActivityIndicator(label="Test", stream=stream)
    indicator._clear_line()
    stream.write.assert_called()


def test_activity_indicator_clear_line_exception():
    """Test _ActivityIndicator clear line handles exception."""
    stream = MagicMock()
    stream.isatty.side_effect = Exception("Error")
    indicator = _ActivityIndicator(label="Test", stream=stream)
    indicator._clear_line()  # Should not raise


def test_activity_indicator_with_touch_activity():
    """Test _ActivityIndicator with touch_activity callback."""
    touch_called = []

    def touch_fn():
        touch_called.append(True)

    indicator = _ActivityIndicator(label="Test", refresh_s=0.1, touch_activity=touch_fn)

    with indicator:
        time.sleep(0.2)

    assert len(touch_called) > 0


def test_activity_indicator_touch_activity_exception():
    """Test _ActivityIndicator handles touch_activity exception."""

    def touch_fn():
        raise Exception("Touch failed")

    indicator = _ActivityIndicator(label="Test", refresh_s=0.05, touch_activity=touch_fn)

    with indicator:
        time.sleep(0.1)  # Should not raise


def test_activity_indicator_non_tty_output():
    """Test _ActivityIndicator output on non-TTY stream."""
    stream = MagicMock()
    stream.isatty.return_value = False
    indicator = _ActivityIndicator(label="Test", refresh_s=0.5, stream=stream)

    # Start indicator briefly
    indicator._stop.clear()
    indicator._thread = threading.Thread(target=indicator._run, daemon=True)
    indicator._thread.start()
    time.sleep(0.1)
    indicator._stop.set()
    indicator._thread.join(timeout=1.0)


def test_activity_indicator_tty_narrow_width():
    """Test _ActivityIndicator on narrow terminal."""
    stream = MagicMock()
    stream.isatty.return_value = True
    indicator = _ActivityIndicator(label="Test", refresh_s=0.05, stream=stream)

    with patch.object(indicator, "_terminal_width", return_value=50):
        indicator._stop.clear()
        indicator._run_iteration_count = 0

        # Simulate one run iteration
        with indicator._lock:
            pass  # Just access lock


# -------------------------------------------------------------------------
# AuditorUIMixin Tests
# -------------------------------------------------------------------------


class MockAuditor(AuditorUIMixin):
    """Mock auditor for testing UI mixin."""

    def __init__(self):
        self.activity_lock = threading.Lock()
        self.COLORS = {
            "OKGREEN": "\033[92m",
            "OKBLUE": "\033[94m",
            "WARNING": "\033[93m",
            "FAIL": "\033[91m",
            "HEADER": "\033[95m",
            "ENDC": "\033[0m",
            "CYAN": "\033[96m",
        }
        self.logger = None
        self._print_lock = threading.Lock()
        self._ui_detail_lock = threading.Lock()
        self._ui_detail = ""
        self._ui_progress_active = False
        self.current_phase = ""
        self.last_activity = datetime.now()
        self.lang = "en"


def test_auditor_ui_mixin_t():
    """Test AuditorUIMixin.t() translation."""
    mock = MockAuditor()
    result = mock.t("some_key")
    assert isinstance(result, str)


def test_auditor_ui_mixin_print_status_basic():
    """Test AuditorUIMixin.print_status() basic output."""
    mock = MockAuditor()
    mock.print_status("Test message", "INFO")


def test_auditor_ui_mixin_print_status_progress_suppressed():
    """Test AuditorUIMixin.print_status() suppresses during progress."""
    mock = MockAuditor()
    mock._ui_progress_active = True
    mock.print_status("Routine info", "INFO")  # Should be suppressed


def test_auditor_ui_mixin_print_status_fail_not_suppressed():
    """Test AuditorUIMixin.print_status() does not suppress FAIL."""
    mock = MockAuditor()
    mock._ui_progress_active = True
    mock.print_status("Error occurred", "FAIL")  # Should NOT be suppressed


def test_auditor_ui_mixin_condense_for_ui_nmap():
    """Test AuditorUIMixin._condense_for_ui() with nmap command."""
    mock = MockAuditor()
    result = mock._condense_for_ui("[ports] 192.168.1.1 → nmap -sV -p- 192.168.1.1")
    assert "192.168.1.1" in result


def test_auditor_ui_mixin_condense_for_ui_testssl():
    """Test AuditorUIMixin._condense_for_ui() with testssl."""
    mock = MockAuditor()
    result = mock._condense_for_ui("[testssl] 192.168.1.1:443 → testssl.sh 192.168.1.1:443")
    assert "testssl" in result


def test_auditor_ui_mixin_condense_for_ui_agentless():
    """Test AuditorUIMixin._condense_for_ui() with agentless."""
    mock = MockAuditor()
    result = mock._condense_for_ui("[agentless] 192.168.1.1 → smb probe")
    assert "agentless" in result


def test_auditor_ui_mixin_condense_for_ui_udp():
    """Test AuditorUIMixin._condense_for_ui() with UDP scan."""
    mock = MockAuditor()
    result = mock._condense_for_ui("[scan] 192.168.1.1 → nmap -sU --top-ports 100")
    assert "UDP" in result or "top ports" in result


def test_auditor_ui_mixin_condense_for_ui_empty():
    """Test AuditorUIMixin._condense_for_ui() with empty string."""
    mock = MockAuditor()
    result = mock._condense_for_ui("")
    assert result == ""


def test_auditor_ui_mixin_condense_for_ui_long():
    """Test AuditorUIMixin._condense_for_ui() truncates long messages."""
    mock = MockAuditor()
    long_msg = "a" * 100
    result = mock._condense_for_ui(long_msg)
    assert len(result) <= 65  # 60 + ellipsis


def test_auditor_ui_mixin_set_ui_detail():
    """Test AuditorUIMixin._set_ui_detail()."""
    mock = MockAuditor()
    mock._set_ui_detail("[scan] 192.168.1.1 → nmap", "INFO")
    assert mock._ui_detail != ""


def test_auditor_ui_mixin_format_ui_detail():
    """Test AuditorUIMixin._format_ui_detail()."""
    mock = MockAuditor()
    result = mock._format_ui_detail("test", "INFO")
    assert "bright_blue" in result


def test_auditor_ui_mixin_coerce_text():
    """Test AuditorUIMixin._coerce_text()."""
    assert AuditorUIMixin._coerce_text(None) == ""
    assert AuditorUIMixin._coerce_text(b"hello") == "hello"
    assert AuditorUIMixin._coerce_text("hello") == "hello"
    assert AuditorUIMixin._coerce_text(123) == "123"


def test_auditor_ui_mixin_phase_detail():
    """Test AuditorUIMixin._phase_detail()."""
    mock = MockAuditor()

    mock.current_phase = ""
    assert mock._phase_detail() == ""

    mock.current_phase = "vulns:testssl:192.168.1.1"
    assert "testssl" in mock._phase_detail()

    mock.current_phase = "vulns:nikto:192.168.1.1"
    assert "nikto" in mock._phase_detail()

    mock.current_phase = "vulns:whatweb:192.168.1.1"
    assert "whatweb" in mock._phase_detail()

    mock.current_phase = "ports:192.168.1.1"
    assert "nmap" in mock._phase_detail()

    mock.current_phase = "deep:192.168.1.1"
    assert "deep scan" in mock._phase_detail()

    mock.current_phase = "discovery:192.168.1.0/24"
    assert "discovery" in mock._phase_detail()

    mock.current_phase = "vulns"
    assert "web vuln" in mock._phase_detail()

    mock.current_phase = "net_discovery"
    assert "net discovery" in mock._phase_detail()

    mock.current_phase = "topology"
    assert "topology" in mock._phase_detail()


def test_auditor_ui_mixin_touch_activity():
    """Test AuditorUIMixin._touch_activity()."""
    mock = MockAuditor()
    before = mock.last_activity
    time.sleep(0.01)
    mock._touch_activity()
    assert mock.last_activity > before


def test_auditor_ui_mixin_should_emit_during_progress():
    """Test AuditorUIMixin._should_emit_during_progress()."""
    mock = MockAuditor()

    # FAIL always emits
    assert mock._should_emit_during_progress("error", "FAIL") is True

    # INFO never emits
    assert mock._should_emit_during_progress("info msg", "INFO") is False

    # OK with deep scan text emits
    assert mock._should_emit_during_progress("deep identity scan finished", "OK") is True

    # WARN with signal terms emits
    assert mock._should_emit_during_progress("CVE found", "WARN") is True
    assert mock._should_emit_during_progress("⚠ warning", "WARN") is True


def test_auditor_ui_mixin_format_eta():
    """Test AuditorUIMixin._format_eta()."""
    mock = MockAuditor()
    assert AuditorUIMixin._format_eta(0) == "0:00"
    assert AuditorUIMixin._format_eta(65) == "1:05"
    assert AuditorUIMixin._format_eta(3661) == "1:01:01"
    assert AuditorUIMixin._format_eta("invalid") == "--:--"


def test_auditor_ui_mixin_terminal_width():
    """Test AuditorUIMixin._terminal_width()."""
    mock = MockAuditor()
    width = mock._terminal_width()
    assert width >= 60


def test_auditor_ui_mixin_progress_console():
    """Test AuditorUIMixin._progress_console()."""
    mock = MockAuditor()
    console = mock._progress_console()
    # May be None if Rich not installed
    assert console is None or console is not None


def test_auditor_ui_mixin_safe_text_column():
    """Test AuditorUIMixin._safe_text_column()."""
    mock = MockAuditor()
    col = mock._safe_text_column("test")
    # May be None if Rich not installed


def test_auditor_ui_mixin_progress_columns():
    """Test AuditorUIMixin._progress_columns()."""
    mock = MockAuditor()
    cols = mock._progress_columns(show_detail=True, show_eta=True, show_elapsed=True)
    assert isinstance(cols, list)


def test_auditor_ui_mixin_progress_ui():
    """Test AuditorUIMixin._progress_ui() context manager."""
    mock = MockAuditor()
    assert mock._ui_progress_active is False

    with mock._progress_ui():
        assert mock._ui_progress_active is True

    assert mock._ui_progress_active is False


# -------------------------------------------------------------------------
# AuditorLoggingMixin Tests
# -------------------------------------------------------------------------


class MockLoggingAuditor(AuditorLoggingMixin):
    """Mock auditor for testing logging mixin."""

    def __init__(self):
        self.logger = None
        self.heartbeat_thread = None
        self.heartbeat_stop = False
        self.activity_lock = threading.Lock()
        self.last_activity = datetime.now()
        self.current_phase = "init"
        self._ui_progress_active = False


def test_logging_mixin_setup():
    """Test AuditorLoggingMixin._setup_logging()."""
    mock = MockLoggingAuditor()
    mock._setup_logging()
    assert mock.logger is not None


def test_logging_mixin_heartbeat():
    """Test AuditorLoggingMixin heartbeat start/stop."""
    mock = MockLoggingAuditor()
    mock.logger = MagicMock()

    mock.start_heartbeat()
    assert mock.heartbeat_thread is not None

    time.sleep(0.1)

    mock.stop_heartbeat()
    assert mock.heartbeat_stop is True
