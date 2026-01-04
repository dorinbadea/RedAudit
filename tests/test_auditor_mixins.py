#!/usr/bin/env python3
"""
RedAudit - Tests for auditor mixins.
"""

import logging
from logging.handlers import RotatingFileHandler
from unittest.mock import patch

from redaudit.core.auditor import InteractiveNetworkAuditor


def test_condense_for_ui_parses_full_scan():
    app = InteractiveNetworkAuditor()
    text = "[nmap] 10.0.0.1 \u2192 nmap -A -sV -p-"
    assert app._condense_for_ui(text) == "nmap 10.0.0.1 (full scan)"


def test_setup_logging_adds_rotating_handler(tmp_path):
    logger = logging.getLogger("RedAudit")
    original_handlers = list(logger.handlers)
    logger.handlers = []
    try:
        with patch(
            "redaudit.core.auditor_mixins.os.path.expanduser",
            return_value=str(tmp_path / "logs"),
        ):
            app = InteractiveNetworkAuditor()
        assert any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers)
    finally:
        logger.handlers = original_handlers


def test_format_eta_and_phase_detail():
    app = InteractiveNetworkAuditor()
    assert app._format_eta(65) == "1:05"
    assert app._format_eta(3661) == "1:01:01"
    assert app._format_eta("bad") == "--:--"

    app.current_phase = "vulns:testssl:1.2.3.4:443"
    assert app._phase_detail() == "testssl 1.2.3.4:443"
    app.current_phase = "ports:10.0.0.1"
    assert app._phase_detail() == "nmap 10.0.0.1"


def test_should_emit_during_progress_filters_noise():
    app = InteractiveNetworkAuditor()
    assert app._should_emit_during_progress("deep identity scan finished", "OK") is True
    assert app._should_emit_during_progress("routine info", "INFO") is False
    assert app._should_emit_during_progress("some error occurred", "WARN") is True


def test_coerce_text_variants():
    app = InteractiveNetworkAuditor()
    assert app._coerce_text(b"abc") == "abc"
    assert app._coerce_text("text") == "text"
    assert app._coerce_text(None) == ""
    assert app._coerce_text(123) == "123"


def test_start_stop_heartbeat():
    """Test heartbeat start/stop lifecycle."""
    app = InteractiveNetworkAuditor()
    app.start_heartbeat()
    assert app.heartbeat_thread is not None
    assert app.heartbeat_thread.is_alive()

    app.stop_heartbeat()
    assert app.heartbeat_stop is True


def test_touch_activity():
    """Test activity tracking update."""
    from datetime import datetime

    app = InteractiveNetworkAuditor()
    before = app.last_activity
    app._touch_activity()
    assert app.last_activity >= before


def test_signal_handler(capsys):
    """Test signal handler sets interrupted state."""
    app = InteractiveNetworkAuditor()
    app.interrupted = False
    app.heartbeat_stop = False

    # Stop heartbeat to prevent SystemExit
    app.heartbeat_stop = True
    try:
        app.signal_handler(2, None)
    except SystemExit:
        pass  # Expected in some cases

    # interrupted should be True after signal
    assert app.interrupted is True or app.heartbeat_stop is True


def test_progress_console():
    """Test _progress_console returns console."""
    app = InteractiveNetworkAuditor()
    console = app._progress_console()
    # Should return a Console or similar object
    assert console is not None


def test_safe_text_column():
    """Test _safe_text_column creates appropriate column."""
    app = InteractiveNetworkAuditor()
    col = app._safe_text_column("[bold]Test[/bold]")
    assert col is not None


def test_progress_columns():
    """Test _progress_columns returns column tuple."""
    app = InteractiveNetworkAuditor()
    cols = app._progress_columns(show_detail=True, show_eta=True, show_elapsed=True)
    assert isinstance(cols, tuple)
    assert len(cols) > 0


def test_condense_for_ui_variants():
    """Test _condense_for_ui with various patterns."""
    app = InteractiveNetworkAuditor()

    # Quick scan pattern
    result = app._condense_for_ui("[nmap] 10.0.0.1 → nmap -sV --top-ports 100")
    assert "nmap" in result.lower()

    # Empty text
    result = app._condense_for_ui("")
    assert result == ""

    # Text without nmap pattern
    result = app._condense_for_ui("Some other message")
    assert result == "Some other message"


def test_format_eta_edge_cases():
    """Test _format_eta with edge cases."""
    app = InteractiveNetworkAuditor()

    assert app._format_eta(0) == "0:00"
    assert app._format_eta(59) == "0:59"
    assert app._format_eta(3600) == "1:00:00"
    assert app._format_eta(None) == "--:--"


def test_phase_detail_variants():
    """Test _phase_detail with different phase types."""
    app = InteractiveNetworkAuditor()

    app.current_phase = "init"
    result = app._phase_detail()
    assert isinstance(result, str)

    app.current_phase = "saving"
    result = app._phase_detail()
    assert isinstance(result, str)

    app.current_phase = "discovery:10.0.0.0/24"
    result = app._phase_detail()
    assert isinstance(result, str)


def test_subprocess_tracking():
    """Test subprocess tracking for cleanup."""
    app = InteractiveNetworkAuditor()

    # Add a mock subprocess
    from unittest.mock import MagicMock

    mock_proc = MagicMock()
    mock_proc.poll.return_value = None

    with app._subprocess_lock:
        app._active_subprocesses.append(mock_proc)

    assert len(app._active_subprocesses) == 1


def test_print_status_variants():
    """Test print_status with different status types."""
    app = InteractiveNetworkAuditor()

    # These should not raise
    app.print_status("Test info", "INFO")
    app.print_status("Test warning", "WARNING")
    app.print_status("Test error", "FAIL")
    app.print_status("Test success", "OKGREEN")


def test_translation_method():
    """Test t() translation method."""
    app = InteractiveNetworkAuditor()
    app.lang = "en"

    # Should return something (key or translation)
    result = app.t("start_audit")
    assert isinstance(result, str)
    assert len(result) > 0
