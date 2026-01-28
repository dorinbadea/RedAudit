#!/usr/bin/env python3
"""
Tests for session_log module.
"""

import io
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

from redaudit.utils.session_log import SessionLogHandler, SessionLogger, TeeStream


class TestTeeStream(unittest.TestCase):
    def test_lines_mode_ignores_partial_writes(self):
        terminal = io.StringIO()
        log = io.StringIO()
        lock = MagicMock()
        stream = TeeStream(terminal, log, lock, mode="lines")

        stream.write("progress 10%")
        self.assertEqual(log.getvalue(), "")
        self.assertEqual(terminal.getvalue(), "progress 10%")

        stream.write("\n")
        self.assertEqual(log.getvalue(), "progress 10%\n")

    def test_lines_mode_drops_carriage_return_frames(self):
        terminal = io.StringIO()
        log = io.StringIO()
        lock = MagicMock()
        stream = TeeStream(terminal, log, lock, mode="lines")

        # Simulate progress redraws that rewrite the same line using carriage returns.
        stream.write("frame1\rframe2\rframe3")
        self.assertEqual(log.getvalue(), "")

        stream.write("\n")
        self.assertEqual(log.getvalue(), "frame3\n")

    def test_lines_mode_prefixes_stderr_lines(self):
        terminal = io.StringIO()
        log = io.StringIO()
        lock = MagicMock()
        stream = TeeStream(terminal, log, lock, prefix="[stderr] ", mode="lines")

        stream.write("oops\n")
        self.assertEqual(log.getvalue(), "[stderr] oops\n")
        self.assertEqual(terminal.getvalue(), "oops\n")

    def test_raw_mode_logs_every_write(self):
        terminal = io.StringIO()
        log = io.StringIO()
        lock = MagicMock()
        stream = TeeStream(terminal, log, lock, mode="raw")

        stream.write("a")
        stream.write("b")
        stream.write("\n")
        self.assertEqual(log.getvalue(), "ab\n")

    def test_isatty_delegates_to_terminal(self):
        terminal = MagicMock()
        terminal.isatty.return_value = True
        log = io.StringIO()
        lock = MagicMock()
        stream = TeeStream(terminal, log, lock, mode="lines")
        self.assertTrue(stream.isatty())

    def test_isatty_handles_exception(self):
        terminal = MagicMock()
        terminal.isatty.side_effect = RuntimeError("boom")
        log = io.StringIO()
        lock = MagicMock()
        stream = TeeStream(terminal, log, lock, mode="lines")
        self.assertFalse(stream.isatty())


def test_session_log_handler_emit_handles_error():
    logger = MagicMock()
    logger.write_direct.side_effect = RuntimeError("boom")
    handler = SessionLogHandler(logger)
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "msg", args=(), exc_info=None)
    with patch.object(handler, "handleError") as mock_handle:
        handler.emit(record)
    assert mock_handle.called


def test_session_logger_start_already_active():
    """Test start() when already active (line 71)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        logger.active = True
        result = logger.start()
        assert result is True


def test_session_logger_start_exception():
    """Test start() with exception (line 109)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = logger.start()
            assert result is False


def test_session_logger_start_warns_on_failure():
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        out = io.StringIO()
        with (
            patch("redaudit.utils.session_log.TeeStream", side_effect=RuntimeError("boom")),
            patch("sys.stdout", out),
        ):
            result = logger.start()
        assert result is False
        assert "[session_log] Warning" in out.getvalue()


def test_session_logger_stop_not_active():
    """Test stop() when not active (line 123)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        logger.active = False
        result = logger.stop()
        assert result is None


def test_session_logger_stop_exception():
    """Test stop() with exception (lines 143-146)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        logger.active = True
        logger.original_stdout = MagicMock()
        logger.original_stderr = MagicMock()
        logger.log_file = MagicMock()
        logger.log_file.close.side_effect = RuntimeError("Close failed")

        with patch.object(logger, "_create_clean_version", side_effect=Exception("Failed")):
            result = logger.stop()
            assert result is None
            assert logger.active is False


def test_session_logger_write_header_no_log_file():
    """Test _write_header with no log file (line 151)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        logger.log_file = None
        logger._write_header()  # Should not raise


def test_session_logger_write_footer_no_log_file():
    """Test _write_footer with no log file (line 168)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        logger.log_file = None
        logger._write_footer()  # Should not raise


def test_session_logger_create_clean_version_exception():
    """Test _create_clean_version with exception (lines 200-201)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        logger.session_dir = Path(tmpdir) / "session_logs"
        logger.session_name = "test"

        with patch("builtins.open", side_effect=IOError("Read failed")):
            result = logger._create_clean_version()
            assert result is None


def test_session_logger_write_direct_no_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        logger.log_file = None
        logger.write_direct("msg")


def test_session_logger_write_direct_exception():
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir)
        bad_file = MagicMock()
        bad_file.write.side_effect = RuntimeError("boom")
        logger.log_file = bad_file
        logger.write_direct("msg")


def test_tee_stream_write_raw_mode():
    """Test TeeStream write in raw mode (lines 253, 258-259)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock, prefix="[test] ", mode="raw")
    tee.write("test data")

    assert log_file.write.called
    assert log_file.flush.called


def test_tee_stream_write_exception():
    """Test TeeStream write with exception (line 258-259)."""
    terminal = MagicMock()
    log_file = MagicMock()
    log_file.write.side_effect = IOError("Write failed")

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock, mode="lines")
    result = tee.write("test\n")

    assert result == 5  # Should not raise


def test_tee_stream_write_lines_empty_data():
    """Test _write_lines with empty data (line 273)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    tee._write_lines("")  # Should not raise


def test_tee_stream_write_lines_buffer_overflow():
    """Test _write_lines with buffer overflow (line 283)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    tee._max_buf = 100
    tee._log_buf = "x" * 200  # Exceed max
    tee._write_lines("more data")

    assert len(tee._log_buf) <= tee._max_buf


def test_tee_stream_write_lines_no_lines():
    """Test _write_lines when splitlines returns empty (line 290)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    tee._log_buf = "\n"
    tee._write_lines("")
    # Should handle gracefully


def test_tee_stream_write_lines_skips_noise():
    terminal = MagicMock()
    log_file = io.StringIO()
    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    tee._should_skip_line = lambda _line: True
    tee._write_lines("skip me\n")
    assert log_file.getvalue() == ""


def test_tee_stream_write_lines_partial_line():
    """Test _write_lines with partial line (line 294)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    tee._write_lines("line1\npartial")

    assert tee._log_buf == "partial"


def test_tee_stream_should_skip_line_empty():
    """Test _should_skip_line with empty line (line 319)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    result = tee._should_skip_line("   \n")

    assert result is False  # Keep blank lines


def test_tee_stream_should_skip_line_status_message():
    """Test _should_skip_line with status message (line 323)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    result = tee._should_skip_line("[OK] Test passed ✓\n")

    assert result is False  # Never skip status


def test_tee_stream_should_skip_line_scan_results():
    """Test _should_skip_line with scan results (line 341)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    result = tee._should_skip_line("Found 5 hosts with 10 ports\n")

    assert result is False  # Keep scan results


def test_tee_stream_should_skip_line_heartbeat_duplicate():
    """Test _should_skip_line with duplicate heartbeat (lines 347-359)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)

    # First heartbeat
    result1 = tee._should_skip_line(
        "[22:30:37] [INFO] Net Discovery en progreso... (8:26 transcurrido)\n"
    )
    assert result1 is False  # Keep first

    # Duplicate heartbeat
    result2 = tee._should_skip_line(
        "[22:30:38] [INFO] Net Discovery en progreso... (8:27 transcurrido)\n"
    )
    assert result2 is True  # Skip duplicate


def test_tee_stream_heartbeat_flush_on_new_key():
    terminal = MagicMock()
    log_file = io.StringIO()
    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)

    tee._should_skip_line("[22:30:37] [INFO] Net Discovery en progreso... (8:26 transcurrido)\n")
    tee._should_skip_line("[22:30:38] [INFO] Net Discovery en progreso... (8:27 transcurrido)\n")
    tee._should_skip_line("[22:30:39] [INFO] Phase 2 en progreso... (0:01 transcurrido)\n")

    assert "updates" in log_file.getvalue()


def test_tee_stream_should_skip_line_progress_minor_change():
    """Test _should_skip_line with minor progress change (lines 365-383)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)

    # First progress
    result1 = tee._should_skip_line("⠋ Discovery ━━━━━━━━━━ 10%\n")
    assert result1 is False  # Keep first

    # Minor change (< 5%)
    result2 = tee._should_skip_line("⠙ Discovery ━━━━━━━━━━ 12%\n")
    assert result2 is True  # Skip minor change


def test_tee_stream_should_skip_line_progress_bar_duplicate():
    """Test _should_skip_line with repeated rich progress bars."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)

    line = "✔ 192.168.178.24 ━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:03 0:00:00\n"
    result1 = tee._should_skip_line(line)
    assert result1 is False  # Keep first occurrence

    result2 = tee._should_skip_line(line)
    assert result2 is True  # Skip duplicate

    result3 = tee._should_skip_line(
        "192.168.178.24 ━━━━━━━━━━━━━━━━━━━━━━━━━ 95% 0:00:10 0:00:00\n"
    )
    assert result3 is False  # Keep pct change


def test_tee_stream_flush_with_heartbeat_count():
    """Test flush with heartbeat count (lines 394-395)."""
    terminal = MagicMock()
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    tee._heartbeat_count = 5
    tee.flush()

    assert log_file.write.called


def test_tee_stream_isatty():
    """Test isatty (line 402)."""
    terminal = MagicMock()
    terminal.isatty.return_value = True
    log_file = MagicMock()

    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    result = tee.isatty()

    assert result is True


def test_tee_stream_encoding_fallback():
    terminal = MagicMock()
    terminal.encoding = None
    log_file = MagicMock()
    lock = MagicMock()
    tee = TeeStream(terminal, log_file, lock)
    assert tee.encoding == "utf-8"
