"""
Tests for command_runner.py edge cases and missing coverage lines.
Target: Push command_runner.py from 87% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess
import logging


class TestCommandRunnerDryRun:
    """Tests for dry_run mode (lines 54, 75, 82-83, 86)."""

    def test_dry_run_property(self):
        """Test dry_run property (line 54)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner(dry_run=True)
        assert runner.dry_run is True

        runner2 = CommandRunner(dry_run=False)
        assert runner2.dry_run is False

    def test_dry_run_execution(self):
        """Test dry_run mode executes without running command."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner(dry_run=True)
        result = runner.run(["echo", "test"])

        assert result.ok is True
        assert result.returncode == 0
        assert result.attempts == 0

    def test_dry_run_capture_output_false(self):
        """Test dry_run with capture_output=False (line 86)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner(dry_run=True)
        result = runner.run(["ls", "-la"], capture_output=False)

        assert result.stdout is None
        assert result.stderr is None

    def test_dry_run_print_exception(self):
        """Test dry_run handles print exception (lines 82-83)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner(dry_run=True)

        with patch("builtins.print", side_effect=Exception("Print error")):
            result = runner.run(["echo", "test"])

        assert result.ok is True


class TestCommandRunnerExceptions:
    """Tests for exception handling paths (lines 204-213)."""

    def test_run_generic_exception_retries(self):
        """Test generic exception with retries (lines 204-207)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner(default_retries=1, backoff_base_s=0.001)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Generic error")

            with pytest.raises(Exception, match="Generic error"):
                runner.run(["cmd", "arg"])

    def test_run_exception_raised_after_attempts(self):
        """Test exception raised after all attempts (line 211-212)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner(default_retries=0)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Failed")

            with pytest.raises(Exception):
                runner.run(["cmd"])


class TestCommandRunnerBackoff:
    """Tests for backoff behavior (lines 268-273)."""

    def test_sleep_backoff_zero_attempt(self):
        """Test backoff with attempt <= 0 returns early (line 268)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner()
        # Directly call private method
        runner._sleep_backoff(0)  # Should return immediately

    def test_sleep_backoff_exception(self):
        """Test backoff handles sleep exception (lines 272-273)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner(backoff_base_s=0.001)

        with patch("time.sleep", side_effect=Exception("Sleep interrupted")):
            runner._sleep_backoff(1)  # Should not raise


class TestCommandRunnerRedaction:
    """Tests for redaction functionality (line 285)."""

    def test_redact_text_empty_value_in_set(self):
        """Test redaction skips empty values (line 285)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner()
        # Pass empty string in redact values
        result = runner._redact_text("secret data", {""})

        assert result == "secret data"

    def test_redact_text_with_values(self):
        """Test redaction replaces values."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner()
        result = runner._redact_text("password=secret123", {"secret123"})

        assert "***" in result
        assert "secret123" not in result


class TestCommandRunnerLogging:
    """Tests for logging behavior (lines 308-314)."""

    def test_log_warning_level(self):
        """Test warning log level (lines 307-308)."""
        from redaudit.core.command_runner import CommandRunner

        mock_logger = MagicMock()
        runner = CommandRunner(logger=mock_logger)

        runner._log("WARNING", "test warning")

        mock_logger.warning.assert_called_once_with("test warning")

    def test_log_fail_level(self):
        """Test FAIL log level (lines 309-310)."""
        from redaudit.core.command_runner import CommandRunner

        mock_logger = MagicMock()
        runner = CommandRunner(logger=mock_logger)

        runner._log("FAIL", "test error")

        mock_logger.error.assert_called_once_with("test error")

    def test_log_info_fallback(self):
        """Test info fallback for other levels (lines 311-312)."""
        from redaudit.core.command_runner import CommandRunner

        mock_logger = MagicMock()
        runner = CommandRunner(logger=mock_logger)

        runner._log("OTHER", "test info")

        mock_logger.info.assert_called_once()

    def test_log_exception_handling(self):
        """Test log exception handling (lines 313-314)."""
        from redaudit.core.command_runner import CommandRunner

        mock_logger = MagicMock()
        mock_logger.debug.side_effect = Exception("Logging failed")
        runner = CommandRunner(logger=mock_logger)

        # Should not raise
        runner._log("DEBUG", "test message")


class TestCommandRunnerValidation:
    """Tests for argument validation (line 243)."""

    def test_validate_non_string_arg(self):
        """Test non-string args are converted (line 243)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner(dry_run=True)
        result = runner.run(["echo", 123, 456])  # Non-string args

        assert result.ok is True

    def test_validate_capture_output_conflict(self):
        """Test capture_output conflict raises (line 75)."""
        from redaudit.core.command_runner import CommandRunner

        runner = CommandRunner()

        with pytest.raises(ValueError, match="cannot be used with capture_output"):
            runner.run(["echo"], capture_output=True, stdout=subprocess.PIPE)
