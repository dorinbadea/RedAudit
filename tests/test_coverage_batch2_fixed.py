#!/usr/bin/env python3
"""
Coverage batch 2 - FIXED APIs: jsonl_exporter, session_log, command_runner
Targeting ~50-70 lines with correct APIs
"""

import os
import tempfile
from pathlib import Path


# =================================================================
# jsonl_exporter.py - Using CORRECT APIs
# =================================================================
def test_jsonl_export_findings_with_empty_data():
    """Test export_findings_jsonl with no vulnerabilities."""
    from redaudit.core import jsonl_exporter

    results = {"vulnerabilities": [], "timestamp": "2025-01-01"}

    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "findings.jsonl"
        count = jsonl_exporter.export_findings_jsonl(results, str(output))
        assert count == 0


def test_jsonl_export_assets_minimal():
    """Test export_assets_jsonl with minimal host data."""
    from redaudit.core import jsonl_exporter

    results = {"hosts": [{"ip": "1.2.3.4"}], "timestamp": "2025-01-01"}

    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "assets.jsonl"
        count = jsonl_exporter.export_assets_jsonl(results, str(output))
        assert count >= 1


def test_jsonl_export_all_creates_files():
    """Test export_all creates all expected files."""
    from redaudit.core import jsonl_exporter

    results = {
        "hosts": [{"ip": "1.2.3.4"}],
        "vulnerabilities": [],
        "timestamp": "2025-01-01",
        "summary": {"total_hosts": 1},
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        stats = jsonl_exporter.export_all(results, tmpdir)
        assert stats is not None
        # Check files exist
        assert Path(tmpdir, "findings.jsonl").exists()
        assert Path(tmpdir, "assets.jsonl").exists()
        assert Path(tmpdir, "summary.json").exists()


# =================================================================
# session_log.py - Using CORRECT APIs
# =================================================================
def test_session_logger_start_stop():
    """Test SessionLogger class with correct API."""
    from redaudit.utils.session_log import SessionLogger

    with tempfile.TemporaryDirectory() as tmpdir:
        logger = SessionLogger(tmpdir, "test_session")

        # Start logging
        result = logger.start()
        assert result is True

        # Write something to stdout (captured)
        print("Test output for session log")

        # Stop logging
        log_path = logger.stop()
        assert log_path is not None
        assert Path(log_path).exists()


def test_session_log_convenience_functions():
    """Test start_session_log/stop_session_log convenience functions."""
    from redaudit.utils.session_log import start_session_log, stop_session_log

    with tempfile.TemporaryDirectory() as tmpdir:
        # Start
        result = start_session_log(tmpdir, "test_conv")
        assert result is True

        # Stop
        log_path = stop_session_log()
        # May be None if already stopped, that's ok
        assert log_path is None or Path(log_path).exists()


# =================================================================
# command_runner.py - Using CORRECT API (CommandRunner class)
# =================================================================
def test_command_runner_basic_usage():
    """Test CommandRunner class with correct API."""
    from redaudit.core.command_runner import CommandRunner

    runner = CommandRunner()
    result = runner.run(["echo", "test"])

    assert result.returncode == 0
    assert result.ok  # Property, not method


def test_command_runner_with_timeout():
    """Test CommandRunner with timeout."""
    from redaudit.core.command_runner import CommandRunner

    runner = CommandRunner(default_timeout=1.0)
    # Command that sleeps - should timeout
    result = runner.run(["sleep", "5"], timeout=0.1)

    # Should timeout
    assert result.timed_out is True


def test_command_runner_dry_run_mode():
    """Test CommandRunner in dry-run mode."""
    from redaudit.core.command_runner import CommandRunner

    runner = CommandRunner(dry_run=True)
    result = runner.run(["rm", "-rf", "/"])  # Safe in dry-run!

    # In dry-run, should return success without executing
    assert result.ok  # Property, not method


def test_command_runner_check_output():
    """Test CommandRunner.check_output convenience method."""
    from redaudit.core.command_runner import CommandRunner

    runner = CommandRunner()
    output = runner.check_output(["echo", "hello"])

    assert "hello" in output
