"""
Tests for scanner/nmap.py to push coverage to 95%+.
Targets uncovered lines: 94, 96, 103, 109, 111 (bytes decoding and max output limits).
"""

from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.scanner.nmap import run_nmap_command


def test_run_nmap_command_stdout_bytes():
    """Test run_nmap_command handles stdout as bytes (line 94)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        # Mock result with bytes stdout
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"nmap output as bytes"
        mock_result.stderr = ""
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
        )

        assert "stdout" in result
        assert isinstance(result["stdout"], str)


def test_run_nmap_command_stderr_bytes():
    """Test run_nmap_command handles stderr as bytes (line 96)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        # Mock result with bytes stderr
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = b"error message as bytes"
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
        )

        assert "stderr" in result
        assert isinstance(result["stderr"], str)


def test_run_nmap_command_max_stdout_none():
    """Test run_nmap_command with max_stdout=None (line 103)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        long_output = "x" * 10000
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = long_output
        mock_result.stderr = ""
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
            max_stdout=None,  # No truncation
        )

        assert len(result["stdout"]) == 10000


def test_run_nmap_command_max_stderr_none():
    """Test run_nmap_command with max_stderr=None (line 109)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        long_error = "e" * 5000
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = long_error
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
            max_stderr=None,  # No truncation
        )

        assert len(result["stderr"]) == 5000


def test_run_nmap_command_max_stderr_zero():
    """Test run_nmap_command with max_stderr=0 (line 111)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "some error"
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
            max_stderr=0,  # Suppress stderr
        )

        assert result["stderr"] == ""
