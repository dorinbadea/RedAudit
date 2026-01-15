"""
Tests for masscan_scanner.py - v4.7.0 HyperScan Masscan Integration.
"""

import os
from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.masscan_scanner import (
    is_masscan_available,
    masscan_sweep,
    masscan_batch_sweep,
)


class TestIsMasscanAvailable:
    """Tests for is_masscan_available()."""

    def test_available_with_root(self):
        """Returns True when masscan exists and running as root."""
        with patch("shutil.which", return_value="/usr/bin/masscan"):
            with patch("os.geteuid", return_value=0):
                assert is_masscan_available() is True

    def test_unavailable_not_root(self):
        """Returns False when not running as root."""
        with patch("shutil.which", return_value="/usr/bin/masscan"):
            with patch("os.geteuid", return_value=1000):
                assert is_masscan_available() is False

    def test_unavailable_masscan_missing(self):
        """Returns False when masscan is not installed."""
        with patch("shutil.which", return_value=None):
            with patch("os.geteuid", return_value=0):
                assert is_masscan_available() is False


class TestMasscanSweep:
    """Tests for masscan_sweep()."""

    def test_returns_empty_when_not_available(self):
        """Returns empty list when masscan not available."""
        with patch("redaudit.core.masscan_scanner.is_masscan_available", return_value=False):
            result = masscan_sweep("192.168.1.1")
            assert result == []

    def test_parses_masscan_output(self):
        """Correctly parses masscan output for open ports."""
        mock_output = """
        Starting masscan
        Discovered open port 22/tcp on 192.168.1.1
        Discovered open port 80/tcp on 192.168.1.1
        Discovered open port 443/tcp on 192.168.1.1
        """
        mock_result = MagicMock()
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("redaudit.core.masscan_scanner.is_masscan_available", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = masscan_sweep("192.168.1.1")
                assert result == [22, 80, 443]

    def test_handles_timeout(self):
        """Returns empty list on subprocess timeout."""
        import subprocess

        with patch("redaudit.core.masscan_scanner.is_masscan_available", return_value=True):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("masscan", 30)):
                result = masscan_sweep("192.168.1.1")
                assert result == []

    def test_deduplicates_ports(self):
        """Removes duplicate port entries."""
        mock_output = """
        Discovered open port 22/tcp on 192.168.1.1
        Discovered open port 22/tcp on 192.168.1.1
        Discovered open port 80/tcp on 192.168.1.1
        """
        mock_result = MagicMock()
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("redaudit.core.masscan_scanner.is_masscan_available", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = masscan_sweep("192.168.1.1")
                assert result == [22, 80]  # No duplicates


class TestMasscanBatchSweep:
    """Tests for masscan_batch_sweep()."""

    def test_returns_empty_dict_when_no_targets(self):
        """Returns empty dict for empty target list."""
        result = masscan_batch_sweep([])
        assert result == {}

    def test_returns_empty_when_not_available(self):
        """Returns empty dict when masscan not available."""
        with patch("redaudit.core.masscan_scanner.is_masscan_available", return_value=False):
            result = masscan_batch_sweep(["192.168.1.1", "192.168.1.2"])
            assert result == {}

    def test_parses_multi_host_output(self):
        """Parses output from multi-host scan correctly."""
        mock_output = """
        Discovered open port 22/tcp on 192.168.1.1
        Discovered open port 80/tcp on 192.168.1.2
        Discovered open port 443/tcp on 192.168.1.1
        Discovered open port 22/tcp on 192.168.1.2
        """
        mock_result = MagicMock()
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch("redaudit.core.masscan_scanner.is_masscan_available", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = masscan_batch_sweep(["192.168.1.1", "192.168.1.2"])
                assert result["192.168.1.1"] == [22, 443]
                assert result["192.168.1.2"] == [22, 80]

    def test_initializes_all_targets(self):
        """Initializes dict entry for all targets even with no ports."""
        mock_result = MagicMock()
        mock_result.stdout = "Discovered open port 22/tcp on 192.168.1.1"
        mock_result.stderr = ""

        with patch("redaudit.core.masscan_scanner.is_masscan_available", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = masscan_batch_sweep(["192.168.1.1", "192.168.1.2"])
                assert "192.168.1.1" in result
                assert "192.168.1.2" in result
                assert result["192.168.1.1"] == [22]
                assert result["192.168.1.2"] == []
