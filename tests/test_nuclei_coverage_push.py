"""
Tests for nuclei.py edge cases and missing coverage lines.
Target: Push nuclei.py from 79% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock
import os


class TestIsNucleiAvailable:
    """Tests for is_nuclei_available function."""

    def test_nuclei_available_true(self):
        """Test when nuclei is installed."""
        from redaudit.core.nuclei import is_nuclei_available

        with patch("shutil.which", return_value="/usr/bin/nuclei"):
            assert is_nuclei_available() is True

    def test_nuclei_available_false(self):
        """Test when nuclei is not installed."""
        from redaudit.core.nuclei import is_nuclei_available

        with patch("shutil.which", return_value=None):
            assert is_nuclei_available() is False


class TestGetNucleiVersion:
    """Tests for get_nuclei_version function."""

    def test_get_version_not_available(self):
        """Test returns None when nuclei not available."""
        from redaudit.core.nuclei import get_nuclei_version

        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=False):
            assert get_nuclei_version() is None

    def test_get_version_success(self):
        """Test successful version parsing."""
        from redaudit.core.nuclei import get_nuclei_version

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Nuclei Engine Version: v3.0.0"

        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
            with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_class:
                mock_runner = MagicMock()
                mock_runner_class.return_value = mock_runner
                mock_runner.run.return_value = mock_result
                result = get_nuclei_version()

        assert "3.0.0" in result or "Version" in result

    def test_get_version_bytes_output(self):
        """Test handling bytes output (lines 34-37)."""
        from redaudit.core.nuclei import get_nuclei_version

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"Nuclei Engine Version: v3.0.0"

        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
            with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_class:
                mock_runner = MagicMock()
                mock_runner_class.return_value = mock_runner
                mock_runner.run.return_value = mock_result
                result = get_nuclei_version()

        assert result is not None

    def test_get_version_exception(self):
        """Test exception handling (lines 44-46)."""
        from redaudit.core.nuclei import get_nuclei_version

        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
            with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_class:
                mock_runner_class.side_effect = Exception("Runner failed")
                result = get_nuclei_version()

        assert result is None


class TestRunNucleiScan:
    """Tests for run_nuclei_scan function."""

    def test_scan_nuclei_not_available(self):
        """Test returns error when nuclei not installed (lines 90-92)."""
        from redaudit.core.nuclei import run_nuclei_scan

        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=False):
            result = run_nuclei_scan(targets=["http://test"], output_dir="/tmp")

        assert result["success"] is False
        assert "not installed" in result["error"]

    def test_scan_no_targets(self):
        """Test returns error when no targets (lines 94-96)."""
        from redaudit.core.nuclei import run_nuclei_scan

        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
            result = run_nuclei_scan(targets=[], output_dir="/tmp")

        assert result["success"] is False
        assert "no targets" in result["error"]

    def test_scan_dry_run(self):
        """Test dry run mode (lines 98-103)."""
        from redaudit.core.nuclei import run_nuclei_scan

        mock_print = MagicMock()

        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
            with patch("redaudit.core.nuclei.is_dry_run", return_value=True):
                result = run_nuclei_scan(
                    targets=["http://test"],
                    output_dir="/tmp",
                    print_status=mock_print,
                )

        assert result["success"] is True
        assert "dry-run" in result["error"]

    def test_scan_targets_file_error(self, tmp_path):
        """Test targets file creation error (lines 114-116)."""
        from redaudit.core.nuclei import run_nuclei_scan

        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
            with patch("redaudit.core.nuclei.is_dry_run", return_value=False):
                with patch("builtins.open") as mock_open:
                    mock_open.side_effect = PermissionError("Access denied")
                    result = run_nuclei_scan(
                        targets=["http://test"],
                        output_dir=str(tmp_path),
                    )

        assert result["success"] is False
        assert "Failed to create" in result["error"]


class TestParseNucleiOutput:
    """Tests for _parse_nuclei_output internal function."""

    def test_nuclei_findings_structure(self, tmp_path):
        """Test that run_nuclei_scan returns expected structure."""
        from redaudit.core.nuclei import run_nuclei_scan

        # Just test the structure when nuclei is not available
        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=False):
            result = run_nuclei_scan(targets=["http://test"], output_dir=str(tmp_path))

        assert "success" in result
        assert "findings" in result
        assert "error" in result
