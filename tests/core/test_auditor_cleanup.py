import os
import signal
import subprocess
import shutil
from unittest.mock import MagicMock, patch
import pytest
from redaudit.core.auditor import InteractiveNetworkAuditor as Auditor


class TestAuditorCleanup:
    @pytest.fixture
    def mock_auditor(self):
        # Create a skeletal mock config
        mock_config = MagicMock()
        mock_config.get.return_value = False

        # Mock dependencies
        with (
            patch("redaudit.core.auditor.ConfigurationContext", return_value=mock_config),
            patch("redaudit.core.auditor.NetworkScanner"),
            patch("redaudit.core.ui_manager.UIManager"),
            patch("redaudit.core.auditor.signal.signal"),
        ):

            auditor = Auditor()
            auditor.logger = MagicMock()
            return auditor

    @patch("shutil.which")
    @patch("subprocess.run")
    @patch("os.getpid", return_value=12345)
    def test_kill_all_subprocesses_calls_pkill(
        self, mock_getpid, mock_run, mock_which, mock_auditor
    ):
        """Verify that kill_all_subprocesses calls pkill -P <PID> if pkill is available."""
        # Setup: pkill exists
        mock_which.return_value = "/usr/bin/pkill"

        # Action
        mock_auditor.kill_all_subprocesses()

        # Assert
        mock_which.assert_called_with("pkill")
        mock_run.assert_called_with(
            ["pkill", "-P", "12345"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        mock_auditor.logger.debug.assert_not_called()

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_kill_all_subprocesses_skips_if_no_pkill(self, mock_run, mock_which, mock_auditor):
        """Verify that pkill is skipped if not found in PATH."""
        # Setup: pkill missing
        mock_which.return_value = None

        # Action
        mock_auditor.kill_all_subprocesses()

        # Assert
        mock_which.assert_called_with("pkill")
        mock_run.assert_not_called()

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_kill_all_subprocesses_handles_error(self, mock_run, mock_which, mock_auditor):
        """Verify that pkill errors are caught and logged."""
        # Setup: pkill exists but fails
        mock_which.return_value = "/usr/bin/pkill"
        mock_run.side_effect = Exception("Pkill access denied")

        # Action
        mock_auditor.kill_all_subprocesses()

        # Assert
        mock_auditor.logger.debug.assert_called_with(
            "Zombie Reaper failed: %s", mock_run.side_effect
        )
