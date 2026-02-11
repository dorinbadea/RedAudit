"""Tests for subprocess management, signal handling, and progress callbacks in auditor.py."""

import os
import sys
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, PropertyMock

from redaudit.core.auditor import InteractiveNetworkAuditor


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestAuditorSubprocess(unittest.TestCase):
    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()

    def test_register_subprocess(self, *args):
        """Test registering a subprocess for tracking."""
        proc = MagicMock()
        self.auditor.register_subprocess(proc)
        self.assertIn(proc, self.auditor._active_subprocesses)

    def test_unregister_subprocess(self, *args):
        """Test unregistering a subprocess."""
        proc = MagicMock()
        self.auditor.register_subprocess(proc)
        self.auditor.unregister_subprocess(proc)
        self.assertNotIn(proc, self.auditor._active_subprocesses)

    def test_unregister_subprocess_not_found(self, *args):
        """Test unregistering a non-existent subprocess."""
        proc = MagicMock()
        self.auditor.unregister_subprocess(proc)  # Should not raise

    @patch("shutil.which", return_value="/usr/bin/pkill")
    @patch("subprocess.run")
    def test_kill_all_subprocesses_running(self, mock_run, mock_which, *args):
        """Test killing tracked subprocesses that are still running."""
        proc = MagicMock()
        proc.poll.return_value = None  # Still running
        self.auditor.register_subprocess(proc)

        self.auditor.kill_all_subprocesses()

        proc.terminate.assert_called_once()
        proc.wait.assert_called()
        self.assertEqual(len(self.auditor._active_subprocesses), 0)

    @patch("shutil.which", return_value="/usr/bin/pkill")
    @patch("subprocess.run")
    def test_kill_all_subprocesses_already_done(self, mock_run, mock_which, *args):
        """Test killing subprocesses that already terminated."""
        proc = MagicMock()
        proc.poll.return_value = 0  # Already done
        self.auditor.register_subprocess(proc)

        self.auditor.kill_all_subprocesses()

        proc.terminate.assert_not_called()
        self.assertEqual(len(self.auditor._active_subprocesses), 0)

    @patch("shutil.which", return_value="/usr/bin/pkill")
    @patch("subprocess.run")
    def test_kill_all_subprocesses_timeout_then_kill(self, mock_run, mock_which, *args):
        """Test subprocess that doesn't terminate gracefully gets killed."""
        import subprocess as sp

        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.side_effect = [sp.TimeoutExpired("cmd", 2), None]
        self.auditor.register_subprocess(proc)

        self.auditor.kill_all_subprocesses()

        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    @patch("shutil.which", return_value=None)
    def test_kill_all_subprocesses_no_pkill(self, mock_which, *args):
        """Test zombie reaper works without pkill."""
        self.auditor.kill_all_subprocesses()  # Should not raise

    @patch("shutil.which", return_value="/usr/bin/pkill")
    @patch("subprocess.run")
    def test_kill_all_subprocesses_exception(self, mock_run, mock_which, *args):
        """Test handling of exception during subprocess kill."""
        proc = MagicMock()
        proc.poll.return_value = None
        proc.terminate.side_effect = OSError("Process already gone")
        self.auditor.register_subprocess(proc)

        self.auditor.kill_all_subprocesses()  # Should not raise

    def test_signal_handler_no_scan_started(self, *args):
        """Test signal handler when scan hasn't started (exits immediately)."""
        self.auditor.scan_start_time = None
        self.auditor.interrupted = False
        self.auditor.stop_heartbeat = MagicMock()

        with self.assertRaises(SystemExit):
            self.auditor.signal_handler(2, None)

        self.assertTrue(self.auditor.interrupted)
        self.assertEqual(self.auditor.current_phase, "interrupted")

    def test_signal_handler_scan_in_progress(self, *args):
        """Test signal handler during active scan (saves progress)."""
        self.auditor.scan_start_time = datetime.now()
        self.auditor.interrupted = False
        self.auditor.stop_heartbeat = MagicMock()

        self.auditor.signal_handler(2, None)

        self.assertTrue(self.auditor.interrupted)
        self.assertEqual(self.auditor.current_phase, "interrupted")
        self.auditor.ui.print_status.assert_called()

    def test_signal_handler_with_active_subprocesses(self, *args):
        """Test signal handler with active subprocesses."""
        self.auditor.scan_start_time = datetime.now()
        self.auditor.interrupted = False
        self.auditor.stop_heartbeat = MagicMock()

        proc = MagicMock()
        proc.poll.return_value = None
        self.auditor._active_subprocesses.append(proc)

        with patch.object(self.auditor, "kill_all_subprocesses") as mock_kill:
            self.auditor.signal_handler(2, None)
            mock_kill.assert_called_once()

    def test_signal_handler_no_ui(self, *args):
        """Test signal handler without UI (early init)."""
        del self.auditor.ui
        self.auditor.scan_start_time = None
        self.auditor.stop_heartbeat = MagicMock()

        with self.assertRaises(SystemExit):
            self.auditor.signal_handler(2, None)

    def test_nd_progress_callback(self, *args):
        """Test net discovery progress callback."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()

        self.auditor._nd_progress_callback(
            label="ARP scan",
            step_index=5,
            step_total=10,
            progress=progress,
            task=task,
            start_time=time.time(),
        )

        progress.update.assert_called_once()
        self.auditor._touch_activity.assert_called_once()

    def test_nd_progress_callback_long_label(self, *args):
        """Test progress callback truncates long labels."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()

        long_label = "A" * 50
        self.auditor._nd_progress_callback(
            label=long_label,
            step_index=5,
            step_total=10,
            progress=progress,
            task=task,
            start_time=time.time(),
        )

        call_kwargs = progress.update.call_args
        desc = call_kwargs[1]["description"]
        self.assertIn("…", desc)

    def test_nd_progress_callback_heartbeat(self, *args):
        """Test heartbeat fires after 30s via UI fallback."""
        progress = MagicMock()
        # Remove console attr to trigger the fallback path
        del progress.console
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._nd_last_heartbeat = time.time() - 31

        self.auditor._nd_progress_callback(
            label="Scan",
            step_index=5,
            step_total=10,
            progress=progress,
            task=task,
            start_time=time.time() - 60,
        )

        self.auditor.ui.print_status.assert_called()

    def test_nd_progress_callback_zero_total(self, *args):
        """Test progress callback with zero total."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()

        self.auditor._nd_progress_callback(
            label="Empty",
            step_index=0,
            step_total=0,
            progress=progress,
            task=task,
            start_time=time.time(),
        )
        progress.update.assert_called_once()

    def test_nd_progress_callback_complete(self, *args):
        """Test progress callback caps at 99%."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()

        self.auditor._nd_progress_callback(
            label="Done",
            step_index=10,
            step_total=10,
            progress=progress,
            task=task,
            start_time=time.time(),
        )
        call_kwargs = progress.update.call_args[1]
        self.assertEqual(call_kwargs["completed"], 99)

    def test_nuclei_progress_callback(self, *args):
        """Test nuclei progress callback."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="5m")

        self.auditor._nuclei_progress_callback(
            completed=5.0,
            total=10,
            eta="5m",
            progress=progress,
            task=task,
            start_time=time.time() - 10,
            timeout=300,
            total_targets=50,
            batch_size=10,
        )

        progress.update.assert_called_once()

    def test_nuclei_progress_callback_running_detail(self, *args):
        """Test nuclei callback with 'running' detail text."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="")

        self.auditor._nuclei_progress_callback(
            completed=5.0,
            total=10,
            eta="",
            progress=progress,
            task=task,
            start_time=time.time() - 10,
            timeout=300,
            total_targets=50,
            batch_size=10,
            detail="running batch 3",
        )

        progress.update.assert_called_once()

    def test_nuclei_progress_callback_regression_guard(self, *args):
        """Test nuclei callback prevents progress regression."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="")

        # First call sets max
        self.auditor._nuclei_progress_callback(
            completed=8.0,
            total=10,
            eta="",
            progress=progress,
            task=task,
            start_time=time.time() - 10,
            timeout=300,
            total_targets=50,
            batch_size=10,
        )
        # Second call with lower progress
        self.auditor._nuclei_progress_callback(
            completed=3.0,
            total=10,
            eta="",
            progress=progress,
            task=task,
            start_time=time.time() - 20,
            timeout=300,
            total_targets=50,
            batch_size=10,
        )
        # The second call should use the max seen value, not regress
        last_call = progress.update.call_args_list[-1]
        self.assertGreaterEqual(last_call[1]["completed"], 30)


if __name__ == "__main__":
    unittest.main()
