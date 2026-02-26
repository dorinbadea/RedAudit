"""Tests for subprocess management, signal handling, and progress callbacks in auditor.py."""

import contextlib
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

    def test_nuclei_progress_render_context_sets_and_restores_state(self, *args):
        """Nuclei render context must mark progress active and restore state on exit."""
        ui = MagicMock()
        ui.progress_context.return_value = contextlib.nullcontext()
        ui._active_progress_console = None
        self.auditor.ui = ui
        self.auditor._ui_progress_active = False

        with self.auditor._nuclei_progress_render_context("console-ref"):
            self.assertTrue(self.auditor._ui_progress_active)
            self.assertEqual(self.auditor.ui._active_progress_console, "console-ref")

        self.assertFalse(self.auditor._ui_progress_active)
        self.assertIsNone(self.auditor.ui._active_progress_console)

    def test_nuclei_progress_render_context_fallback_when_progress_context_fails(self, *args):
        """Context helper should still toggle progress state if UI progress_context errors."""
        ui = MagicMock()
        ui.progress_context.side_effect = RuntimeError("boom")
        ui._active_progress_console = "old-console"
        self.auditor.ui = ui
        self.auditor._ui_progress_active = False

        with self.auditor._nuclei_progress_render_context("new-console"):
            self.assertTrue(self.auditor._ui_progress_active)
            self.assertEqual(self.auditor.ui._active_progress_console, "new-console")

        self.assertFalse(self.auditor._ui_progress_active)
        self.assertEqual(self.auditor.ui._active_progress_console, "old-console")

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
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *vals: f"{key}:{vals}")
        self.auditor.ui.print_status = MagicMock()

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
        call_kwargs = progress.update.call_args.kwargs
        assert call_kwargs["detail"] == ""
        self.auditor.ui.print_status.assert_called_once()

    def test_nuclei_progress_callback_updates_secondary_telemetry_task(self, *args):
        """With a telemetry task, details stay in Live progress and do not spam INFO logs."""
        progress = MagicMock()
        telemetry_progress = MagicMock()
        task = MagicMock()
        telemetry_task = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="0:10")
        self.auditor.ui.print_status = MagicMock()

        self.auditor._nuclei_progress_callback(
            completed=5.0,
            total=10,
            eta="",
            progress=progress,
            task=task,
            start_time=time.time() - 20,
            timeout=300,
            total_targets=50,
            batch_size=5,
            telemetry_task=telemetry_task,
            telemetry_progress=telemetry_progress,
            detail=(
                "active batches 2/4 | sub-batch elapsed 0:12 | split depth 3/6 (current/max) "
                "| total elapsed shown in timer"
            ),
        )

        assert progress.update.call_count == 1
        telemetry_update = telemetry_progress.update.call_args.kwargs
        assert telemetry_update["description"].startswith("[bright_blue]AB 2/4")
        assert "SB 0:12" in telemetry_update["description"]
        assert "SD 3/6" in telemetry_update["description"]
        self.auditor.ui.print_status.assert_not_called()

    def test_nuclei_progress_callback_sub_batch_clamps_completion(self, *args):
        """Sub-batch detail should keep task open until final completion."""
        progress = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="0:10")
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *vals: f"{key}:{vals}")
        self.auditor.ui.print_status = MagicMock()
        self.auditor._nuclei_progress_state = {"total_targets": 7, "max_targets": 0}

        self.auditor._nuclei_progress_callback(
            completed=7.0,
            total=7,
            eta="",
            progress=progress,
            task="task",
            start_time=time.time() - 20,
            timeout=300,
            total_targets=7,
            batch_size=1,
            detail="batch 1/1 | sub-batch elapsed 0:05 | split depth 1/5",
        )

        call_kwargs = progress.update.call_args.kwargs
        assert call_kwargs["completed"] == 6

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

    def test_nuclei_progress_callback_ignores_sub_batch_elapsed_for_state(self, *args):
        """Do not emit a new telemetry line when only sub-batch elapsed changes."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="5:00")
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *vals: f"{key}:{vals}")
        self.auditor.ui.print_status = MagicMock()
        self.auditor._nuclei_progress_log_state = {
            "last_emit_ts": 0.0,
            "last_state": "",
            "heartbeat_s": 30.0,
        }

        self.auditor._nuclei_progress_callback(
            completed=5.0,
            total=10,
            eta="",
            progress=progress,
            task=task,
            start_time=time.time() - 20,
            timeout=300,
            total_targets=50,
            batch_size=5,
            detail=(
                "active batches 1/4 | sub-batch elapsed 0:10 | split depth 2/8 (current/max) "
                "| total elapsed shown in timer"
            ),
        )
        self.auditor._nuclei_progress_callback(
            completed=5.0,
            total=10,
            eta="",
            progress=progress,
            task=task,
            start_time=time.time() - 20,
            timeout=300,
            total_targets=50,
            batch_size=5,
            detail=(
                "active batches 1/4 | sub-batch elapsed 0:12 | split depth 2/8 (current/max) "
                "| total elapsed shown in timer"
            ),
        )

        self.assertEqual(self.auditor.ui.print_status.call_count, 1)

    def test_nuclei_progress_callback_heartbeat_emits_same_state(self, *args):
        """Heartbeat should still emit telemetry even when the state is unchanged."""
        progress = MagicMock()
        task = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="5:00")
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *vals: f"{key}:{vals}")
        self.auditor.ui.print_status = MagicMock()
        self.auditor._nuclei_progress_log_state = {
            "last_emit_ts": time.time() - 31.0,
            "last_state": "active batches 1/4 | split depth 2/8",
            "heartbeat_s": 30.0,
        }

        self.auditor._nuclei_progress_callback(
            completed=5.0,
            total=10,
            eta="",
            progress=progress,
            task=task,
            start_time=time.time() - 20,
            timeout=300,
            total_targets=50,
            batch_size=5,
            detail=(
                "active batches 1/4 | sub-batch elapsed 0:42 | split depth 2/8 (current/max) "
                "| total elapsed shown in timer"
            ),
        )

        self.auditor.ui.print_status.assert_called_once()

    def test_nuclei_progress_callback_compacts_spanish_tokens(self, *args):
        """Spanish detail tokens are normalized to compact AB/B/SB/SD style."""
        line = self.auditor._build_nuclei_telemetry_line(
            "lotes activos 3/4 | tiempo de sub-lote 0:15 | profundidad de division 2/8 (actual/maximo)",
            completed=1.0,
            total=4,
        )
        assert "AB 3/4" in line
        assert "SB 0:15" in line
        assert "SD 2/8" in line

    def test_build_nuclei_telemetry_line_handles_non_string_detail_and_fallback(self, *args):
        """Non-string details should safely fallback to compact batch counters."""
        line = self.auditor._build_nuclei_telemetry_line(None, completed=3.0, total=7)
        assert line == "B 3/7"

    def test_build_nuclei_telemetry_line_supports_retry_and_complete_tokens(self, *args):
        """Retry and completion tokens should map to compact output without loss."""
        line = self.auditor._build_nuclei_telemetry_line(
            "retry 2 | batches 2/2 complete",
            completed=2.0,
            total=2,
        )
        assert "R 2" in line
        assert "batches 2/2 complete" in line

    def test_build_nuclei_telemetry_line_appends_timeout_suffix(self, *args):
        self.auditor._nuclei_timeout_agg = {
            "events": 2,
            "batches": {"1/3": {"events": 2}},
            "details": [],
            "last_event_ts": 0.0,
        }
        line = self.auditor._build_nuclei_telemetry_line("active batches 1/3", completed=1, total=3)
        assert "TO 2 | TB 1" in line

    def test_parse_nuclei_timeout_message_extracts_fields(self, *args):
        parsed = self.auditor._parse_nuclei_timeout_message(
            "Nuclei timeout in batch 2/4: hosts 192.168.1.1(2), 192.168.1.2(1); ports 80, 443"
        )
        assert parsed is not None
        assert parsed["batch_idx"] == 2
        assert parsed["total_batches"] == 4
        assert parsed["host_list"].startswith("192.168.1.1")
        assert parsed["port_list"] == "80, 443"

    def test_parse_nuclei_timeout_message_rejects_invalid_inputs(self, *args):
        assert self.auditor._parse_nuclei_timeout_message(123) is None
        assert (
            self.auditor._parse_nuclei_timeout_message("nuclei timeout without batch data") is None
        )
        assert self.auditor._parse_nuclei_timeout_message("✅✅✅") is None

    def test_record_timeout_event_resets_non_dict_aggregation(self, *args):
        self.auditor._nuclei_timeout_agg = "invalid"
        self.auditor._record_nuclei_timeout_event(
            {
                "batch_idx": 1,
                "total_batches": 2,
                "detail": "hosts 10.0.0.1(1); ports 80",
                "host_list": "10.0.0.1(1)",
                "port_list": "80",
            }
        )
        assert self.auditor._nuclei_timeout_agg["events"] == 1

    def test_timeout_compact_suffix_handles_invalid_agg(self, *args):
        self.auditor._nuclei_timeout_agg = None
        assert self.auditor._nuclei_timeout_compact_suffix() == ""

    def test_make_nuclei_status_adapter_suppresses_live_timeout_warning(self, *args):
        self.auditor.ui.print_status = MagicMock()
        adapter = self.auditor._make_nuclei_status_adapter(live_progress=True)

        adapter(
            "Nuclei timeout in batch 1/3: hosts 192.168.1.1(1); ports 80",
            "WARNING",
            None,
        )

        assert self.auditor._nuclei_timeout_agg["events"] == 1
        self.auditor.ui.print_status.assert_not_called()

    def test_make_nuclei_status_adapter_forwards_when_not_live(self, *args):
        self.auditor.ui.print_status = MagicMock()
        adapter = self.auditor._make_nuclei_status_adapter(live_progress=False)

        adapter(
            "Nuclei timeout in batch 1/2: hosts 192.168.1.1(1); ports 80",
            "WARNING",
            None,
        )

        assert self.auditor._nuclei_timeout_agg["events"] == 0
        self.auditor.ui.print_status.assert_called_once()

    def test_make_nuclei_status_adapter_uses_timeout_metadata_payload(self, *args):
        self.auditor.ui.print_status = MagicMock()
        adapter = self.auditor._make_nuclei_status_adapter(live_progress=True)

        adapter(
            "ignored",
            "WARNING",
            {
                "event": "nuclei_timeout",
                "batch_idx": 3,
                "total_batches": 4,
                "detail": "hosts 10.0.0.3(1); ports 443",
                "host_list": "10.0.0.3(1)",
                "port_list": "443",
            },
        )

        assert self.auditor._nuclei_timeout_agg["events"] == 1
        self.auditor.ui.print_status.assert_not_called()

    def test_emit_nuclei_timeout_summary_limits_lines_and_reports_more(self, *args):
        self.auditor.ui.print_status = MagicMock()
        self.auditor.ui.t = lambda key, *vals: f"{key}:{','.join(str(v) for v in vals)}"
        self.auditor._reset_nuclei_timeout_aggregation()
        for idx in range(1, 11):
            self.auditor._record_nuclei_timeout_event(
                {
                    "batch_idx": idx,
                    "total_batches": 10,
                    "detail": f"hosts 10.0.0.{idx}(1); ports 80",
                    "host_list": f"10.0.0.{idx}(1)",
                    "port_list": "80",
                }
            )

        summary = self.auditor._emit_nuclei_timeout_summary()

        assert summary["timeout_events_count"] == 10
        assert summary["timeout_batches_count"] == 10
        assert summary["timeout_summary_compact"] == "TO 10 | TB 10"
        rendered = [call.args[0] for call in self.auditor.ui.print_status.call_args_list]
        assert any("nuclei_timeout_summary_final" in msg for msg in rendered)
        assert any("nuclei_timeout_summary_more" in msg for msg in rendered)

    def test_emit_nuclei_timeout_summary_handles_invalid_agg(self, *args):
        self.auditor._nuclei_timeout_agg = "bad"
        summary = self.auditor._emit_nuclei_timeout_summary()
        assert summary["timeout_events_count"] == 0
        assert summary["timeout_batches_count"] == 0
        assert summary["timeout_summary_compact"] == ""

    def test_nuclei_progress_render_context_without_ui_uses_nullcontext(self, *args):
        del self.auditor.ui
        with self.auditor._nuclei_progress_render_context("console-ref"):
            pass

    def test_sanitize_terminal_status_text_non_string(self, *args):
        assert self.auditor._sanitize_terminal_status_text(123) == ""

    def test_sanitize_terminal_status_text_strips_non_ascii(self, *args):
        cleaned = self.auditor._sanitize_terminal_status_text("AB 1/2 | SB 0:10 ✅")
        assert "✅" not in cleaned
        assert cleaned == "AB 1/2 | SB 0:10"

    def test_nuclei_progress_callback_marks_compact_ab_detail_as_running(self, *args):
        """Compact AB detail must keep progress one step below completion while running."""
        progress = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="")

        self.auditor._nuclei_progress_callback(
            completed=10.0,
            total=10,
            eta="",
            progress=progress,
            task="task",
            start_time=time.time() - 5,
            timeout=300,
            total_targets=10,
            batch_size=1,
            detail="AB 1/2 | SB 0:05",
        )

        call_kwargs = progress.update.call_args.kwargs
        assert call_kwargs["completed"] == 9

    def test_nuclei_progress_callback_uses_primary_progress_when_secondary_missing(self, *args):
        """When telemetry task exists but no telemetry progress is passed, reuse main progress."""
        progress = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = MagicMock(return_value="")

        self.auditor._nuclei_progress_callback(
            completed=1.0,
            total=2,
            eta="",
            progress=progress,
            task="task",
            start_time=time.time() - 5,
            timeout=300,
            total_targets=2,
            batch_size=1,
            telemetry_task="telemetry",
            detail="batch 1/2 | sub-batch elapsed 0:02",
        )

        assert progress.update.call_count >= 2

    @patch("redaudit.core.auditor.os.listdir", side_effect=OSError("boom"))
    def test_find_nuclei_resume_candidates_handles_listdir_exception(self, _mock_listdir, *args):
        result = self.auditor._find_nuclei_resume_candidates("/tmp")
        assert result == []
        self.auditor.logger.debug.assert_called()


if __name__ == "__main__":
    unittest.main()
