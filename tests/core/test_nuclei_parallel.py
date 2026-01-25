#!/usr/bin/env python3
"""
RedAudit - Tests for parallel Nuclei batch execution.
"""

import time
import unittest
import tempfile
import os
import json
from unittest.mock import MagicMock, patch
from redaudit.core.nuclei import run_nuclei_scan


class _FakeRunResult:
    def __init__(self):
        self.returncode = 0
        self.stdout = ""
        self.stderr = ""
        self.timed_out = False


class _FakeCommandRunnerParallel:
    def __init__(self, *args, **kwargs):
        pass

    def run(self, cmd, *args, **kwargs):
        # Simulate work
        time.sleep(0.5)

        # Simulate Nuclei writing findings to the batch output file
        if "-o" in cmd:
            try:
                idx = cmd.index("-o") + 1
                out_path = cmd[idx]
                # Ensure directory exists (nuclei does this)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as f:
                    # Write one finding per batch execution
                    payload = {
                        "template-id": "parallel-test",
                        "info": {"name": "Parallel Test", "severity": "info"},
                        "host": "http://127.0.0.1",
                        "matched-at": "http://127.0.0.1",
                    }
                    f.write(json.dumps(payload) + "\n")
            except Exception:
                pass

        return _FakeRunResult()


class TestNucleiParallel(unittest.TestCase):
    def test_batches_run_in_parallel_and_output_safety(self):
        """
        Verify that:
        1. 4 batches of 0.5s run in parallel (< 1.5s total).
        2. All 4 batches write their output successfully (thread safety check).
        """
        targets = [f"http://127.0.0.{i}:80" for i in range(40)]  # 40 targets => 4 batches of 10

        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
                with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
                    with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunnerParallel):
                        res = run_nuclei_scan(
                            targets=targets,
                            output_dir=tmpdir,
                            batch_size=10,
                            progress_callback=lambda c, t, e: None,
                            use_internal_progress=False,
                        )

            # Duration check
            duration = time.time() - start_time

            # File integrity check
            outfile = res.get("raw_output_file")
            self.assertTrue(outfile and os.path.exists(outfile), "Output file should exist")

            with open(outfile, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # We expect exactly 4 lines (one per batch)
            self.assertEqual(
                len(lines),
                4,
                f"Expected 4 finding lines, got {len(lines)}. Possible lost write race condition.",
            )

        self.assertTrue(res["success"])
        # If sequential: 4 * 0.5 = 2.0s
        # If parallel: max(0.5) = 0.5s + overhead
        self.assertLess(duration, 1.5, f"Execution took {duration}s, expected < 1.5s (parallel)")
        self.assertGreater(duration, 0.4, "Execution surely took at least 0.4s")

    def test_parallel_with_one_batch(self):
        """Verify it handles single batch case correctly too."""
        targets = ["http://127.0.0.1:80"]
        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
                with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
                    with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunnerParallel):
                        res = run_nuclei_scan(
                            targets=targets,
                            output_dir=tmpdir,
                            batch_size=10,
                            progress_callback=lambda c, t, e: None,
                        )

        duration = time.time() - start_time
        self.assertTrue(res["success"])
        self.assertLess(duration, 1.0)

    def test_parallel_progress_is_monotonic(self):
        """
        Verify that progress updates are monotonic (never go backwards).
        This ensures the 'jitter' bug (threads overwriting global progress with local low values) is gone.
        """
        targets = [f"http://127.0.0.{i}:80" for i in range(40)]
        progress_values = []

        def _cb(completed, total, eta, detail=""):
            progress_values.append(completed)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
                with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
                    with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunnerParallel):
                        res = run_nuclei_scan(
                            targets=targets,
                            output_dir=tmpdir,
                            batch_size=10,
                            progress_callback=_cb,
                            use_internal_progress=False,  # Use external callback logic
                        )

        self.assertTrue(res["success"])
        self.assertTrue(len(progress_values) > 0, "Should have received progress updates")

        # Check monotony: each value must be >= max of previous values (approx)
        # Actually, since threads update referencing a shared 'completed_targets',
        # providing we lock effectively, the reported 'current' should never decrease significantly.
        # It might stay same, or increase.

        max_seen = -1.0
        for val in progress_values:
            # Allow tiny float precision error, but essentially explicit decreases are bad.
            # The bug caused jumps like 10 -> 2. So we check for gross violations.
            if val < max_seen - 0.1:
                self.fail(f"Progress went backwards! Seen {max_seen}, got {val}")
            if val > max_seen:
                max_seen = val

        self.assertEqual(max_seen, 40.0, "Should have reached 100% (40 targets)")

    def test_parallel_clamps_when_timeout_high(self):
        targets = [f"http://127.0.0.{i}:80" for i in range(40)]
        seen = {}

        class _ImmediateFuture:
            def __init__(self, fn, *args, **kwargs):
                self._result = fn(*args, **kwargs)

            def result(self):
                return self._result

        class _DummyExecutor:
            def __init__(self, max_workers=None):
                seen["max_workers"] = max_workers

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn, *args, **kwargs):
                return _ImmediateFuture(fn, *args, **kwargs)

        def _as_completed(futures):
            return futures

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
                with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
                    with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunnerParallel):
                        with patch("concurrent.futures.ThreadPoolExecutor", _DummyExecutor):
                            with patch("concurrent.futures.as_completed", _as_completed):
                                res = run_nuclei_scan(
                                    targets=targets,
                                    output_dir=tmpdir,
                                    batch_size=10,
                                    timeout=900,
                                    progress_callback=lambda c, t, e, detail="": None,
                                    use_internal_progress=False,
                                )

        self.assertTrue(res["success"])
        self.assertEqual(seen.get("max_workers"), 2)
