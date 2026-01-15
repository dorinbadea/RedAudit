#!/usr/bin/env python3
"""
RedAudit - Tests for parallel Nuclei batch execution.
"""

import time
import unittest
import tempfile
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
        return _FakeRunResult()


class TestNucleiParallel(unittest.TestCase):
    def test_batches_run_in_parallel(self):
        """
        Verify that 4 batches of 0.5s each run in approx 0.5s total (parallel)
        instead of 2.0s total (sequential).
        We allow some overhead, so we assert < 1.0s.
        """
        targets = [f"http://127.0.0.{i}:80" for i in range(40)]  # 40 targets
        # batch_size=10 => 4 batches

        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
                # Mock is_nuclei_available to avoid real check
                with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
                    with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunnerParallel):
                        res = run_nuclei_scan(
                            targets=targets,
                            output_dir=tmpdir,
                            batch_size=10,
                            progress_callback=lambda c, t, e: None,
                            use_internal_progress=False,
                        )

        duration = time.time() - start_time

        self.assertTrue(res["success"])
        # If sequential: 4 * 0.5 = 2.0s
        # If parallel: max(0.5) = 0.5s + overhead
        # We assert it took less than 1.5s to be safe but prove parallelism
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
        # Should be approx 0.5s
        self.assertLess(duration, 1.0)
