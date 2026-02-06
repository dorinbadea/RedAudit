#!/usr/bin/env python3
"""
Tests for Thread Limit Logic (v4.6.29).
"""

from unittest.mock import MagicMock

from redaudit.core.auditor_scan import AuditorScan
from redaudit.utils.constants import MAX_THREADS


class TestThreadLimits:
    def test_deep_scan_respects_max_threads(self, monkeypatch):
        """Verify that deep scan worker count respects high thread config up to MAX_THREADS."""
        scan = AuditorScan()

        # Mock config to request 100 threads
        scan.config = {"threads": 200}

        # Mock UI
        scan.ui = MagicMock()
        scan.ui.get_progress_console.return_value = None

        # Mock _progress_ui context manager (v4.6.26+)
        scan._progress_ui = MagicMock()
        scan._progress_ui.return_value.__enter__.return_value = None
        scan._progress_ui.return_value.__exit__.return_value = None

        scan.interrupted = False

        # Captures
        captured_workers = None

        # Monkeypatch ThreadPoolExecutor to inspect max_workers
        class MockExecutor:
            def __init__(self, max_workers=None):
                nonlocal captured_workers
                captured_workers = max_workers

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def submit(self, *args, **kwargs):
                f = MagicMock()
                f.result.return_value = None
                return f

        monkeypatch.setattr("redaudit.core.auditor_scan.ThreadPoolExecutor", MockExecutor)

        # Mock wait to return immediately (all done)
        def mock_wait(fs, **kwargs):
            return fs, []  # completed=fs, pending=[]

        monkeypatch.setattr("redaudit.core.auditor_scan.wait", mock_wait)

        # Mock as_completed to return immediately (v4.10.1 fix for fallback path)
        def mock_as_completed(fs, timeout=None):
            return list(fs)

        monkeypatch.setattr("redaudit.core.auditor_scan.as_completed", mock_as_completed)

        # Fake hosts
        class MockHost:
            def __init__(self, i):
                self.ip = f"192.168.1.{i}"

        hosts = [MockHost(i) for i in range(150)]

        # Run
        scan.run_deep_scans_concurrent(hosts)

        # Assert
        assert captured_workers == MAX_THREADS
        assert captured_workers == 100

    def test_deep_scan_respects_low_threads(self, monkeypatch):
        """Verify that deep scan respects low thread config."""
        scan = AuditorScan()
        scan.config = {"threads": 5}
        scan.ui = MagicMock()

        # Mock _progress_ui context manager
        scan._progress_ui = MagicMock()
        scan._progress_ui.return_value.__enter__.return_value = None
        scan._progress_ui.return_value.__exit__.return_value = None

        scan.interrupted = False

        captured_workers = None

        class MockExecutor:
            def __init__(self, max_workers=None):
                nonlocal captured_workers
                captured_workers = max_workers

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def submit(self, *args, **kwargs):
                return MagicMock()

        monkeypatch.setattr("redaudit.core.auditor_scan.ThreadPoolExecutor", MockExecutor)
        # Mock wait to return immediately
        monkeypatch.setattr("redaudit.core.auditor_scan.wait", lambda fs, **kw: (fs, []))

        class MockHost:
            def __init__(self, i):
                self.ip = f"10.0.0.{i}"

        scan.run_deep_scans_concurrent([MockHost(i) for i in range(10)])

        assert captured_workers == 5
