"""Tests for suggest_threads() function in constants.py."""

import unittest
from unittest.mock import patch


class TestSuggestThreads(unittest.TestCase):
    """Test cases for thread autodetection."""

    def test_suggest_threads_returns_integer(self):
        """suggest_threads() should always return an integer."""
        from redaudit.utils.constants import suggest_threads

        result = suggest_threads()
        self.assertIsInstance(result, int)

    def test_suggest_threads_within_bounds(self):
        """Result must be between MIN_THREADS+1 and MAX_THREADS."""
        from redaudit.utils.constants import suggest_threads, MIN_THREADS, MAX_THREADS

        result = suggest_threads()
        self.assertGreaterEqual(result, MIN_THREADS + 1)
        self.assertLessEqual(result, MAX_THREADS)

    def test_suggest_threads_caps_at_12(self):
        """Result should cap at 12 even if more cores available."""
        from redaudit.utils.constants import suggest_threads

        with patch("os.cpu_count", return_value=32):
            result = suggest_threads()
            self.assertEqual(result, 12)

    def test_suggest_threads_uses_cores_when_low(self):
        """Result should equal cores when cores <= 12."""
        from redaudit.utils.constants import suggest_threads

        with patch("os.cpu_count", return_value=4):
            result = suggest_threads()
            self.assertEqual(result, 4)

    def test_suggest_threads_minimum_is_2(self):
        """Result should be at least 2 even on single-core."""
        from redaudit.utils.constants import suggest_threads

        with patch("os.cpu_count", return_value=1):
            result = suggest_threads()
            self.assertEqual(result, 2)

    def test_suggest_threads_fallback_when_cpu_count_none(self):
        """Should fallback to 4 when os.cpu_count() returns None."""
        from redaudit.utils.constants import suggest_threads

        with patch("os.cpu_count", return_value=None):
            result = suggest_threads()
            self.assertEqual(result, 4)


if __name__ == "__main__":
    unittest.main()
