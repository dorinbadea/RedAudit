#!/usr/bin/env python3
"""
RedAudit - i18n Tests
Unit tests for language detection helpers.
"""

import os
import sys
import unittest
from unittest.mock import patch

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.utils.i18n import detect_preferred_language


class TestDetectPreferredLanguage(unittest.TestCase):
    def test_prefers_explicit_value(self):
        self.assertEqual(detect_preferred_language("es"), "es")
        self.assertEqual(detect_preferred_language("en"), "en")

    def test_detects_from_env_lang(self):
        with patch.dict(os.environ, {"LANG": "es_ES.UTF-8"}, clear=True):
            self.assertEqual(detect_preferred_language(None), "es")

    def test_falls_back_to_en_for_unknown(self):
        with (
            patch.dict(os.environ, {"LANG": "C.UTF-8"}, clear=True),
            patch("locale.getlocale", return_value=(None, None)),
            patch("locale.getdefaultlocale", return_value=(None, None)),
        ):
            self.assertEqual(detect_preferred_language(None), "en")


if __name__ == "__main__":
    unittest.main()

