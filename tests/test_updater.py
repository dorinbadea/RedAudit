#!/usr/bin/env python3
"""
RedAudit - Updater Module Tests
Unit tests for updater helpers (no network, no root required).
"""

import os
import sys
import tempfile
import unittest

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.updater import compute_tree_diff, _inject_default_lang


class TestComputeTreeDiff(unittest.TestCase):
    def test_added_removed_modified(self):
        with tempfile.TemporaryDirectory() as old_dir, tempfile.TemporaryDirectory() as new_dir:
            # Old tree
            with open(os.path.join(old_dir, "same.txt"), "w", encoding="utf-8") as f:
                f.write("same")
            with open(os.path.join(old_dir, "removed.txt"), "w", encoding="utf-8") as f:
                f.write("bye")
            with open(os.path.join(old_dir, "modified.txt"), "w", encoding="utf-8") as f:
                f.write("v1")

            # New tree
            with open(os.path.join(new_dir, "same.txt"), "w", encoding="utf-8") as f:
                f.write("same")
            with open(os.path.join(new_dir, "added.txt"), "w", encoding="utf-8") as f:
                f.write("hi")
            with open(os.path.join(new_dir, "modified.txt"), "w", encoding="utf-8") as f:
                f.write("v2")

            diff = compute_tree_diff(old_dir, new_dir)
            self.assertEqual(diff["added"], ["added.txt"])
            self.assertEqual(diff["removed"], ["removed.txt"])
            self.assertEqual(diff["modified"], ["modified.txt"])


class TestInjectDefaultLang(unittest.TestCase):
    def test_injects_lang(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "constants.py")
            with open(path, "w", encoding="utf-8") as f:
                f.write('DEFAULT_LANG = "en"\n')
            ok = _inject_default_lang(path, "es")
            self.assertTrue(ok)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn('DEFAULT_LANG = "es"', content)

    def test_invalid_lang_defaults_to_en(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "constants.py")
            with open(path, "w", encoding="utf-8") as f:
                f.write('DEFAULT_LANG = "es"\n')
            ok = _inject_default_lang(path, "fr")
            self.assertTrue(ok)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn('DEFAULT_LANG = "en"', content)


if __name__ == "__main__":
    unittest.main()
