#!/usr/bin/env python3
"""
RedAudit - Updater Module Tests
Unit tests for updater helpers (no network, no root required).
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.updater import (
    compute_tree_diff,
    _inject_default_lang,
    format_release_notes_for_cli,
    restart_self,
)


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


class TestReleaseNotesFormatting(unittest.TestCase):
    def test_format_release_notes_strips_markdown_noise(self):
        notes = """# RedAudit v3.1.1 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.1.1_ES.md)

## Overview

- **Topology**: New `topology` block in JSON.
- Link: [CHANGELOG.md](../../CHANGELOG.md)
---
"""
        with patch("shutil.get_terminal_size") as m_size:
            m_size.return_value = os.terminal_size((100, 24))
            out = format_release_notes_for_cli(notes, max_lines=50)

        self.assertIn("RedAudit v3.1.1 - Release Notes", out)
        self.assertIn("Overview", out)
        self.assertIn("- Topology: New topology block in JSON.", out)
        self.assertIn("- Link: CHANGELOG.md", out)
        self.assertNotIn("shields.io", out)
        self.assertNotIn("[![", out)
        self.assertNotIn("#", out)
        self.assertNotIn("`", out)


class TestRestartSelf(unittest.TestCase):
    def test_restart_self_returns_false_when_all_methods_fail(self):
        with (
            patch.object(sys, "argv", ["redaudit", "--version"]),
            patch("redaudit.core.updater.os.execvp", side_effect=OSError("fail")) as m_execvp,
            patch("shutil.which", return_value=None),
            patch("redaudit.core.updater.os.execv", side_effect=OSError("fail")) as m_execv,
            patch("redaudit.core.updater.os.path.isfile", return_value=False),
        ):
            ok = restart_self(logger=None)

        self.assertFalse(ok)
        m_execvp.assert_called_once()
        self.assertEqual(m_execv.call_count, 0)

    def test_restart_self_uses_resolved_path_when_available(self):
        with (
            patch.object(sys, "argv", ["redaudit", "--version"]),
            patch("redaudit.core.updater.os.execvp", side_effect=OSError("fail")),
            patch("shutil.which", return_value="/usr/local/bin/redaudit"),
            patch("redaudit.core.updater.os.execv", side_effect=OSError("fail")) as m_execv,
            patch("redaudit.core.updater.os.path.isfile", return_value=False),
        ):
            ok = restart_self(logger=None)

        self.assertFalse(ok)
        m_execv.assert_called_with("/usr/local/bin/redaudit", ["/usr/local/bin/redaudit", "--version"])


if __name__ == "__main__":
    unittest.main()
