#!/usr/bin/env python3
"""
RedAudit - Updater Module Tests
Unit tests for updater helpers (no network, no root required).
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.updater import (
    compute_tree_diff,
    _inject_default_lang,
    format_release_notes_for_cli,
    render_update_summary_for_cli,
    restart_self,
)
from redaudit.utils.i18n import get_text


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


class TestUpdateSummaryRendering(unittest.TestCase):
    def test_render_update_summary_for_cli_is_concise_and_plain(self):
        notes = """## [3.2.1] - 2025-12-16 (Example)

### Added
- **Feature**: Something useful

### Fixed
- Bug fix in update prompt

### Breaking changes
- Changed defaults behavior
"""
        fake_stdout = Mock()
        fake_stdout.isatty.return_value = False
        with patch("redaudit.core.updater.sys.stdout", new=fake_stdout):
            out = render_update_summary_for_cli(
                current_version="3.2.0",
                latest_version="3.2.1",
                release_notes=notes,
                release_url="https://example.com/release",
                published_at=None,
                lang="en",
                notes_lang="en",
                t_fn=lambda key, *args: get_text(key, "en", *args),
                max_items=10,
                max_breaking=5,
            )

        self.assertIn("Release date: 2025-12-16", out)
        self.assertIn("Type: Patch", out)
        self.assertIn("Highlights:", out)
        self.assertIn("- Feature: Something useful", out)
        self.assertIn("- Bug fix in update prompt", out)
        self.assertIn("Breaking changes:", out)
        self.assertIn("- Changed defaults behavior", out)
        self.assertIn("Full release notes: https://example.com/release", out)

    def test_render_update_summary_adds_language_fallback_note(self):
        notes = """## [3.2.1] - 2025-12-16 (Example)

### Added
- Something
"""
        fake_stdout = Mock()
        fake_stdout.isatty.return_value = False
        with patch("redaudit.core.updater.sys.stdout", new=fake_stdout):
            out = render_update_summary_for_cli(
                current_version="3.2.0",
                latest_version="3.2.1",
                release_notes=notes,
                release_url=None,
                published_at=None,
                lang="es",
                notes_lang="en",
                t_fn=lambda key, *args: get_text(key, "es", *args),
                max_items=5,
                max_breaking=0,
            )

        self.assertIn("Notas solo disponibles en inglés.", out)


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


class TestPrintStatusMapping(unittest.TestCase):
    """Test that print_status maps internal tokens correctly for both TTY and non-TTY modes."""

    def test_status_mapping_non_tty(self):
        """Verify internal tokens are mapped to user-friendly labels in non-TTY mode."""
        from io import StringIO
        from redaudit.core.auditor import InteractiveNetworkAuditor
        
        auditor = InteractiveNetworkAuditor()
        
        # Mock non-TTY output
        captured = StringIO()
        with patch('sys.stdout', captured), \
             patch('sys.stdout.isatty', return_value=False):
            auditor.print_status("Test message", "OKGREEN")
        
        output = captured.getvalue()
        # Should contain [OK], not [OKGREEN]
        self.assertIn("[OK]", output)
        self.assertNotIn("[OKGREEN]", output)
        self.assertIn("Test message", output)

    def test_status_mapping_warning_to_warn(self):
        """Verify WARNING is mapped to WARN."""
        from io import StringIO
        from redaudit.core.auditor import InteractiveNetworkAuditor
        
        auditor = InteractiveNetworkAuditor()
        
        captured = StringIO()
        with patch('sys.stdout', captured), \
             patch('sys.stdout.isatty', return_value=False):
            auditor.print_status("Warning test", "WARNING")
        
        output = captured.getvalue()
        self.assertIn("[WARN]", output)
        self.assertNotIn("[WARNING]", output)

    def test_all_internal_tokens_mapped(self):
        """Verify all known internal tokens have mappings."""
        from redaudit.core.auditor import InteractiveNetworkAuditor
        from io import StringIO
        
        auditor = InteractiveNetworkAuditor()
        
        # These internal tokens should be mapped
        token_map = {
            "OKGREEN": "OK",
            "OKBLUE": "INFO",
            "HEADER": "INFO",
            "WARNING": "WARN",
            "FAIL": "FAIL",
            "INFO": "INFO",
        }
        
        for internal, expected in token_map.items():
            captured = StringIO()
            with patch('sys.stdout', captured), \
                 patch('sys.stdout.isatty', return_value=False):
                auditor.print_status(f"Testing {internal}", internal)
            
            output = captured.getvalue()
            self.assertIn(f"[{expected}]", output, 
                         f"Token {internal} should map to [{expected}]")
            if internal != expected:
                self.assertNotIn(f"[{internal}]", output,
                               f"Internal token [{internal}] should not appear in output")

    def test_status_mapping_tty_no_internal_tokens(self):
        """Verify internal tokens are NOT displayed in TTY mode (only colors differ)."""
        from io import StringIO
        from redaudit.core.auditor import InteractiveNetworkAuditor
        
        auditor = InteractiveNetworkAuditor()
        
        # Mock TTY output
        captured = StringIO()
        captured.isatty = lambda: True  # Simulate TTY
        with patch('sys.stdout', captured):
            auditor.print_status("Test TTY message", "OKGREEN")
        
        output = captured.getvalue()
        # Should contain [OK] (with color codes), NOT [OKGREEN]
        self.assertIn("[OK]", output)
        self.assertNotIn("[OKGREEN]", output)
        self.assertIn("Test TTY message", output)


if __name__ == "__main__":
    unittest.main()
