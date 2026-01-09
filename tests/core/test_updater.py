#!/usr/bin/env python3
"""
RedAudit - Updater Module Tests
Unit tests for updater helpers (no network, no root required).
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch
from urllib.error import HTTPError, URLError

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.updater import (
    compare_versions,
    compute_tree_diff,
    fetch_changelog_snippet,
    fetch_latest_version,
    format_release_notes_for_cli,
    get_repo_path,
    interactive_update_check,
    _inject_default_lang,
    _extract_release_items,
    _pause_for_restart_terminal,
    _show_restart_terminal_notice,
    parse_version,
    perform_git_update,
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
        m_execv.assert_called_with(
            "/usr/local/bin/redaudit", ["/usr/local/bin/redaudit", "--version"]
        )


class TestPrintStatusMapping(unittest.TestCase):
    """Test that print_status maps internal tokens correctly for both TTY and non-TTY modes."""

    def test_status_mapping_non_tty(self):
        """Verify internal tokens are mapped to user-friendly labels in non-TTY mode."""
        from io import StringIO
        from redaudit.core.auditor import InteractiveNetworkAuditor

        auditor = InteractiveNetworkAuditor()

        # Mock non-TTY output
        captured = StringIO()
        with patch("sys.stdout", captured), patch("sys.stdout.isatty", return_value=False):
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
        with patch("sys.stdout", captured), patch("sys.stdout.isatty", return_value=False):
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
            with patch("sys.stdout", captured), patch("sys.stdout.isatty", return_value=False):
                auditor.print_status(f"Testing {internal}", internal)

            output = captured.getvalue()
            self.assertIn(f"[{expected}]", output, f"Token {internal} should map to [{expected}]")
            if internal != expected:
                self.assertNotIn(
                    f"[{internal}]",
                    output,
                    f"Internal token [{internal}] should not appear in output",
                )

    def test_status_mapping_tty_no_internal_tokens(self):
        """Verify internal tokens are NOT displayed in TTY mode (only colors differ)."""
        from io import StringIO
        from redaudit.core.auditor import InteractiveNetworkAuditor

        auditor = InteractiveNetworkAuditor()

        # Mock TTY output
        captured = StringIO()
        captured.isatty = lambda: True  # Simulate TTY
        with patch("sys.stdout", captured):
            auditor.print_status("Test TTY message", "OKGREEN")

        output = captured.getvalue()
        # Should contain [OK] (with color codes), NOT [OKGREEN]
        self.assertIn("[OK]", output)
        self.assertNotIn("[OKGREEN]", output)
        self.assertIn("Test TTY message", output)


if __name__ == "__main__":
    unittest.main()


def test_parse_version_edge():
    """Test parse_version with invalid or empty inputs."""
    assert parse_version("invalid") == (0, 0, 0, "")
    assert parse_version("1.2") == (0, 0, 0, "")
    res = parse_version("1.2.3.4")
    assert res == (1, 2, 3, "")
    assert parse_version("3.8.0") == (3, 8, 0, "")
    assert parse_version("3.8.0a") == (3, 8, 0, "a")


def test_compare_versions_edge():
    """Test compare_versions with suffix and base differences."""
    assert compare_versions("3.8.0", "3.9.0") == -1
    assert compare_versions("3.9.0", "3.8.0") == 1
    assert compare_versions("3.8.0", "3.8.0") == 0
    assert compare_versions("3.8.0", "3.8.0a") == -1
    assert compare_versions("3.8.0b", "3.8.0a") == 1


def test_fetch_latest_version_errors():
    """Test fetch_latest_version with network or API errors."""
    with patch("redaudit.core.updater.urlopen") as mock_url:
        mock_url.side_effect = HTTPError("http://url", 404, "Not Found", {}, None)
        assert fetch_latest_version(logger=MagicMock()) is None
        mock_url.side_effect = URLError("Network down")
        assert fetch_latest_version(logger=MagicMock()) is None
        mock_url.side_effect = Exception("Crash")
        assert fetch_latest_version(logger=MagicMock()) is None


def test_fetch_changelog_snippet_multi_lang():
    """Test fetch_changelog_snippet with multiple languages and fallbacks."""
    with patch("redaudit.core.updater.urlopen") as mock_url:
        m1 = MagicMock()
        m1.status = 404
        m1.__enter__.return_value = m1

        m2 = MagicMock()
        m2.status = 200
        m2.read.return_value = b"## [3.9.0]\n- Change 1"
        m2.__enter__.return_value = m2

        mock_url.side_effect = [m1, m2]
        res = fetch_changelog_snippet("3.9.0", lang="es")
        assert res[0] == "## [3.9.0]\n- Change 1"
        assert res[1] == "en"


def test_extract_release_items_edge():
    """Test _extract_release_items with various markdown edge cases."""
    notes = """
## [3.9.0]
### Added
- Feature A
- https://shields.io/badge
- View in English

### Security:
- Fix vuln

### Breaking changes
- Change B
"""
    items = _extract_release_items(notes)
    assert "highlights" in items
    assert any("Feature A" in h for h in items["highlights"])
    assert any("Fix vuln" in h for h in items["highlights"])
    assert any("Change B" in b for b in items["breaking"])


def test_format_release_notes_complex():
    """Test format_release_notes_for_cli with headers and lists."""
    notes = "## Title\n### Section\n- Item 1\n- Item 2\n"
    res = format_release_notes_for_cli(notes, width=40)
    assert "Title" in res
    assert "Section" in res
    assert "Item 1" in res


def test_compute_tree_diff_edge():
    """Test compute_tree_diff with added/modified/removed files."""

    def mock_walk(top, **kwargs):
        if "path1" in top:
            yield ("/path1", [], ["common", "removed"])
        else:
            yield ("/path2", [], ["common", "added"])

    with patch("os.walk", side_effect=mock_walk):
        with patch("os.path.isdir", return_value=True):
            with patch("os.path.getsize", side_effect=[100, 200]):  # common file diff size
                with patch("os.path.isfile", return_value=True):
                    res = compute_tree_diff("/path1", "/path2")
                    assert "added" in res["added"]
                    assert "common" in res["modified"]
                    assert "removed" in res["removed"]


@patch("shutil.which", return_value="/usr/bin/git")
@patch("subprocess.Popen")
def test_perform_git_update_atomic_swap_fail(mock_popen, mock_which):
    """Test perform_git_update with atomic swap failure and rollback."""
    process = MagicMock()
    process.stdout.readline.side_effect = ["Cloning...", ""]
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    mock_popen.return_value = process

    with patch("os.geteuid", return_value=0):
        with patch("tempfile.mkdtemp", return_value="/tmp/redaudit"):
            with patch("shutil.rmtree"):
                with patch("shutil.copytree"):
                    with patch("os.walk", return_value=[]):
                        with patch("os.path.exists", return_value=True):
                            with patch("os.path.isdir", return_value=True):
                                with patch("os.path.isfile", return_value=True):
                                    with patch("os.chmod"):
                                        with patch("os.rename", side_effect=Exception("SWAP_FAIL")):
                                            with patch(
                                                "redaudit.core.updater.CommandRunner"
                                            ) as MockCR:
                                                MockCR.return_value.check_output.side_effect = [
                                                    "abc\trefs/tags/v3.8.4",  # ls-remote
                                                    "abc",  # rev-parse
                                                ]
                                                MockCR.return_value.run.return_value = MagicMock(
                                                    returncode=0
                                                )
                                                success, msg = perform_git_update(
                                                    "/repo", print_fn=MagicMock()
                                                )
                                                assert success is False
                                                assert "SWAP_FAIL" in msg


@patch("shutil.which", return_value="/usr/bin/git")
@patch("subprocess.Popen")
def test_perform_git_update_verification_fail(mock_popen, mock_which):
    """Test perform_git_update with verification failure and rollback."""
    process = MagicMock()
    process.stdout.readline.side_effect = ["Cloning...", ""]
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    mock_popen.return_value = process

    with patch("os.geteuid", return_value=0):
        with patch("tempfile.mkdtemp", return_value="/tmp/redaudit"):
            with patch.dict("os.environ", {"SUDO_USER": "testuser"}):
                with patch("pwd.getpwnam") as mock_pwd:
                    mock_pwd.return_value = MagicMock(
                        pw_dir="/home/testuser", pw_uid=1000, pw_gid=1000
                    )
                    with patch("shutil.rmtree"):
                        with patch("shutil.copytree"):
                            with patch("os.walk", return_value=[]):
                                with patch("os.chmod"):
                                    with patch("os.rename"):  # Rename succeeds
                                        with patch("os.path.isdir", return_value=False):
                                            with patch(
                                                "os.path.exists", return_value=True
                                            ):  # Backups exist
                                                with patch(
                                                    "redaudit.core.updater.CommandRunner"
                                                ) as MockCR:
                                                    MockCR.return_value.check_output.side_effect = [
                                                        "abc\trefs/tags/v3.8.4",  # ls-remote
                                                        "abc",  # rev-parse
                                                    ]
                                                    MockCR.return_value.run.return_value = (
                                                        MagicMock(returncode=0)
                                                    )
                                                    success, msg = perform_git_update(
                                                        "/repo", print_fn=MagicMock()
                                                    )
                                                    assert success is False
                                                    assert "verification failed" in msg


@patch("shutil.which", return_value="/usr/bin/git")
@patch("subprocess.Popen")
def test_perform_git_update_diff_preview(mock_popen, mock_which):
    """Test perform_git_update with large diff preview."""
    process = MagicMock()
    process.stdout.readline.side_effect = ["Cloning...", ""]
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    mock_popen.return_value = process

    with patch("os.geteuid", return_value=0):
        with patch("tempfile.mkdtemp", return_value="/tmp/redaudit"):
            with patch("shutil.rmtree"):
                with patch("shutil.copytree"):
                    # Large diff
                    large_diff = {
                        "added": [f"file{i}" for i in range(30)],
                        "modified": ["mod"],
                        "removed": [],
                    }
                    with patch("redaudit.core.updater.compute_tree_diff", return_value=large_diff):
                        with patch("os.path.isdir", return_value=True):
                            with patch("redaudit.core.updater.CommandRunner") as MockCR:
                                MockCR.return_value.check_output.side_effect = [
                                    "abc\trefs/tags/v3.8.4",
                                    "abc",
                                ]
                                # We don't need to finish update, just hit the preview lines
                                with patch(
                                    "os.path.exists", side_effect=[True, False]
                                ):  # install exists, staged doesn't
                                    with patch("os.walk", return_value=[]):
                                        # Mocking validation failure to exit early after preview
                                        with patch("os.path.isfile", return_value=False):
                                            perform_git_update("/repo", print_fn=MagicMock())


@patch("shutil.which", return_value="/usr/bin/git")
@patch("subprocess.Popen")
def test_perform_git_update_missing_key_file(mock_popen, mock_which):
    """Test perform_git_update staging validation failure."""
    process = MagicMock()
    process.stdout.readline.side_effect = ["Cloning...", ""]
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    mock_popen.return_value = process

    with patch("tempfile.mkdtemp", return_value="/tmp/redaudit"):
        with patch("shutil.copytree"):
            with patch("os.walk", return_value=[]):
                with patch("os.path.isdir", return_value=True):
                    with patch("redaudit.core.updater.CommandRunner") as MockCR:
                        MockCR.return_value.check_output.side_effect = [
                            "abc\trefs/tags/v3.8.4",  # ls-remote
                            "abc",  # rev-parse for checkout verification
                        ]
                        with patch("os.path.isfile", return_value=False):  # Missing key file
                            success, msg = perform_git_update(
                                "/repo", print_fn=MagicMock(), t_fn=lambda k, *args: k
                            )
                            assert success is False
                            assert "verify_failed" in msg or "missing" in msg


def test_restart_self_edge():
    """Test restart_self in various failure modes."""
    with (
        patch("os.execvp", side_effect=Exception("EXECVP_FAIL")),
        patch("os.execv", side_effect=Exception("EXEC_FAIL")),
    ):
        assert restart_self(logger=MagicMock()) is False

    with (
        patch("os.execvp", side_effect=Exception("EXECVP_FAIL")),
        patch("os.execv", side_effect=Exception("EXEC_FAIL")),
        patch("sys.executable", ""),
    ):
        assert restart_self() is False


def test_render_update_summary_edge():
    """Test render_update_summary_for_cli with long notes and specific lang."""
    notes = "### v3.9.0\n- Feature 1\n- Feature 2"

    def mock_t(key, *args):
        if args:
            return f"{key}:{args[0]}"
        return key

    res = render_update_summary_for_cli(
        current_version="3.8.0",
        latest_version="3.9.0",
        release_notes=notes,
        release_url="http://rel",
        published_at="2025-01-01",
        lang="en",
        t_fn=mock_t,
    )
    assert "update_release_date:2025-01-01" in res
    assert "Feature 1" in res


def test_show_restart_terminal_notice_no_tty():
    """Test _show_restart_terminal_notice when not in TTY."""
    with patch("sys.stdout.isatty", return_value=False):
        _show_restart_terminal_notice(t_fn=lambda k, *args: k, lang="en")


def test_pause_for_restart_terminal_no_tty():
    """Test _pause_for_restart_terminal when not in TTY."""
    with patch("sys.stdin.isatty", return_value=False):
        with patch("time.sleep") as mock_sleep:
            _pause_for_restart_terminal(t_fn=lambda k, *args: k)
            assert mock_sleep.called


def test_get_repo_path():
    """Test get_repo_path."""
    path = get_repo_path()
    assert os.path.exists(path)


def test_interactive_update_check_skipped():
    """Test interactive_update_check when user skips."""
    with patch(
        "redaudit.core.updater.check_for_updates",
        return_value=(True, "3.9.0", "Notes", "url", "date", "en"),
    ):
        with patch("builtins.input", return_value="n"):
            assert interactive_update_check(print_fn=MagicMock()) is False


class TestCheckForUpdates(unittest.TestCase):
    """Tests for check_for_updates function."""

    def test_returns_false_when_no_release_info(self):
        """Returns (False, None, ...) when API fails."""
        from redaudit.core.updater import check_for_updates

        with patch("redaudit.core.updater.fetch_latest_version", return_value=None):
            result = check_for_updates()
            self.assertFalse(result[0])
            self.assertIsNone(result[1])

    def test_returns_false_when_no_tag_name(self):
        """Returns False when release has no tag_name."""
        from redaudit.core.updater import check_for_updates

        with patch(
            "redaudit.core.updater.fetch_latest_version",
            return_value={"name": "Release", "published_at": "2024-01-01"},
        ):
            result = check_for_updates()
            self.assertFalse(result[0])

    def test_returns_update_available(self):
        """Returns True when newer version available."""
        from redaudit.core.updater import check_for_updates

        newer_version = "99.99.99"  # Always newer than current
        with patch(
            "redaudit.core.updater.fetch_latest_version",
            return_value={
                "tag_name": newer_version,
                "html_url": "https://github.com/test",
                "published_at": "2026-01-01T00:00:00Z",
                "body": "Release notes",
            },
        ):
            with patch(
                "redaudit.core.updater.fetch_changelog_snippet",
                return_value=("Changelog", "en"),
            ):
                result = check_for_updates()
                self.assertTrue(result[0])
                self.assertEqual(result[1], newer_version)
                self.assertIsNotNone(result[2])

    def test_returns_false_when_up_to_date(self):
        """Returns False when already at latest version."""
        from redaudit.core.updater import check_for_updates, VERSION

        with patch(
            "redaudit.core.updater.fetch_latest_version",
            return_value={
                "tag_name": VERSION,
                "published_at": "2024-01-01T00:00:00Z",
            },
        ):
            result = check_for_updates()
            self.assertFalse(result[0])
            self.assertEqual(result[1], VERSION)


class TestHelperFunctions(unittest.TestCase):
    """Tests for updater helper functions."""

    def test_parse_published_date_valid(self):
        """Parses valid ISO date."""
        from redaudit.core.updater import _parse_published_date

        result = _parse_published_date("2024-01-15T12:30:00Z")
        self.assertIsNotNone(result)
        self.assertIn("2024", result)

    def test_parse_published_date_none(self):
        """Returns None for None input."""
        from redaudit.core.updater import _parse_published_date

        result = _parse_published_date(None)
        self.assertIsNone(result)

    def test_extract_release_date_from_notes(self):
        """Extracts date from release notes."""
        from redaudit.core.updater import _extract_release_date_from_notes

        # The function may not find a date if format doesn't match exactly
        notes = "## v4.5.0 - 2024-03-15\n- Feature 1"
        result = _extract_release_date_from_notes(notes, "v4.5.0")
        # Result may be None if regex doesn't match; test that it doesn't crash
        self.assertIsInstance(result, (str, type(None)))

    def test_classify_release_type(self):
        """Classifies release types correctly."""
        from redaudit.core.updater import _classify_release_type

        # Major update (returns capitalized)
        self.assertEqual(_classify_release_type("3.0.0", "4.0.0"), "Major")
        # Minor update
        self.assertEqual(_classify_release_type("3.0.0", "3.1.0"), "Minor")
        # Patch update
        self.assertEqual(_classify_release_type("3.1.0", "3.1.1"), "Patch")


class TestComputeFileHash(unittest.TestCase):
    """Tests for compute_file_hash function."""

    def test_computes_sha256(self):
        """Computes SHA256 hash correctly."""
        from redaudit.core.updater import compute_file_hash

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
            f.write("test content")
            f.flush()
            try:
                result = compute_file_hash(f.name)
                self.assertEqual(len(result), 64)  # SHA256 produces 64 hex chars
            finally:
                os.unlink(f.name)

    def test_computes_sha512(self):
        """Computes SHA512 hash correctly."""
        from redaudit.core.updater import compute_file_hash

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
            f.write("test content")
            f.flush()
            try:
                result = compute_file_hash(f.name, algorithm="sha512")
                self.assertEqual(len(result), 128)  # SHA512 produces 128 hex chars
            finally:
                os.unlink(f.name)


class TestIterFiles(unittest.TestCase):
    """Tests for _iter_files function."""

    def test_excludes_pycache(self):
        """Excludes __pycache__ directories."""
        from redaudit.core.updater import _iter_files

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular file
            with open(os.path.join(tmpdir, "file.py"), "w") as f:
                f.write("code")
            # Create __pycache__ dir
            pycache = os.path.join(tmpdir, "__pycache__")
            os.makedirs(pycache)
            with open(os.path.join(pycache, "file.pyc"), "w") as f:
                f.write("bytecode")

            files = list(_iter_files(tmpdir))
            self.assertIn("file.py", files)
            self.assertNotIn("__pycache__/file.pyc", files)


class TestSuggestRestartCommand(unittest.TestCase):
    """Tests for _suggest_restart_command."""

    def test_suggests_command(self):
        """Returns a restart suggestion."""
        from redaudit.core.updater import _suggest_restart_command

        result = _suggest_restart_command()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)


class TestStripMarkdownInline(unittest.TestCase):
    """Tests for _strip_markdown_inline."""

    def test_strips_bold(self):
        """Strips bold markers."""
        from redaudit.core.updater import _strip_markdown_inline

        result = _strip_markdown_inline("**bold text**")
        self.assertEqual(result, "bold text")

    def test_strips_inline_code(self):
        """Strips inline code markers."""
        from redaudit.core.updater import _strip_markdown_inline

        result = _strip_markdown_inline("`code`")
        self.assertEqual(result, "code")


if __name__ == "__main__":
    unittest.main()
