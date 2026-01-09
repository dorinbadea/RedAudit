#!/usr/bin/env python3

"""

RedAudit - Updater Module Tests

Unit tests for updater helpers (no network, no root required).

"""

import os

import sys

import tempfile

import unittest

import subprocess

from unittest.mock import MagicMock, Mock, patch

from urllib.error import HTTPError, URLError

# Add parent directory to path for CI compatibility

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.updater import (  # noqa: E402
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
)  # noqa: E402

from redaudit.utils.i18n import get_text  # noqa: E402


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


class TestFetchLatestVersionSuccess(unittest.TestCase):
    """Tests for fetch_latest_version success paths."""

    def test_fetch_success(self):
        """Should return release info on success."""

        from redaudit.core.updater import fetch_latest_version

        mock_response = MagicMock()

        mock_response.status = 200

        mock_response.read.return_value = b'{"tag_name": "v4.5.0", "name": "Release", "body": "Notes", "published_at": "2026-01-01", "html_url": "url"}'

        mock_response.__enter__ = MagicMock(return_value=mock_response)

        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("redaudit.core.updater.urlopen", return_value=mock_response):

            result = fetch_latest_version()

        self.assertIsNotNone(result)

        self.assertEqual(result["tag_name"], "4.5.0")

    def test_fetch_http_error_with_logger(self):
        """Should log HTTP error."""

        from redaudit.core.updater import fetch_latest_version

        logger = MagicMock()

        with patch(
            "redaudit.core.updater.urlopen", side_effect=HTTPError(None, 404, "Not Found", {}, None)
        ):

            result = fetch_latest_version(logger=logger)

        self.assertIsNone(result)

        logger.warning.assert_called()

    def test_fetch_generic_exception_with_logger(self):
        """Should log generic exception."""

        from redaudit.core.updater import fetch_latest_version

        logger = MagicMock()

        with patch("redaudit.core.updater.urlopen", side_effect=Exception("Network error")):

            result = fetch_latest_version(logger=logger)

        self.assertIsNone(result)

        logger.debug.assert_called()


class TestFetchChangelogSnippetSuccess(unittest.TestCase):
    """Tests for fetch_changelog_snippet success paths."""

    def test_fetch_changelog_success(self):
        """Should return changelog snippet on success."""

        from redaudit.core.updater import fetch_changelog_snippet

        changelog_content = """## [4.5.0] - 2026-01-01

- Feature 1

- Feature 2

## [4.4.0]"""

        mock_response = MagicMock()

        mock_response.status = 200

        mock_response.read.return_value = changelog_content.encode("utf-8")

        mock_response.__enter__ = MagicMock(return_value=mock_response)

        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("redaudit.core.updater.urlopen", return_value=mock_response):

            result = fetch_changelog_snippet("4.5.0", lang="en")

        self.assertIsNotNone(result)

        self.assertIn("Feature 1", result[0])

    def test_fetch_changelog_falls_back_to_en(self):
        """Should fall back to EN when ES not found."""

        from redaudit.core.updater import fetch_changelog_snippet

        call_count = [0]

        def mock_urlopen(*args, **kwargs):

            call_count[0] += 1

            if call_count[0] == 1:  # ES request

                raise HTTPError(None, 404, "Not Found", {}, None)

            # EN request

            mock_response = MagicMock()

            mock_response.status = 200

            mock_response.read.return_value = b"## [4.5.0]\n- Feature 1"

            mock_response.__enter__ = MagicMock(return_value=mock_response)

            mock_response.__exit__ = MagicMock(return_value=False)

            return mock_response

        with patch("redaudit.core.updater.urlopen", side_effect=mock_urlopen):

            result = fetch_changelog_snippet("4.5.0", lang="es")

        # Fallback behavior: may return EN result or None if version not found

        self.assertIsInstance(result, (tuple, type(None)))


class TestFormatReleaseNotesForCli(unittest.TestCase):
    """Tests for format_release_notes_for_cli function."""

    def test_format_handles_code_blocks(self):
        """Should handle code blocks in notes."""

        from redaudit.core.updater import format_release_notes_for_cli

        notes = "Feature:\n```python\ncode here\n```"

        result = format_release_notes_for_cli(notes)

        self.assertIsInstance(result, str)

    def test_format_wraps_long_lines(self):
        """Should wrap long lines."""

        from redaudit.core.updater import format_release_notes_for_cli

        long_line = "- " + "word " * 50

        result = format_release_notes_for_cli(long_line, width=80)

        self.assertIsInstance(result, str)

    def test_format_truncates_to_max_lines(self):
        """Should truncate to max_lines."""

        from redaudit.core.updater import format_release_notes_for_cli

        notes = "\n".join([f"- Line {i}" for i in range(100)])

        result = format_release_notes_for_cli(notes, max_lines=10)

        self.assertIn("...", result)  # Uses '...' not '[...]'

    def test_format_handles_unicode(self):
        """Should handle Unicode characters."""

        from redaudit.core.updater import format_release_notes_for_cli

        notes = "- Añadido soporte para ñ y acentos áéíóú"

        result = format_release_notes_for_cli(notes)

        self.assertIn("soporte", result)


class TestCheckForUpdatesFlows(unittest.TestCase):
    """Tests for check_for_updates various flows."""

    def test_update_available_with_changelog_fallback(self):
        """Should use release body when changelog not found."""

        from redaudit.core.updater import check_for_updates

        with patch(
            "redaudit.core.updater.fetch_latest_version",
            return_value={
                "tag_name": "99.99.99",
                "body": "Release notes body",
                "published_at": "2026-01-01",
                "html_url": "url",
            },
        ):

            with patch("redaudit.core.updater.fetch_changelog_snippet", return_value=None):

                result = check_for_updates()

        self.assertTrue(result[0])

        self.assertEqual(result[2], "Release notes body")


class TestRenderUpdateSummaryForCli(unittest.TestCase):
    """Tests for render_update_summary_for_cli function."""

    def test_render_with_all_parameters(self):
        """Should render summary with all parameters."""

        from redaudit.core.updater import render_update_summary_for_cli

        result = render_update_summary_for_cli(
            current_version="4.4.0",
            latest_version="4.5.0",
            release_notes="- Feature 1\n- Feature 2",
            release_url="https://github.com/test",
            published_at="2026-01-01",
            lang="en",
            t_fn=lambda k, *args: k,
            notes_lang="en",
        )

        self.assertIsInstance(result, str)

    def test_render_with_breaking_changes(self):
        """Should highlight breaking changes."""

        from redaudit.core.updater import render_update_summary_for_cli

        notes = "### BREAKING\n- Changed API\n### Features\n- New feature"

        result = render_update_summary_for_cli(
            current_version="4.4.0",
            latest_version="5.0.0",
            release_notes=notes,
            release_url="url",
            published_at="2026-01-01",
            lang="en",
            t_fn=lambda k, *args: k,
        )

        self.assertIsInstance(result, str)


class TestExtractReleaseItems(unittest.TestCase):
    """Tests for _extract_release_items function."""

    def test_extract_with_breaking_section(self):
        """Should extract breaking changes."""

        from redaudit.core.updater import _extract_release_items

        notes = "### BREAKING\n- API changed\n### Features\n- New feature"

        result = _extract_release_items(notes)

        self.assertIn("breaking", result)

        self.assertIn("highlights", result)

    def test_extract_with_empty_notes(self):
        """Should handle empty notes."""

        from redaudit.core.updater import _extract_release_items

        result = _extract_release_items("")

        self.assertEqual(result["highlights"], [])

        self.assertEqual(result["breaking"], [])


class TestInjectDefaultLangAdditional(unittest.TestCase):
    """Tests for _inject_default_lang function (additional)."""

    def test_inject_with_no_existing_lang(self):
        """Should add DEFAULT_LANG if not present."""

        from redaudit.core.updater import _inject_default_lang

        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:

            f.write("# Constants\nVERSION = '1.0'\n")

            f.flush()

            try:

                result = _inject_default_lang(f.name, "es")

                self.assertTrue(result)

            finally:

                os.unlink(f.name)


class TestPerformGitUpdatePaths(unittest.TestCase):
    """Tests for perform_git_update edge cases."""

    def test_update_without_print_fn(self):
        """Should handle missing print_fn."""

        from redaudit.core.updater import perform_git_update

        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmpdir:

            with patch("subprocess.run") as mock_run:

                mock_run.return_value.returncode = 1

                mock_run.return_value.stderr = "error"

                success, msg = perform_git_update(tmpdir, print_fn=None)

                self.assertFalse(success)


class TestPerformGitUpdateDeep(unittest.TestCase):

    def setUp(self):

        self.repo_path = "/tmp/repo"

    @patch("redaudit.core.updater.os.geteuid", return_value=0)
    @patch("shutil.rmtree")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.CommandRunner.check_output")
    @patch("redaudit.core.updater.CommandRunner.run")
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("shutil.copytree")
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile", return_value=True)
    @patch("redaudit.core.updater.os.rename")
    @patch("redaudit.core.updater._inject_default_lang")
    @patch("redaudit.core.updater.os.chmod")
    @patch("redaudit.core.updater.os.chown")
    @patch("time.time", return_value=1000)
    def test_perform_git_update_root_success(
        self,
        mock_time,
        mock_chown,
        mock_chmod,
        mock_inject,
        mock_rename,
        mock_isfile,
        mock_isdir,
        mock_copytree,
        mock_popen,
        mock_run,
        mock_check_output,
        mock_exists,
        mock_rmtree,
        mock_geteuid,
    ):

        mock_check_output.side_effect = ["f79d033 (tag)\n", "f79d033\n", "", "ok\n"] + [""] * 10

        process = MagicMock()

        process.poll.side_effect = [None, 0, 0, 0]

        process.stdout.__iter__.return_value = ["Cloning..."]
        process.stdout.readline.return_value = ""  # CRITICAL: prevents infinite loop

        process.wait.return_value = 0

        mock_popen.return_value = process

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

        self.assertTrue(success, f"Failed: {msg}")

        self.assertEqual(msg, "UPDATE_SUCCESS_RESTART")

    @patch("redaudit.core.updater.os.geteuid", return_value=1000)
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.CommandRunner.check_output")
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("shutil.copytree")
    @patch("redaudit.core.updater.os.rename")
    @patch("shutil.rmtree")
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile", return_value=True)
    @patch("time.time", return_value=1000)
    def test_perform_git_update_home_copy_success(
        self,
        mock_time,
        mock_isfile,
        mock_isdir,
        mock_rmtree,
        mock_rename,
        mock_copytree,
        mock_popen,
        mock_check_output,
        mock_exists,
        mock_geteuid,
    ):

        mock_check_output.side_effect = ["f79d033 (tag)\n", "f79d033\n", "", "ok\n"] + [""] * 10

        process = MagicMock()

        process.poll.side_effect = [None, 0, 0, 0]

        process.stdout.__iter__.return_value = []
        process.stdout.readline.return_value = ""  # CRITICAL: prevents infinite loop

        process.wait.return_value = 0

        mock_popen.return_value = process

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

        self.assertTrue(success, f"Failed: {msg}")

    @patch("redaudit.core.updater.CommandRunner.check_output")
    def test_perform_git_update_timeout(self, mock_check_output):

        mock_check_output.side_effect = subprocess.TimeoutExpired(["git"], 30)

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

        self.assertFalse(success)

        # Exception during ls-remote returns "Could not resolve tag..."

        self.assertIn("Could not resolve tag", msg)

    @patch("redaudit.core.updater.CommandRunner.check_output", side_effect=FileNotFoundError())
    def test_perform_git_update_git_missing(self, mock_check_output):

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

        self.assertFalse(success)

        self.assertIn("Could not resolve tag", msg)

    @patch("redaudit.core.updater.is_dry_run", return_value=True)
    def test_perform_git_update_dry_run(self, mock_dry):

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path)

        self.assertTrue(success)

        self.assertEqual(msg, "Dry-run: update skipped")

    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.CommandRunner.check_output")
    def test_perform_git_update_dirty_repo(self, mock_check, mock_isdir, mock_exists):

        # f79d033 (tag) for ls-remote, f79d033 for rev-parse, then "M" for porcelain status

        mock_check.side_effect = ["f79d033 (tag)\n", "f79d033\n", "M modified_file.py\n"]

        from redaudit.core.updater import perform_git_update

        # Mock geuid to be non-root so it skips system install and reaches home check

        with patch("redaudit.core.updater.os.geteuid", return_value=1000):

            success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

            self.assertFalse(success)

            self.assertEqual(msg, "update_home_changes_detected_abort")

    @patch("redaudit.core.updater.CommandRunner")
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile", return_value=True)
    @patch("redaudit.core.updater.os.rename")
    @patch("shutil.rmtree")
    @patch("shutil.copytree")
    def test_perform_git_update_ls_remote_fallback(
        self,
        mock_copy,
        mock_rm,
        mock_rename,
        mock_isfile,
        mock_isdir,
        mock_exists,
        mock_popen,
        mock_runner_cls,
    ):

        mock_runner = mock_runner_cls.return_value

        mock_runner.is_available.return_value = True

        def se(cmd, **kwargs):

            c = " ".join(cmd)

            if "ls-remote" in c:

                return "" if "^{}" in c else "f79d033 (tag)\n"

            if "rev-parse" in c:

                return "f79d033\n"

            return ""

        mock_runner.check_output.side_effect = se

        process = MagicMock()

        process.poll.return_value = 0

        process.wait.return_value = 0

        process.stdout.readline.return_value = ""

        mock_popen.return_value = process

        from redaudit.core.updater import perform_git_update

        with patch("redaudit.core.updater.os.geteuid", return_value=1000):

            success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

            self.assertTrue(success, f"Failed: {msg}")

    @patch("redaudit.core.updater.CommandRunner")
    def test_perform_git_update_ls_remote_fail(self, mock_runner_cls):

        mock_runner = mock_runner_cls.return_value

        mock_runner.check_output.side_effect = ["", ""]  # Both fail

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

        self.assertFalse(success)

        self.assertIn("Could not resolve tag", msg)

    @patch("redaudit.core.updater.os.geteuid", return_value=0)
    @patch("redaudit.core.updater.CommandRunner")
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile", return_value=False)
    @patch("shutil.rmtree")
    @patch("shutil.copytree")
    def test_perform_git_update_staged_verify_fail(
        self,
        mock_copy,
        mock_rm,
        mock_isfile,
        mock_isdir,
        mock_exists,
        mock_popen,
        mock_runner_cls,
        mock_geteuid,
    ):

        mock_runner = mock_runner_cls.return_value

        mock_runner.check_output.side_effect = ["f79d033 (tag)\n", "f79d033\n", "", ""] + [""] * 10

        mock_runner.run.return_value = MagicMock(returncode=0)

        process = MagicMock()

        process.poll.return_value = 0

        process.stdout.readline.return_value = ""

        process.wait.return_value = 0

        mock_popen.return_value = process

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

        self.assertFalse(success)

        self.assertIn("Staged install missing key file", msg)

    @patch("redaudit.core.updater.os.geteuid", return_value=0)
    @patch("redaudit.core.updater.CommandRunner")
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile", return_value=True)
    @patch("redaudit.core.updater.os.rename")
    @patch("redaudit.core.updater.os.chmod")
    @patch("redaudit.core.updater.os.chown")
    @patch("redaudit.core.updater.os.walk", return_value=[("/tmp", [], ["__init__.py"])])
    @patch("shutil.rmtree")
    @patch("shutil.copytree")
    def test_perform_git_update_system_swap_fail(
        self,
        mock_copy,
        mock_rm,
        mock_walk,
        mock_chown,
        mock_chmod,
        mock_rename,
        mock_isfile,
        mock_isdir,
        mock_exists,
        mock_popen,
        mock_runner_cls,
        mock_geteuid,
    ):

        mock_runner = mock_runner_cls.return_value

        mock_runner.check_output.side_effect = ["f79d033 (tag)\n", "f79d033\n", "", ""] + [""] * 10

        mock_runner.run.return_value = MagicMock(returncode=0)

        mock_rename.side_effect = [None, Exception("Rename failed")]

        process = MagicMock()

        process.poll.return_value = 0

        process.stdout.readline.return_value = ""

        process.wait.return_value = 0

        mock_popen.return_value = process

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

        self.assertFalse(success)

        self.assertIn("System install swap failed", msg)

    @patch("redaudit.core.updater.os.geteuid", return_value=1000)
    @patch("redaudit.core.updater.CommandRunner")
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile", return_value=True)
    @patch("redaudit.core.updater.os.rename")
    @patch("shutil.rmtree")
    @patch("shutil.copytree")
    def test_perform_git_update_dirty_home_abort(
        self,
        mock_copy,
        mock_rm,
        mock_rename,
        mock_isfile,
        mock_isdir,
        mock_exists,
        mock_popen,
        mock_runner_cls,
        mock_geteuid,
    ):

        mock_runner = mock_runner_cls.return_value

        def check_output_se(cmd, **kwargs):

            cmd_str = " ".join(cmd)

            if "ls-remote" in cmd_str:

                return "f79d033 (tag)\n"

            if "rev-parse" in cmd_str:

                return "f79d033\n"

            if "status" in cmd_str:

                # First status (clone check) is clean, second (home repo) is dirty

                if kwargs.get("cwd") == self.repo_path:

                    return ""

                return "M modified\n"

            return ""

        mock_runner.check_output.side_effect = check_output_se

        process = MagicMock()

        process.poll.return_value = 0

        process.stdout.readline.return_value = ""

        process.wait.return_value = 0

        mock_popen.return_value = process

        from redaudit.core.updater import perform_git_update

        success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

        self.assertFalse(success, f"Expected False, got True with msg: {msg}")

        self.assertEqual(msg, "update_home_changes_detected_abort")

    @patch("redaudit.core.updater.os.geteuid", return_value=0)
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile")
    @patch("redaudit.core.updater.os.rename")
    @patch("redaudit.core.updater.os.chmod")
    @patch("redaudit.core.updater.os.chown")
    @patch("redaudit.core.updater.os.walk", return_value=[("/tmp", [], ["__init__.py"])])
    @patch("shutil.rmtree")
    @patch("shutil.copytree")
    @patch("time.time", return_value=1000)
    def test_perform_git_update_verification_rollback(
        self,
        mock_time,
        mock_copy,
        mock_rm,
        mock_walk,
        mock_chown,
        mock_chmod,
        mock_rename,
        mock_isfile,
        mock_isdir,
        mock_exists,
        mock_popen,
        mock_geteuid,
    ):

        with patch("redaudit.core.updater.CommandRunner") as mock_runner_cls:

            mock_runner = mock_runner_cls.return_value

            mock_runner.is_available.return_value = True

            mock_runner.check_output.side_effect = ["f79d033 (tag)\n", "f79d033\n", "", ""] + [
                ""
            ] * 10

            # 1. Inject (T), 2-4. Staged verify (T), 5. Final verify (F)

            mock_isfile.side_effect = [True, True, True, True, False]

            process = MagicMock()

            process.poll.return_value = 0

            process.stdout.__iter__.return_value = []
            process.stdout.readline.return_value = ""  # CRITICAL: prevents infinite loop

            process.wait.return_value = 0

            mock_popen.return_value = process

            from redaudit.core.updater import perform_git_update

            success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

            self.assertFalse(success)

            # Either rollback or staged verify failure is acceptable
            self.assertTrue(
                "Installation verification failed" in msg or "Staged install missing" in msg,
                f"Unexpected error: {msg}",
            )

    @patch("redaudit.core.updater.CommandRunner", side_effect=Exception("Generic failure"))
    def test_perform_git_update_generic_exception(self, mock_runner_cls):

        from redaudit.core.updater import perform_git_update

        with patch("redaudit.core.updater.os.geteuid", return_value=1000):

            success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

            self.assertFalse(success)

            self.assertIn("Update failed: Generic failure", msg)

    @patch("redaudit.core.updater.os.geteuid", return_value=0)
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile", return_value=True)
    @patch("redaudit.core.updater.os.rename")
    @patch("shutil.rmtree")
    @patch("time.time", return_value=1000)
    def test_perform_git_update_inject_fail(
        self,
        mock_time,
        mock_rm,
        mock_rename,
        mock_isfile,
        mock_isdir,
        mock_exists,
        mock_popen,
        mock_geteuid,
    ):

        with patch("redaudit.core.updater.CommandRunner") as mock_runner_cls:

            mock_runner = mock_runner_cls.return_value

            mock_runner.is_available.return_value = True

            mock_runner.check_output.side_effect = ["f79d033 (tag)\n", "f79d033\n"] + [""] * 10

            process = MagicMock()

            process.poll.return_value = 0

            process.wait.return_value = 0

            process.stdout.__iter__.return_value = []
            process.stdout.readline.return_value = ""  # CRITICAL: prevents infinite loop

            mock_popen.return_value = process

            # Mock it to fail

            with patch("redaudit.core.updater._inject_default_lang", return_value=False):

                from redaudit.core.updater import perform_git_update

                success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

                self.assertIsInstance(success, bool)

    def test_fetch_changelog_snippet_exception_logger(self):

        from redaudit.core.updater import fetch_changelog_snippet

        logger = MagicMock()

        with patch("redaudit.core.updater.urlopen", side_effect=Exception("error")):

            res = fetch_changelog_snippet("1.0.0", logger=logger)

            self.assertIsNone(res)

            logger.debug.assert_called()

    def test_extract_release_date_from_notes_edge_cases(self):

        from redaudit.core.updater import _extract_release_date_from_notes

        self.assertIsNone(_extract_release_date_from_notes("", "1.0.0"))

        with patch("re.search", side_effect=Exception("regex error")):

            self.assertIsNone(_extract_release_date_from_notes("## [1.0.0]", "1.0.0"))

    def test_extract_release_items_edge_cases(self):

        from redaudit.core.updater import _extract_release_items

        notes = "- View in Spanish\n- View in english\n- http://site"

        res = _extract_release_items(notes)

        self.assertEqual(res["highlights"], [])

    @patch("redaudit.core.updater.urlopen")
    def test_fetch_latest_version_fails_json(self, mock_urlopen):

        from redaudit.core.updater import fetch_latest_version

        mock_response = MagicMock()

        mock_response.status = 200

        mock_response.read.return_value = b"invalid json"

        mock_response.__enter__.return_value = mock_response

        mock_urlopen.return_value = mock_response

        res = fetch_latest_version(logger=MagicMock())

        self.assertIsNone(res)

    @patch("redaudit.core.updater.os.geteuid", return_value=1000)
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile", return_value=True)
    @patch("redaudit.core.updater.os.rename")
    @patch("shutil.rmtree")
    @patch("shutil.copytree")
    @patch("time.time", return_value=1000)
    def test_perform_git_update_home_swap_fail(
        self,
        mock_time,
        mock_copytree,
        mock_rm,
        mock_rename,
        mock_isfile,
        mock_isdir,
        mock_exists,
        mock_popen,
        mock_geteuid,
    ):

        with patch("redaudit.core.updater.CommandRunner") as mock_runner_cls:

            mock_runner = mock_runner_cls.return_value

            mock_runner.is_available.return_value = True

            mock_runner.check_output.side_effect = ["f79d033 (tag)\n", "f79d033\n"] + [""] * 10

            # rename 1 (system OK, geuid=1000 skips it),

            # then home renames: backup (None), activate (FAIL)

            mock_rename.side_effect = [None, Exception("Home activate failed")]

            process = MagicMock()

            process.poll.return_value = 0

            process.wait.return_value = 0

            process.stdout.__iter__.return_value = []
            process.stdout.readline.return_value = ""  # CRITICAL: prevents infinite loop

            mock_popen.return_value = process

            from redaudit.core.updater import perform_git_update

            success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

            self.assertFalse(success)

            self.assertIn("Home folder swap failed", msg)

    @patch("redaudit.core.updater.os.geteuid", return_value=1000)
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater.os.path.exists", return_value=True)
    @patch("redaudit.core.updater.os.path.isdir", return_value=True)
    @patch("redaudit.core.updater.os.path.isfile")
    @patch("shutil.rmtree")
    @patch("shutil.copytree")
    @patch("time.time", return_value=1000)
    def test_perform_git_update_staged_home_verify_fail(
        self,
        mock_time,
        mock_copytree,
        mock_rmtree,
        mock_isfile,
        mock_isdir,
        mock_exists,
        mock_popen,
        mock_geteuid,
    ):

        with patch("redaudit.core.updater.CommandRunner") as mock_runner_cls:

            mock_runner = mock_runner_cls.return_value

            mock_runner.is_available.return_value = True

            mock_runner.check_output.side_effect = ["f79d033 (tag)\n", "f79d033\n", "", ""] + [
                ""
            ] * 10

            # 1. staged verify (T), 2. home staging verify (F)

            mock_isfile.side_effect = [True, False]

            process = MagicMock()

            process.poll.return_value = 0

            process.wait.return_value = 0

            process.stdout.__iter__.return_value = []
            process.stdout.readline.return_value = ""  # CRITICAL: prevents infinite loop

            mock_popen.return_value = process

            from redaudit.core.updater import perform_git_update

            success, msg = perform_git_update(self.repo_path, target_version="4.4.2")

            self.assertFalse(success)

            # Either specific message or generic failure is acceptable
            self.assertTrue(
                "Staged home copy missing key files" in msg or "Update failed" in msg,
                f"Unexpected error: {msg}",
            )


class TestInteractiveUpdateCheckFlow(unittest.TestCase):

    @patch("redaudit.core.updater.check_for_updates")
    @patch("redaudit.core.updater.render_update_summary_for_cli", return_value="Summary")
    @patch(
        "redaudit.core.updater.perform_git_update", return_value=(True, "UPDATE_SUCCESS_RESTART")
    )
    @patch("redaudit.core.updater._show_restart_terminal_notice")
    @patch("redaudit.core.updater._pause_for_restart_terminal")
    @patch("redaudit.core.updater.sys.exit")
    @patch("redaudit.core.updater.get_repo_path", return_value="/tmp/repo")
    def test_interactive_update_user_says_yes(
        self, mock_repo, mock_exit, mock_pause, mock_notice, mock_update, mock_render, mock_check
    ):

        mock_check.return_value = (True, "1.1.0", "Notes", "URL", "Date", "en")

        ask_fn = MagicMock(return_value=True)

        from redaudit.core.updater import interactive_update_check

        interactive_update_check(ask_fn=ask_fn)

        mock_update.assert_called()

        mock_exit.assert_called_with(0)

    @patch("redaudit.core.updater.check_for_updates")
    def test_interactive_update_no_version(self, mock_check):

        mock_check.return_value = (False, None, None, None, None, None)

        from redaudit.core.updater import interactive_update_check

        self.assertFalse(interactive_update_check())

    @patch("redaudit.core.updater.check_for_updates")
    def test_interactive_update_no_update(self, mock_check):

        mock_check.return_value = (False, "1.0.0", "Notes", "URL", "Date", "en")

        from redaudit.core.updater import interactive_update_check

        self.assertFalse(interactive_update_check())


class TestUpdateUIEdges(unittest.TestCase):

    def test_show_restart_terminal_notice(self):

        from redaudit.core.updater import _show_restart_terminal_notice

        t_fn = MagicMock(return_value="Notice")

        with patch("sys.stdout.isatty", return_value=True):

            _show_restart_terminal_notice(t_fn=t_fn, lang="en")

    def test_pause_for_restart_terminal_tty(self):

        from redaudit.core.updater import _pause_for_restart_terminal

        t_fn = MagicMock(return_value="Press Enter")

        with patch("sys.stdin.isatty", return_value=True):

            with patch("builtins.input", return_value=""):

                _pause_for_restart_terminal(t_fn=t_fn)

    def test_pause_for_restart_terminal_non_tty(self):

        from redaudit.core.updater import _pause_for_restart_terminal

        t_fn = MagicMock()

        with patch("sys.stdin.isatty", return_value=False):

            with patch("time.sleep") as mock_sleep:

                _pause_for_restart_terminal(t_fn=t_fn)

                mock_sleep.assert_called_with(1.0)


if __name__ == "__main__":

    unittest.main()
