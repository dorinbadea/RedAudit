"""Tests for updater.py to push coverage to 95%+
Targets atomic swaps, rollbacks, git failures, and verification.
"""

import os
import shutil
import subprocess
import json
import sys
from unittest.mock import patch, MagicMock
import pytest
from urllib.error import URLError, HTTPError
from redaudit.core.updater import (
    perform_git_update,
    compute_tree_diff,
    _inject_default_lang,
    render_update_summary_for_cli,
    _show_restart_terminal_notice,
    _pause_for_restart_terminal,
    get_repo_path,
    interactive_update_check,
    parse_version,
    compare_versions,
    fetch_latest_version,
    fetch_changelog_snippet,
    _extract_release_items,
    format_release_notes_for_cli,
    restart_self,
)


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
