"""
Tests for updater.py edge cases and missing coverage lines.
Target: Push updater.py from 73% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock, Mock
from urllib.error import HTTPError, URLError
import io
import sys


class TestFetchLatestVersionErrors:
    """Tests for error handling in fetch_latest_version (lines 107-115)."""

    def test_fetch_latest_version_http_error_with_logger(self):
        """Test HTTPError logging (line 109)."""
        from redaudit.core.updater import fetch_latest_version

        mock_logger = MagicMock()
        with patch("redaudit.core.updater.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = HTTPError(
                url="http://test", code=403, msg="Forbidden", hdrs={}, fp=None
            )
            result = fetch_latest_version(logger=mock_logger)

        assert result is None
        mock_logger.warning.assert_called()

    def test_fetch_latest_version_url_error_with_logger(self):
        """Test URLError logging (lines 111-112)."""
        from redaudit.core.updater import fetch_latest_version

        mock_logger = MagicMock()
        with patch("redaudit.core.updater.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("Connection refused")
            result = fetch_latest_version(logger=mock_logger)

        assert result is None
        mock_logger.warning.assert_called()

    def test_fetch_latest_version_generic_exception_with_logger(self):
        """Test generic exception logging (lines 114-115)."""
        from redaudit.core.updater import fetch_latest_version

        mock_logger = MagicMock()
        with patch("redaudit.core.updater.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = ValueError("Unexpected error")
            result = fetch_latest_version(logger=mock_logger)

        assert result is None
        mock_logger.debug.assert_called()


class TestFetchChangelogSnippetErrors:
    """Tests for error handling in fetch_changelog_snippet (lines 148-149, 159-161)."""

    def test_fetch_changelog_non_200_response(self):
        """Test non-200 response continues to next URL (line 149)."""
        from redaudit.core.updater import fetch_changelog_snippet

        mock_response = MagicMock()
        mock_response.status = 404
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch("redaudit.core.updater.urlopen", return_value=mock_response):
            result = fetch_changelog_snippet("3.8.9")

        assert result is None

    def test_fetch_changelog_exception_with_logger(self):
        """Test exception logging (lines 159-161)."""
        from redaudit.core.updater import fetch_changelog_snippet

        mock_logger = MagicMock()
        with patch("redaudit.core.updater.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("Network timeout")
            result = fetch_changelog_snippet("3.8.9", logger=mock_logger)

        assert result is None
        mock_logger.debug.assert_called()


class TestExtractReleaseDateFromNotes:
    """Tests for _extract_release_date_from_notes edge cases (lines 217, 227-228)."""

    def test_extract_release_date_empty_notes(self):
        """Test with empty notes (line 217->218)."""
        from redaudit.core.updater import _extract_release_date_from_notes

        result = _extract_release_date_from_notes("", "3.8.9")
        assert result is None

    def test_extract_release_date_none_notes(self):
        """Test with None notes (line 217)."""
        from redaudit.core.updater import _extract_release_date_from_notes

        result = _extract_release_date_from_notes(None, "3.8.9")
        assert result is None

    def test_extract_release_date_regex_exception(self):
        """Test regex exception handling (lines 227-228)."""
        from redaudit.core.updater import _extract_release_date_from_notes

        # Force a regex exception by mocking re.search to raise
        with patch("redaudit.core.updater.re.search") as mock_search:
            mock_search.side_effect = Exception("Regex catastrophic backtracking")
            result = _extract_release_date_from_notes("## [3.8.9] - 2025-12-25", "3.8.9")

        assert result is None


class TestCheckForUpdatesEdgeCases:
    """Tests for check_for_updates edge cases (lines 188-189, 199-202)."""

    def test_check_for_updates_no_latest_version(self):
        """Test when latest_version is empty (lines 188-189)."""
        from redaudit.core.updater import check_for_updates

        with patch("redaudit.core.updater.fetch_latest_version") as mock_fetch:
            mock_fetch.return_value = {"tag_name": "", "html_url": "", "published_at": ""}
            result = check_for_updates()

        assert result[0] is False  # update_available
        assert result[1] is None  # latest_version

    def test_check_for_updates_fallback_to_release_body(self):
        """Test fallback to release body when changelog snippet empty (lines 199-202)."""
        from redaudit.core import updater
        from redaudit.core.updater import check_for_updates

        with patch.object(updater, "VERSION", "3.0.0"):
            with patch("redaudit.core.updater.fetch_latest_version") as mock_fetch:
                mock_fetch.return_value = {
                    "tag_name": "3.9.0",
                    "body": "Release body content here",
                    "html_url": "https://github.com/test",
                    "published_at": "2025-12-25",
                }
                with patch("redaudit.core.updater.fetch_changelog_snippet") as mock_changelog:
                    mock_changelog.return_value = None  # No changelog found
                    result = check_for_updates()

        assert result[0] is True  # update_available
        assert result[2] == "Release body content here"  # release_notes from body


class TestRenderUpdateSummaryForCliEdgeCases:
    """Tests for render_update_summary_for_cli edge cases (lines 363-366, 389-394)."""

    def test_render_terminal_width_exception(self):
        """Test terminal width exception handling (lines 365-366)."""
        from redaudit.core.updater import render_update_summary_for_cli

        def mock_t(key, *args):
            return f"{key}: {args}" if args else key

        with patch("shutil.get_terminal_size") as mock_size:
            mock_size.side_effect = Exception("No terminal")
            result = render_update_summary_for_cli(
                current_version="3.8.0",
                latest_version="3.9.0",
                release_notes="## [3.9.0]\n- New feature",
                release_url="https://github.com/test",
                published_at="2025-12-25",
                lang="en",
                t_fn=mock_t,
            )

        assert "3.9.0" in str(result) or "update" in str(result).lower()

    def test_render_notes_lang_fallback_en(self):
        """Test notes_lang fallback when en (lines 391-392)."""
        from redaudit.core.updater import render_update_summary_for_cli

        def mock_t(key, *args):
            return f"[{key}]" + (f": {args[0]}" if args else "")

        result = render_update_summary_for_cli(
            current_version="3.8.0",
            latest_version="3.9.0",
            release_notes="## [3.9.0]\n- Feature",
            release_url=None,
            published_at=None,
            lang="es",  # User wants Spanish
            notes_lang="en",  # But notes are in English
            t_fn=mock_t,
        )

        assert "[update_notes_fallback_en]" in result

    def test_render_notes_lang_fallback_es(self):
        """Test notes_lang fallback when es (lines 393-394)."""
        from redaudit.core.updater import render_update_summary_for_cli

        def mock_t(key, *args):
            return f"[{key}]" + (f": {args[0]}" if args else "")

        result = render_update_summary_for_cli(
            current_version="3.8.0",
            latest_version="3.9.0",
            release_notes="## [3.9.0]\n- Característica",
            release_url=None,
            published_at=None,
            lang="en",  # User wants English
            notes_lang="es",  # But notes are in Spanish
            t_fn=mock_t,
        )

        assert "[update_notes_fallback_es]" in result


class TestParsePublishedDate:
    """Tests for _parse_published_date function (lines 209-213)."""

    def test_parse_published_date_valid(self):
        """Test valid date string."""
        from redaudit.core.updater import _parse_published_date

        result = _parse_published_date("2025-12-25T10:30:00Z")
        assert result == "2025-12-25"

    def test_parse_published_date_none(self):
        """Test None input (line 210-211)."""
        from redaudit.core.updater import _parse_published_date

        result = _parse_published_date(None)
        assert result is None

    def test_parse_published_date_empty(self):
        """Test empty string."""
        from redaudit.core.updater import _parse_published_date

        result = _parse_published_date("")
        assert result is None

    def test_parse_published_date_invalid_format(self):
        """Test invalid date format (line 212-213, no match)."""
        from redaudit.core.updater import _parse_published_date

        result = _parse_published_date("not-a-date")
        assert result is None


class TestClassifyReleaseType:
    """Tests for _classify_release_type function (lines 232-239)."""

    def test_classify_major_release(self):
        """Test major version bump (line 235-236)."""
        from redaudit.core.updater import _classify_release_type

        result = _classify_release_type("3.8.9", "4.0.0")
        assert result == "Major"

    def test_classify_minor_release(self):
        """Test minor version bump (line 237-238)."""
        from redaudit.core.updater import _classify_release_type

        result = _classify_release_type("3.8.9", "3.9.0")
        assert result == "Minor"

    def test_classify_patch_release(self):
        """Test patch version bump (line 239)."""
        from redaudit.core.updater import _classify_release_type

        result = _classify_release_type("3.8.9", "3.8.10")
        assert result == "Patch"


class TestInjectDefaultLang:
    """Tests for _inject_default_lang function (lines 667-696)."""

    def test_inject_default_lang_invalid_lang(self, tmp_path):
        """Test invalid lang falls back to en (line 673-674)."""
        from redaudit.core.updater import _inject_default_lang

        constants_file = tmp_path / "constants.py"
        constants_file.write_text('DEFAULT_LANG = "es"\n')

        result = _inject_default_lang(str(constants_file), "fr")  # Invalid lang

        assert result is True
        content = constants_file.read_text()
        assert 'DEFAULT_LANG = "en"' in content

    def test_inject_default_lang_file_not_exists(self, tmp_path):
        """Test non-existent file returns False (line 676-677)."""
        from redaudit.core.updater import _inject_default_lang

        result = _inject_default_lang(str(tmp_path / "nonexistent.py"), "en")
        assert result is False

    def test_inject_default_lang_modifies_file(self, tmp_path):
        """Test successful lang injection (lines 679-694)."""
        from redaudit.core.updater import _inject_default_lang

        constants_file = tmp_path / "constants.py"
        constants_file.write_text('DEFAULT_LANG = "en"\nOTHER_VAR = "value"\n')

        result = _inject_default_lang(str(constants_file), "es")

        assert result is True
        content = constants_file.read_text()
        assert 'DEFAULT_LANG = "es"' in content
        assert 'OTHER_VAR = "value"' in content

    def test_inject_default_lang_appends_if_missing(self, tmp_path):
        """Test append if DEFAULT_LANG missing (lines 687-689)."""
        from redaudit.core.updater import _inject_default_lang

        constants_file = tmp_path / "constants.py"
        constants_file.write_text('OTHER_VAR = "value"\n')

        result = _inject_default_lang(str(constants_file), "es")

        assert result is True
        content = constants_file.read_text()
        assert 'DEFAULT_LANG = "es"' in content

    def test_inject_default_lang_exception(self, tmp_path):
        """Test exception returns False (lines 695-696)."""
        from redaudit.core.updater import _inject_default_lang

        with patch("builtins.open") as mock_open:
            mock_open.side_effect = PermissionError("Access denied")
            result = _inject_default_lang(str(tmp_path / "test.py"), "en")

        assert result is False


class TestComputeTreeDiff:
    """Tests for compute_tree_diff function (lines 633-664)."""

    def test_compute_tree_diff_added_files(self, tmp_path):
        """Test detecting added files (line 647)."""
        from redaudit.core.updater import compute_tree_diff

        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        new_dir.mkdir()

        (old_dir / "existing.py").write_text("old")
        (new_dir / "existing.py").write_text("old")
        (new_dir / "new_file.py").write_text("new")

        result = compute_tree_diff(str(old_dir), str(new_dir))

        assert "new_file.py" in result["added"]
        assert result["removed"] == []

    def test_compute_tree_diff_removed_files(self, tmp_path):
        """Test detecting removed files (line 648)."""
        from redaudit.core.updater import compute_tree_diff

        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        new_dir.mkdir()

        (old_dir / "existing.py").write_text("old")
        (old_dir / "to_remove.py").write_text("remove")
        (new_dir / "existing.py").write_text("old")

        result = compute_tree_diff(str(old_dir), str(new_dir))

        assert "to_remove.py" in result["removed"]
        assert result["added"] == []

    def test_compute_tree_diff_modified_files(self, tmp_path):
        """Test detecting modified files (lines 651-662)."""
        from redaudit.core.updater import compute_tree_diff

        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        new_dir.mkdir()

        (old_dir / "mod.py").write_text("original content")
        (new_dir / "mod.py").write_text("modified content")

        result = compute_tree_diff(str(old_dir), str(new_dir))

        assert "mod.py" in result["modified"]


class TestRestartSelf:
    """Tests for restart_self function (lines 553-591)."""

    def test_restart_self_empty_argv(self):
        """Test empty argv returns False (lines 562-564)."""
        from redaudit.core.updater import restart_self

        with patch("sys.argv", []):
            result = restart_self()

        assert result is False

    def test_restart_self_execvp_exception_with_logger(self):
        """Test execvp exception logging (lines 570-572)."""
        from redaudit.core.updater import restart_self

        mock_logger = MagicMock()
        with patch("sys.argv", ["redaudit", "--help"]):
            with patch("os.execvp") as mock_execvp:
                mock_execvp.side_effect = OSError("execvp failed")
                with patch("shutil.which", return_value=None):
                    with patch("os.path.isfile", return_value=False):
                        result = restart_self(logger=mock_logger)

        assert result is False
        mock_logger.debug.assert_called()

    def test_restart_self_resolved_execv_fails(self):
        """Test resolved execv exception (lines 579-581)."""
        from redaudit.core.updater import restart_self

        mock_logger = MagicMock()
        with patch("sys.argv", ["redaudit"]):
            with patch("os.execvp") as mock_execvp:
                mock_execvp.side_effect = OSError("first fail")
                with patch("shutil.which", return_value="/usr/bin/redaudit"):
                    with patch("os.execv") as mock_execv:
                        mock_execv.side_effect = OSError("second fail")
                        with patch("os.path.isfile", return_value=False):
                            result = restart_self(logger=mock_logger)

        assert result is False

    def test_restart_self_python_fallback_fails(self):
        """Test python fallback exception (lines 584-589)."""
        from redaudit.core.updater import restart_self

        mock_logger = MagicMock()
        with patch("sys.argv", ["/path/to/script.py"]):
            with patch("os.execvp") as mock_execvp:
                mock_execvp.side_effect = OSError("fail")
                with patch("shutil.which", return_value=None):
                    with patch("os.path.isfile", return_value=True):
                        with patch("os.execv") as mock_execv:
                            mock_execv.side_effect = OSError("python fail")
                            result = restart_self(logger=mock_logger)

        assert result is False
        # Should have logged at least one debug message
        assert mock_logger.debug.call_count >= 1


class TestComputeFileHash:
    """Tests for compute_file_hash function (lines 594-611)."""

    def test_compute_file_hash_sha256(self, tmp_path):
        """Test SHA256 hash computation."""
        from redaudit.core.updater import compute_file_hash

        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        result = compute_file_hash(str(test_file), "sha256")

        assert len(result) == 64  # SHA256 hex is 64 chars
        assert result.isalnum()

    def test_compute_file_hash_sha512(self, tmp_path):
        """Test SHA512 hash computation."""
        from redaudit.core.updater import compute_file_hash

        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        result = compute_file_hash(str(test_file), "sha512")

        assert len(result) == 128  # SHA512 hex is 128 chars


class TestIterFiles:
    """Tests for _iter_files function (lines 614-630)."""

    def test_iter_files_excludes_pycache(self, tmp_path):
        """Test __pycache__ is excluded."""
        from redaudit.core.updater import _iter_files

        (tmp_path / "module.py").write_text("code")
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "module.cpython-39.pyc").write_text("bytecode")

        result = list(_iter_files(str(tmp_path)))

        assert "module.py" in result
        assert "__pycache__" not in str(result)

    def test_iter_files_sorted_output(self, tmp_path):
        """Test files are returned sorted."""
        from redaudit.core.updater import _iter_files

        (tmp_path / "z_last.py").write_text("")
        (tmp_path / "a_first.py").write_text("")
        (tmp_path / "m_middle.py").write_text("")

        result = list(_iter_files(str(tmp_path)))

        assert result == sorted(result)
