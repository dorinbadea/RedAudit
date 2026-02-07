import unittest
from urllib.parse import urlparse
from unittest.mock import patch, MagicMock, Mock
import sys
import io
import json
from urllib.error import URLError, HTTPError
from redaudit.core.updater import (
    check_for_updates,
    render_update_summary_for_cli,
    interactive_update_check,
    compare_versions,
    parse_version,
    format_release_notes_for_cli,
    fetch_changelog_snippet,
    _extract_release_items,
    fetch_latest_version,
    restart_self,
    _get_update_check_cache_path,
)


class TestUpdaterCliLogic(unittest.TestCase):
    def setUp(self):
        self.mock_logger = MagicMock()
        self.mock_print = MagicMock()

    def test_get_update_check_cache_path_fallback(self):
        # Test fallback when platformdirs is missing or fails
        with patch.dict("sys.modules", {"platformdirs": None}):
            # Verify it uses ~/.redaudit/update_check_cache.json
            path = _get_update_check_cache_path()
            self.assertIn("update_check_cache.json", str(path))
            self.assertIn(".redaudit", str(path))

    @patch("os.execv")
    @patch("os.execvp", side_effect=Exception("execvp failed"))
    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile", return_value=True)
    @patch("sys.executable", "/usr/bin/python3")
    @patch("sys.argv", ["script.py", "arg1"])
    def test_restart_self(self, mock_isfile, mock_which, mock_execvp, mock_execv):
        restart_self(logger=self.mock_logger)
        mock_execv.assert_called_with("/usr/bin/python3", ["/usr/bin/python3", "script.py", "arg1"])

    def test_parse_version(self):
        self.assertEqual(parse_version("1.0.0"), (1, 0, 0, ""))
        self.assertEqual(parse_version("  2.1.3  "), (2, 1, 3, ""))
        self.assertEqual(parse_version("3.0.0a"), (3, 0, 0, "a"))
        self.assertEqual(parse_version("invalid"), (0, 0, 0, ""))

    def test_compare_versions(self):
        self.assertEqual(compare_versions("1.0.0", "1.0.0"), 0)
        self.assertEqual(compare_versions("1.0.0", "1.0.1"), -1)
        self.assertEqual(compare_versions("1.0.1", "1.0.0"), 1)
        self.assertEqual(compare_versions("1.0.0", "2.0.0"), -1)
        self.assertEqual(compare_versions("1.0.0", "1.0.0a"), -1)
        self.assertEqual(compare_versions("1.0.0a", "1.0.0b"), -1)
        self.assertEqual(compare_versions("1.0.0b", "1.0.0a"), 1)

    @patch("redaudit.core.updater.compare_versions")
    @patch("redaudit.core.updater.fetch_latest_version")
    def test_check_for_updates_success_major(self, mock_fetch, mock_compare):
        mock_fetch.return_value = {
            "tag_name": "99.0.0",
            "html_url": "url",
            "published_at": "2026-01-01",
            "body": "## Added\n- Feature",
        }
        mock_compare.return_value = -1  # Update available

        update_available, latest_ver, notes, url, pub_date, lang = check_for_updates(
            logger=self.mock_logger
        )

        self.assertTrue(update_available)
        self.assertEqual(latest_ver, "99.0.0")

    @patch("redaudit.core.updater.compare_versions")
    @patch("redaudit.core.updater.fetch_latest_version")
    def test_check_for_updates_no_update(self, mock_fetch, mock_compare):
        mock_fetch.return_value = {"tag_name": "current", "html_url": "url", "body": "notes"}
        mock_compare.return_value = 0

        update_available, latest_ver, notes, url, pub_date, lang = check_for_updates(
            logger=self.mock_logger
        )

        self.assertFalse(update_available)
        from redaudit.core.updater import VERSION

        self.assertEqual(latest_ver, VERSION)

    @patch("redaudit.core.updater.fetch_latest_version")
    def test_check_for_updates_api_failure(self, mock_fetch):
        mock_fetch.return_value = None
        result = check_for_updates(logger=self.mock_logger)
        self.assertEqual(result, (False, None, None, None, None, None))

    @patch("redaudit.core.updater.fetch_latest_version")
    def test_check_for_updates_rate_limit(self, mock_fetch):
        mock_fetch.return_value = None
        result = check_for_updates(logger=self.mock_logger)
        self.assertEqual(result, (False, None, None, None, None, None))

    def test_render_update_summary_cli_formatting(self):
        t_fn = lambda k, *a: f"{k} {' '.join(str(x) for x in a)}".strip()
        summary = render_update_summary_for_cli(
            current_version="1.0.0",
            latest_version="2.0.0",
            release_notes="## Added\n- Feature A",
            release_url="http://url",
            published_at="2026-01-01",
            lang="en",
            t_fn=t_fn,
        )
        self.assertIn("update_release_type Major", summary)
        self.assertIn("- Feature A", summary)

    @patch("sys.stdout.isatty", return_value=True)
    @patch("shutil.get_terminal_size")
    def test_render_update_summary_cli_wrapping(self, mock_term_size, mock_isatty):
        mock_term_size.return_value = Mock(columns=40)
        t_fn = lambda k, *a: k

        long_note = "- " + "A " * 40  # Spaces allow wrapping
        summary = render_update_summary_for_cli(
            current_version="1.0.0",
            latest_version="1.1.0",
            release_notes=long_note,
            release_url="",
            published_at="",
            lang="en",
            t_fn=t_fn,
        )
        self.assertIn("\n  A", summary)

    @patch("redaudit.core.updater.check_for_updates")
    @patch("redaudit.core.updater.perform_git_update")
    @patch("redaudit.core.updater._show_restart_terminal_notice")
    @patch("redaudit.core.updater._pause_for_restart_terminal")
    @patch("sys.exit")
    def test_interactive_update_check_flow_success(
        self, mock_exit, mock_pause, mock_show_notice, mock_perform, mock_check
    ):
        mock_check.return_value = (True, "2.0.0", "Notes", "URL", "Date", "en")
        ask_fn = MagicMock(return_value=True)
        mock_perform.return_value = (True, "Success")

        # Mock t_fn (translation function) as it's passed or defaulted
        # interactive_update_check uses default t_fn if None.

        interactive_update_check(
            lang="en", logger=self.mock_logger, print_fn=self.mock_print, ask_fn=ask_fn
        )

        mock_check.assert_called_once()
        mock_perform.assert_called_once()
        mock_show_notice.assert_called_once()
        mock_exit.assert_called_with(0)

    @patch("redaudit.core.updater.check_for_updates")
    @patch("redaudit.core.updater.perform_git_update")
    def test_interactive_update_check_user_decline(self, mock_perform, mock_check):
        mock_check.return_value = (True, "2.0.0", "Notes", "URL", "Date", "en")
        ask_fn = MagicMock(return_value=False)
        result = interactive_update_check(
            lang="en", logger=self.mock_logger, print_fn=self.mock_print, ask_fn=ask_fn
        )
        mock_perform.assert_not_called()
        self.assertFalse(result)

    @patch("redaudit.core.updater.check_for_updates")
    def test_interactive_update_check_no_update(self, mock_check):
        mock_check.return_value = (False, "1.0.0", None, None, None, "en")
        result = interactive_update_check(
            lang="en", logger=self.mock_logger, print_fn=self.mock_print
        )
        self.assertFalse(result)

    def test_extract_release_items_complex(self):
        notes = """
## Added
- Item 1
- Item 2
## Seguridad
- Sec fix
## Ignored
- View in English
- https://shields.io/badge
# Bad Header
- Bad item
"""
        items = _extract_release_items(notes)
        self.assertIn("Item 1", items["highlights"] + items.get("added", []))
        # Note: _extract_release_items returns {"highlights": [], "breaking": []} only?
        # Check impl: returns {"highlights": ..., "breaking": ...}
        # It aggregates into highlights.

        # "Item 1" should be in highlights.
        self.assertIn("Item 1", items["highlights"])

        # "Sec fix" under "Seguridad" -> "security" -> highlights (order: security, added...)
        self.assertIn("Sec fix", items["highlights"])

        # "View in English" should be dropped
        for item in items["highlights"]:
            self.assertNotEqual(item, "View in English")
            self.assertNotEqual(urlparse(item).netloc, "shields.io")

    def test_format_release_notes_for_cli(self):
        notes = "- Item 1\n- Item 2"
        # Since logic wraps, check for content presence
        formatted = format_release_notes_for_cli(notes, width=50)
        self.assertIn("Item 1", formatted)
        self.assertIn("Item 2", formatted)

    @patch("redaudit.core.updater.urlopen")
    @patch("redaudit.core.updater.Request")
    def test_fetch_latest_version_logic(self, mock_req, mock_urlopen):
        # Mock Context Manager
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({"tag_name": "1.2.3"}).encode("utf-8")
        mock_urlopen.return_value = mock_response

        data = fetch_latest_version(logger=self.mock_logger)

        self.assertIsNotNone(data, "Data should not be None")
        self.assertEqual(data["tag_name"], "1.2.3")

    @patch("redaudit.core.updater.urlopen")
    @patch("redaudit.core.updater.Request")
    def test_fetch_latest_version_failure(self, mock_req, mock_urlopen):
        mock_urlopen.side_effect = URLError("Fail")
        data = fetch_latest_version(logger=self.mock_logger)
        self.assertIsNone(data)
        self.mock_logger.warning.assert_called()


if __name__ == "__main__":
    unittest.main()
