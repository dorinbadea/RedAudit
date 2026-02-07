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
