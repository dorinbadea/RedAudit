#!/usr/bin/env python3
"""
RedAudit - Path Helpers Tests
"""

import os
import sys
import unittest
from unittest.mock import patch, mock_open, call

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.utils import paths


class TestExpandUserPath(unittest.TestCase):
    def test_expand_user_path_under_sudo_uses_invoking_user_home(self):
        with (
            patch.dict(os.environ, {"SUDO_USER": "alice"}, clear=False),
            patch("redaudit.utils.paths.os.geteuid", return_value=0),
            patch(
                "redaudit.utils.paths.os.path.expanduser",
                side_effect=lambda p: "/home/alice" if p == "~alice" else p,
            ),
        ):
            self.assertEqual(paths.expand_user_path("~/Documents"), "/home/alice/Documents")

    def test_expand_user_path_keeps_named_user_expansion(self):
        with (
            patch.dict(os.environ, {"SUDO_USER": "alice"}, clear=False),
            patch("redaudit.utils.paths.os.geteuid", return_value=0),
            patch(
                "redaudit.utils.paths.os.path.expanduser",
                side_effect=lambda p: "/home/bob/Documents" if p == "~bob/Documents" else p,
            ),
        ):
            self.assertEqual(paths.expand_user_path("~bob/Documents"), "/home/bob/Documents")


class TestDocumentsDir(unittest.TestCase):
    def test_get_documents_dir_prefers_xdg_user_dirs(self):
        content = 'XDG_DOCUMENTS_DIR="$HOME/Documentos"\n'
        with (
            patch("redaudit.utils.paths.open", mock_open(read_data=content)),
            patch("redaudit.utils.paths.os.path.isabs", return_value=True),
        ):
            self.assertEqual(paths.get_documents_dir("/home/alice"), "/home/alice/Documentos")

    def test_get_documents_dir_falls_back_to_existing_documentos(self):
        def isdir_side_effect(p):
            if p == "/home/alice/Documentos":
                return True
            if p == "/home/alice/Documents":
                return False
            return False

        with (
            patch("redaudit.utils.paths.open", side_effect=FileNotFoundError),
            patch("redaudit.utils.paths.os.path.isdir", side_effect=isdir_side_effect),
        ):
            self.assertEqual(paths.get_documents_dir("/home/alice"), "/home/alice/Documentos")


class TestChownTree(unittest.TestCase):
    def test_maybe_chown_tree_calls_chown(self):
        with (
            patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)),
            patch("redaudit.utils.paths.os.chown") as mock_chown,
            patch(
                "redaudit.utils.paths.os.walk",
                return_value=[
                    ("/tmp/out", ["sub"], ["a.json"]),
                    ("/tmp/out/sub", [], ["b.txt"]),
                ],
            ),
        ):
            paths.maybe_chown_tree_to_invoking_user("/tmp/out")
            mock_chown.assert_has_calls(
                [
                    call("/tmp/out", 1000, 1000),
                    call("/tmp/out/sub", 1000, 1000),
                    call("/tmp/out/a.json", 1000, 1000),
                    call("/tmp/out/sub/b.txt", 1000, 1000),
                ],
                any_order=True,
            )


if __name__ == "__main__":
    unittest.main()
