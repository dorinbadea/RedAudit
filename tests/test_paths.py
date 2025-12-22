#!/usr/bin/env python3
"""
RedAudit - Path Helpers Tests
"""

import os
import sys
import unittest
from types import SimpleNamespace
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

    @unittest.skipIf(paths.pwd is None, "pwd not available on this platform")
    def test_get_default_reports_base_dir_prefers_single_human_user_under_home_when_root(self):
        class _PwEntry:
            def __init__(self, name, uid, home, shell="/bin/bash"):
                self.pw_name = name
                self.pw_uid = uid
                self.pw_dir = home
                self.pw_shell = shell

        def isdir_side_effect(p):
            return p in {"/home/kali", "/home/kali/Documents"}

        with (
            patch("redaudit.utils.paths.os.geteuid", return_value=0),
            patch(
                "redaudit.utils.paths.pwd.getpwall",
                return_value=[_PwEntry("kali", 1000, "/home/kali")],
            ),
            patch("redaudit.utils.paths.open", side_effect=FileNotFoundError),
            patch("redaudit.utils.paths.os.path.isdir", side_effect=isdir_side_effect),
        ):
            self.assertEqual(
                paths.get_default_reports_base_dir(), "/home/kali/Documents/RedAuditReports"
            )


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


class TestInvokingUser(unittest.TestCase):
    def test_get_invoking_user_returns_none_when_not_root(self):
        with (
            patch("redaudit.utils.paths.os.geteuid", return_value=1000),
            patch.dict(os.environ, {"SUDO_USER": "alice"}, clear=False),
        ):
            self.assertIsNone(paths.get_invoking_user())

    def test_get_invoking_user_returns_sudo_user(self):
        with (
            patch("redaudit.utils.paths.os.geteuid", return_value=0),
            patch.dict(os.environ, {"SUDO_USER": "alice"}, clear=False),
        ):
            self.assertEqual(paths.get_invoking_user(), "alice")

    def test_get_invoking_user_ignores_root(self):
        with (
            patch("redaudit.utils.paths.os.geteuid", return_value=0),
            patch.dict(os.environ, {"SUDO_USER": "root"}, clear=False),
        ):
            self.assertIsNone(paths.get_invoking_user())

    def test_resolve_invoking_user_owner_uses_sudo_ids(self):
        with (
            patch("redaudit.utils.paths.os.geteuid", return_value=0),
            patch.dict(os.environ, {"SUDO_UID": "1001", "SUDO_GID": "1002"}, clear=False),
        ):
            self.assertEqual(paths.resolve_invoking_user_owner(), (1001, 1002))

    @unittest.skipIf(paths.pwd is None, "pwd not available on this platform")
    def test_resolve_invoking_user_owner_uses_pwd(self):
        with (
            patch("redaudit.utils.paths.os.geteuid", return_value=0),
            patch.dict(os.environ, {"SUDO_UID": "", "SUDO_GID": ""}, clear=False),
            patch("redaudit.utils.paths.get_invoking_user", return_value="alice"),
            patch(
                "redaudit.utils.paths.pwd.getpwnam",
                return_value=SimpleNamespace(pw_uid=2000, pw_gid=2001),
            ),
        ):
            self.assertEqual(paths.resolve_invoking_user_owner(), (2000, 2001))

    def test_resolve_invoking_user_owner_non_root(self):
        with patch("redaudit.utils.paths.os.geteuid", return_value=1000):
            self.assertIsNone(paths.resolve_invoking_user_owner())


if __name__ == "__main__":
    unittest.main()
