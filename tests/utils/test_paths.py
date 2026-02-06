#!/usr/bin/env python3
"""
RedAudit - Path Helpers Tests
"""

import logging
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, call, mock_open, patch

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.utils import paths
from redaudit.utils.paths import (
    _get_preferred_human_home_under_home,
    _read_xdg_documents_dir,
    _resolve_home_dir_for_user,
    expand_user_path,
    maybe_chown_to_invoking_user,
    maybe_chown_tree_to_invoking_user,
    resolve_invoking_user_owner,
)


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


def test_resolve_home_dir_exception():
    """Test _resolve_home_dir_for_user with exception (line 45)."""
    with patch("os.path.expanduser", side_effect=Exception("Failed")):
        result = _resolve_home_dir_for_user("testuser")
        assert result is None


def test_get_preferred_human_home_getpwall_exception():
    """Test _get_preferred_human_home_under_home with getpwall exception (line 89)."""
    with patch("redaudit.utils.paths._is_root", return_value=True):
        with patch("redaudit.utils.paths.pwd") as mock_pwd:
            mock_pwd.getpwall.side_effect = Exception("Failed")
            result = _get_preferred_human_home_under_home()
            assert result is None


def test_get_preferred_human_home_nologin_shell():
    """Test _get_preferred_human_home_under_home with nologin shell (lines 95-96)."""
    with patch("redaudit.utils.paths._is_root", return_value=True):
        with patch("redaudit.utils.paths.pwd") as mock_pwd:
            mock_entry = MagicMock()
            mock_entry.pw_name = "testuser"
            mock_entry.pw_uid = 1000
            mock_entry.pw_dir = "/home/testuser"
            mock_entry.pw_shell = "/usr/sbin/nologin"
            mock_pwd.getpwall.return_value = [mock_entry]

            result = _get_preferred_human_home_under_home()
            assert result is None


def test_get_preferred_human_home_entry_exception():
    """Test _get_preferred_human_home_under_home with entry exception (lines 101-102)."""
    with patch("redaudit.utils.paths._is_root", return_value=True):
        with patch("redaudit.utils.paths.pwd") as mock_pwd:

            class _BadEntry:
                pw_name = "testuser"
                pw_dir = "/home/testuser"
                pw_shell = "/bin/bash"

                @property
                def pw_uid(self):
                    raise Exception("Failed")

            mock_entry = _BadEntry()
            mock_pwd.getpwall.return_value = [mock_entry]

            result = _get_preferred_human_home_under_home()
            # Should handle exception and return None


def test_get_preferred_human_home_single_candidate():
    """Test _get_preferred_human_home_under_home with single candidate (line 111)."""
    with patch("redaudit.utils.paths._is_root", return_value=True):
        with patch("redaudit.utils.paths.pwd") as mock_pwd:
            with patch("os.path.isdir", return_value=True):
                mock_entry = MagicMock()
                mock_entry.pw_name = "testuser"
                mock_entry.pw_uid = 1000
                mock_entry.pw_dir = "/home/testuser"
                mock_entry.pw_shell = "/bin/bash"
                mock_pwd.getpwall.return_value = [mock_entry]

                result = _get_preferred_human_home_under_home()
                assert result == "/home/testuser"


def test_expand_user_path_empty():
    """Test expand_user_path with empty path (line 161)."""
    result = expand_user_path("   ")
    assert result == ""  # Strips to empty string


def test_read_xdg_documents_dir_skip_comment():
    """Test _read_xdg_documents_dir skipping comments (line 180)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = os.path.join(tmpdir, ".config")
        os.makedirs(config_dir)
        user_dirs = os.path.join(config_dir, "user-dirs.dirs")

        with open(user_dirs, "w") as f:
            f.write("# Comment line\n")
            f.write('XDG_DOCUMENTS_DIR="$HOME/Documents"\n')

        result = _read_xdg_documents_dir(tmpdir)
        assert result is not None


def test_read_xdg_documents_dir_skip_non_documents():
    """Test _read_xdg_documents_dir skipping non-documents lines (line 182)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = os.path.join(tmpdir, ".config")
        os.makedirs(config_dir)
        user_dirs = os.path.join(config_dir, "user-dirs.dirs")

        with open(user_dirs, "w") as f:
            f.write('XDG_DESKTOP_DIR="$HOME/Desktop"\n')
            f.write('XDG_DOCUMENTS_DIR="$HOME/Documents"\n')

        result = _read_xdg_documents_dir(tmpdir)
        assert result is not None


def test_read_xdg_documents_dir_empty_value():
    """Test _read_xdg_documents_dir with empty value (line 190)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = os.path.join(tmpdir, ".config")
        os.makedirs(config_dir)
        user_dirs = os.path.join(config_dir, "user-dirs.dirs")

        with open(user_dirs, "w") as f:
            f.write('XDG_DOCUMENTS_DIR=""\n')

        result = _read_xdg_documents_dir(tmpdir)
        assert result is None


def test_read_xdg_documents_dir_relative_path():
    """Test _read_xdg_documents_dir with relative path (line 192)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = os.path.join(tmpdir, ".config")
        os.makedirs(config_dir)
        user_dirs = os.path.join(config_dir, "user-dirs.dirs")

        with open(user_dirs, "w") as f:
            f.write('XDG_DOCUMENTS_DIR="Documents"\n')

        result = _read_xdg_documents_dir(tmpdir)
        assert result == os.path.join(tmpdir, "Documents")


def test_read_xdg_documents_dir_file_not_found():
    """Test _read_xdg_documents_dir with missing file (line 196-197)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _read_xdg_documents_dir(tmpdir)
        assert result is None


def test_read_xdg_documents_dir_exception():
    """Test _read_xdg_documents_dir with exception (line 198-199)."""
    with patch("builtins.open", side_effect=PermissionError("Access denied")):
        result = _read_xdg_documents_dir("/tmp")
        assert result is None


def test_resolve_invoking_user_owner_pwd_exception():
    """Test resolve_invoking_user_owner with pwd exception (lines 249-252)."""
    with patch("redaudit.utils.paths._is_root", return_value=True):
        with patch("redaudit.utils.paths.get_invoking_user", return_value="testuser"):
            with patch("redaudit.utils.paths.pwd") as mock_pwd:
                mock_pwd.getpwnam.side_effect = Exception("Failed")
                result = resolve_invoking_user_owner()
                assert result is None


def test_maybe_chown_exception(caplog):
    """Test maybe_chown_to_invoking_user with exception (lines 269-270)."""
    with patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)):
        with patch("os.chown", side_effect=PermissionError("Access denied")):
            caplog.set_level(logging.DEBUG)
            maybe_chown_to_invoking_user("/tmp/test")
            # Should not raise
            assert "Failed to chown path to invoking user" in caplog.text


def test_maybe_chown_tree_root_exception(caplog):
    """Test maybe_chown_tree_to_invoking_user with root exception (lines 289-290)."""
    with patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)):
        with patch("os.chown", side_effect=PermissionError("Access denied")):
            caplog.set_level(logging.DEBUG)
            maybe_chown_tree_to_invoking_user("/tmp/test")
            # Should not raise
            assert "Failed to chown root path to invoking user" in caplog.text


def test_maybe_chown_tree_dir_exception():
    """Test maybe_chown_tree_to_invoking_user with dir exception (lines 297-298)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        subdir = os.path.join(tmpdir, "subdir")
        os.makedirs(subdir)

        with patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)):
            with patch("os.chown") as mock_chown:
                mock_chown.side_effect = [None, PermissionError("Failed"), None]
                maybe_chown_tree_to_invoking_user(tmpdir)
                # Should handle exception gracefully


def test_maybe_chown_tree_walk_exception(caplog):
    """Test maybe_chown_tree_to_invoking_user with walk exception (lines 302-305)."""
    with patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)):
        with patch("os.walk", side_effect=Exception("Walk failed")):
            caplog.set_level(logging.DEBUG)
            maybe_chown_tree_to_invoking_user("/tmp/test")
            # Should not raise
            assert "Failed to walk path for chown" in caplog.text


def test_is_root_exception_returns_false():
    with patch("redaudit.utils.paths.os.geteuid", side_effect=Exception("boom")):
        assert paths._is_root() is False


def test_resolve_home_dir_invalid_input():
    assert _resolve_home_dir_for_user(None) is None


def test_resolve_home_dir_expanduser_unresolved():
    with patch("redaudit.utils.paths.pwd", None):
        with patch("redaudit.utils.paths.os.path.expanduser", return_value="~user"):
            assert _resolve_home_dir_for_user("user") is None


def test_get_preferred_human_home_invalid_username():
    class _Entry:
        pw_name = None
        pw_uid = 1000
        pw_dir = "/home/user"
        pw_shell = "/bin/bash"

    with (
        patch("redaudit.utils.paths._is_root", return_value=True),
        patch("redaudit.utils.paths.pwd.getpwall", return_value=[_Entry()]),
        patch("redaudit.utils.paths.os.path.isdir", return_value=True),
    ):
        assert _get_preferred_human_home_under_home() is None


def test_get_preferred_human_home_non_home_dir():
    class _Entry:
        pw_name = "user"
        pw_uid = 1000
        pw_dir = "/Users/user"
        pw_shell = "/bin/bash"

    with (
        patch("redaudit.utils.paths._is_root", return_value=True),
        patch("redaudit.utils.paths.pwd.getpwall", return_value=[_Entry()]),
    ):
        assert _get_preferred_human_home_under_home() is None


def test_get_preferred_human_home_not_dir():
    class _Entry:
        pw_name = "user"
        pw_uid = 1000
        pw_dir = "/home/user"
        pw_shell = "/bin/bash"

    with (
        patch("redaudit.utils.paths._is_root", return_value=True),
        patch("redaudit.utils.paths.pwd.getpwall", return_value=[_Entry()]),
        patch("redaudit.utils.paths.os.path.isdir", return_value=False),
    ):
        assert _get_preferred_human_home_under_home() is None


def test_get_preferred_human_home_multiple_candidates():
    class _Entry:
        def __init__(self, name):
            self.pw_name = name
            self.pw_uid = 1000
            self.pw_dir = f"/home/{name}"
            self.pw_shell = "/bin/bash"

    with (
        patch("redaudit.utils.paths._is_root", return_value=True),
        patch("redaudit.utils.paths.pwd.getpwall", return_value=[_Entry("a"), _Entry("b")]),
        patch("redaudit.utils.paths.os.path.isdir", return_value=True),
    ):
        assert _get_preferred_human_home_under_home() is None


def test_expand_user_path_non_str():
    class _Obj:
        def __str__(self):
            return "value"

    assert expand_user_path(_Obj()) == "value"


def test_read_xdg_documents_dir_no_match_returns_none():
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = os.path.join(tmpdir, ".config")
        os.makedirs(config_dir)
        user_dirs = os.path.join(config_dir, "user-dirs.dirs")
        with open(user_dirs, "w") as f:
            f.write('XDG_DESKTOP_DIR="$HOME/Desktop"\\n')
        assert _read_xdg_documents_dir(tmpdir) is None


def test_resolve_invoking_user_owner_no_env_and_no_user():
    with patch("redaudit.utils.paths._is_root", return_value=True):
        with patch.dict(os.environ, {"SUDO_UID": "", "SUDO_GID": ""}, clear=False):
            with patch("redaudit.utils.paths.get_invoking_user", return_value=None):
                assert resolve_invoking_user_owner() is None


def test_maybe_chown_to_invoking_user_no_chown(monkeypatch):
    monkeypatch.setattr(paths, "resolve_invoking_user_owner", lambda: (1000, 1000))
    monkeypatch.delattr(paths.os, "chown", raising=False)
    maybe_chown_to_invoking_user("/tmp/test")


def test_maybe_chown_tree_no_chown(monkeypatch):
    monkeypatch.setattr(paths, "resolve_invoking_user_owner", lambda: (1000, 1000))
    monkeypatch.delattr(paths.os, "chown", raising=False)
    maybe_chown_tree_to_invoking_user("/tmp/test")


def test_maybe_chown_tree_file_exception():
    with (
        patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)),
        patch(
            "redaudit.utils.paths.os.walk",
            return_value=[("/tmp/out", [], ["a.json"])],
        ),
        patch("redaudit.utils.paths.os.chown", side_effect=[None, PermissionError("fail")]),
    ):
        maybe_chown_tree_to_invoking_user("/tmp/out")
