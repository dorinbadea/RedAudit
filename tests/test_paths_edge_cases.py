"""Tests for paths.py to push coverage to 95%+"""

from unittest.mock import patch, MagicMock
import os
import tempfile

from redaudit.utils.paths import (
    _resolve_home_dir_for_user,
    _get_preferred_human_home_under_home,
    expand_user_path,
    _read_xdg_documents_dir,
    resolve_invoking_user_owner,
    maybe_chown_to_invoking_user,
    maybe_chown_tree_to_invoking_user,
)


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
            mock_entry = MagicMock()
            mock_entry.pw_name = "testuser"
            mock_entry.pw_uid = MagicMock(side_effect=Exception("Failed"))
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


def test_maybe_chown_exception():
    """Test maybe_chown_to_invoking_user with exception (lines 269-270)."""
    with patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)):
        with patch("os.chown", side_effect=PermissionError("Access denied")):
            maybe_chown_to_invoking_user("/tmp/test")
            # Should not raise


def test_maybe_chown_tree_root_exception():
    """Test maybe_chown_tree_to_invoking_user with root exception (lines 289-290)."""
    with patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)):
        with patch("os.chown", side_effect=PermissionError("Access denied")):
            maybe_chown_tree_to_invoking_user("/tmp/test")
            # Should not raise


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


def test_maybe_chown_tree_walk_exception():
    """Test maybe_chown_tree_to_invoking_user with walk exception (lines 302-305)."""
    with patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)):
        with patch("os.walk", side_effect=Exception("Walk failed")):
            maybe_chown_tree_to_invoking_user("/tmp/test")
            # Should not raise
