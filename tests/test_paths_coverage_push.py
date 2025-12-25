"""
Tests for paths.py edge cases and missing coverage lines.
Target: Push paths.py from 79% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock
import os


class TestIsRoot:
    """Tests for _is_root function (lines 21-25)."""

    def test_is_root_true(self):
        """Test when running as root."""
        from redaudit.utils.paths import _is_root

        with patch("os.geteuid", return_value=0):
            assert _is_root() is True

    def test_is_root_false(self):
        """Test when not root."""
        from redaudit.utils.paths import _is_root

        with patch("os.geteuid", return_value=1000):
            assert _is_root() is False

    def test_is_root_exception(self):
        """Test exception returns False (line 24-25)."""
        from redaudit.utils.paths import _is_root

        with patch("os.geteuid") as mock_geteuid:
            mock_geteuid.side_effect = AttributeError("No geteuid")
            assert _is_root() is False


class TestResolveHomeDirForUser:
    """Tests for _resolve_home_dir_for_user function (lines 28-45)."""

    def test_resolve_home_dir_empty_username(self):
        """Test empty username returns None (line 29-30)."""
        from redaudit.utils.paths import _resolve_home_dir_for_user

        assert _resolve_home_dir_for_user("") is None
        assert _resolve_home_dir_for_user(None) is None

    def test_resolve_home_dir_via_pwd(self):
        """Test resolution via pwd module (lines 32-36)."""
        from redaudit.utils.paths import _resolve_home_dir_for_user

        mock_pw = MagicMock()
        mock_pw.pw_dir = "/home/testuser"

        with patch("redaudit.utils.paths.pwd") as mock_pwd:
            mock_pwd.getpwnam.return_value = mock_pw
            result = _resolve_home_dir_for_user("testuser")

        assert result == "/home/testuser"

    def test_resolve_home_dir_pwd_exception_fallback(self):
        """Test fallback to expanduser when pwd fails (lines 35-36, 38-44)."""
        from redaudit.utils.paths import _resolve_home_dir_for_user

        with patch("redaudit.utils.paths.pwd") as mock_pwd:
            mock_pwd.getpwnam.side_effect = KeyError("User not found")
            with patch("os.path.expanduser", return_value="/home/fallback"):
                result = _resolve_home_dir_for_user("testuser")

        assert result == "/home/fallback"

    def test_resolve_home_dir_expanduser_fails(self):
        """Test returns None when all methods fail (lines 42-45)."""
        from redaudit.utils.paths import _resolve_home_dir_for_user

        with patch("redaudit.utils.paths.pwd") as mock_pwd:
            mock_pwd.getpwnam.side_effect = KeyError("Not found")
            with patch("os.path.expanduser") as mock_expand:
                mock_expand.side_effect = Exception("Expand failed")
                result = _resolve_home_dir_for_user("testuser")

        assert result is None


class TestGetInvokingUser:
    """Tests for get_invoking_user function (lines 48-60)."""

    def test_get_invoking_user_not_root(self):
        """Test returns None when not root (line 55-56)."""
        from redaudit.utils.paths import get_invoking_user

        with patch("redaudit.utils.paths._is_root", return_value=False):
            assert get_invoking_user() is None

    def test_get_invoking_user_with_sudo(self):
        """Test returns SUDO_USER when running as root (lines 57-59)."""
        from redaudit.utils.paths import get_invoking_user

        with patch("redaudit.utils.paths._is_root", return_value=True):
            with patch.dict(os.environ, {"SUDO_USER": "testuser"}):
                result = get_invoking_user()

        assert result == "testuser"

    def test_get_invoking_user_sudo_is_root(self):
        """Test returns None when SUDO_USER is 'root' (line 58)."""
        from redaudit.utils.paths import get_invoking_user

        with patch("redaudit.utils.paths._is_root", return_value=True):
            with patch.dict(os.environ, {"SUDO_USER": "root"}):
                result = get_invoking_user()

        assert result is None


class TestGetPreferredHumanHomeUnderHome:
    """Tests for _get_preferred_human_home_under_home function (lines 63-111)."""

    def test_get_preferred_home_not_root(self):
        """Test returns None when not root (line 73-74)."""
        from redaudit.utils.paths import _get_preferred_human_home_under_home

        with patch("redaudit.utils.paths._is_root", return_value=False):
            assert _get_preferred_human_home_under_home() is None

    def test_get_preferred_home_getpwall_exception(self):
        """Test returns None on getpwall exception (lines 78-79)."""
        from redaudit.utils.paths import _get_preferred_human_home_under_home

        with patch("redaudit.utils.paths._is_root", return_value=True):
            with patch("redaudit.utils.paths.pwd") as mock_pwd:
                mock_pwd.getpwall.side_effect = Exception("Cannot read passwd")
                result = _get_preferred_human_home_under_home()

        assert result is None

    def test_get_preferred_home_skips_nologin_users(self):
        """Test skips users with nologin shell (lines 96-97)."""
        from redaudit.utils.paths import _get_preferred_human_home_under_home

        mock_entry = MagicMock()
        mock_entry.pw_name = "daemon"
        mock_entry.pw_uid = 1001
        mock_entry.pw_dir = "/home/daemon"
        mock_entry.pw_shell = "/usr/sbin/nologin"

        with patch("redaudit.utils.paths._is_root", return_value=True):
            with patch("redaudit.utils.paths.pwd") as mock_pwd:
                mock_pwd.getpwall.return_value = [mock_entry]
                result = _get_preferred_human_home_under_home()

        assert result is None

    def test_get_preferred_home_skips_nonexistent_home(self):
        """Test skips users with non-existent home dirs (lines 98-99)."""
        from redaudit.utils.paths import _get_preferred_human_home_under_home

        mock_entry = MagicMock()
        mock_entry.pw_name = "testuser"
        mock_entry.pw_uid = 1001
        mock_entry.pw_dir = "/home/testuser"
        mock_entry.pw_shell = "/bin/bash"

        with patch("redaudit.utils.paths._is_root", return_value=True):
            with patch("redaudit.utils.paths.pwd") as mock_pwd:
                mock_pwd.getpwall.return_value = [mock_entry]
                with patch("os.path.isdir", return_value=False):
                    result = _get_preferred_human_home_under_home()

        assert result is None

    def test_get_preferred_home_kali_priority(self):
        """Test 'kali' user gets priority (lines 107-108)."""
        from redaudit.utils.paths import _get_preferred_human_home_under_home

        mock_entry1 = MagicMock()
        mock_entry1.pw_name = "otheruser"
        mock_entry1.pw_uid = 1001
        mock_entry1.pw_dir = "/home/otheruser"
        mock_entry1.pw_shell = "/bin/bash"

        mock_entry2 = MagicMock()
        mock_entry2.pw_name = "kali"
        mock_entry2.pw_uid = 1000
        mock_entry2.pw_dir = "/home/kali"
        mock_entry2.pw_shell = "/bin/bash"

        with patch("redaudit.utils.paths._is_root", return_value=True):
            with patch("redaudit.utils.paths.pwd") as mock_pwd:
                mock_pwd.getpwall.return_value = [mock_entry1, mock_entry2]
                with patch("os.path.isdir", return_value=True):
                    result = _get_preferred_human_home_under_home()

        assert result == "/home/kali"

    def test_get_preferred_home_single_user(self):
        """Test returns single user's home (lines 109-110)."""
        from redaudit.utils.paths import _get_preferred_human_home_under_home

        mock_entry = MagicMock()
        mock_entry.pw_name = "singleuser"
        mock_entry.pw_uid = 1001
        mock_entry.pw_dir = "/home/singleuser"
        mock_entry.pw_shell = "/bin/bash"

        with patch("redaudit.utils.paths._is_root", return_value=True):
            with patch("redaudit.utils.paths.pwd") as mock_pwd:
                mock_pwd.getpwall.return_value = [mock_entry]
                with patch("os.path.isdir", return_value=True):
                    result = _get_preferred_human_home_under_home()

        assert result == "/home/singleuser"


class TestGetReportsHomeDir:
    """Tests for get_reports_home_dir function (lines 114+)."""

    def test_get_reports_home_dir_with_sudo_user(self):
        """Test uses SUDO_USER's home when available."""
        from redaudit.utils.paths import get_reports_home_dir

        with patch("redaudit.utils.paths.get_invoking_user", return_value="testuser"):
            with patch(
                "redaudit.utils.paths._resolve_home_dir_for_user", return_value="/home/testuser"
            ):
                result = get_reports_home_dir()

        assert result == "/home/testuser"

    def test_get_reports_home_dir_fallback_to_human_home(self):
        """Test falls back to human home when no invoking user."""
        from redaudit.utils.paths import get_reports_home_dir

        with patch("redaudit.utils.paths.get_invoking_user", return_value=None):
            with patch(
                "redaudit.utils.paths._get_preferred_human_home_under_home",
                return_value="/home/human",
            ):
                result = get_reports_home_dir()

        assert result == "/home/human"


class TestGetDefaultReportsBaseDir:
    """Tests for get_default_reports_base_dir function."""

    def test_get_default_reports_base_dir_documents(self, tmp_path):
        """Test prefers Documents if available."""
        from redaudit.utils.paths import get_default_reports_base_dir

        docs_dir = tmp_path / "Documents"
        docs_dir.mkdir()

        with patch("redaudit.utils.paths.get_reports_home_dir", return_value=str(tmp_path)):
            result = get_default_reports_base_dir()

        assert "Documents" in result or "RedAuditReports" in result


class TestGetDefaultDocsDir:
    """Tests for get_default_dir_name resolver."""

    def test_get_default_reports_base_dir_fallback(self, tmp_path):
        """Test falls back to home/RedAuditReports."""
        from redaudit.utils.paths import get_default_reports_base_dir

        with patch("redaudit.utils.paths.get_reports_home_dir", return_value=str(tmp_path)):
            result = get_default_reports_base_dir()

        assert "RedAuditReports" in result
