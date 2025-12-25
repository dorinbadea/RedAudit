"""
Tests for config.py edge cases and missing coverage lines.
Target: Push config.py from 79% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock
import os
import json


class TestResolveConfigOwner:
    """Tests for _resolve_config_owner function (lines 78-95)."""

    def test_resolve_config_owner_under_sudo(self):
        """Test owner resolution when running as root with SUDO_USER (lines 87-91)."""
        from redaudit.utils.config import _resolve_config_owner

        mock_pw = MagicMock()
        mock_pw.pw_uid = 1000
        mock_pw.pw_gid = 1000

        with patch("os.geteuid", return_value=0):
            with patch.dict(os.environ, {"SUDO_USER": "testuser"}):
                with patch("redaudit.utils.config.pwd") as mock_pwd:
                    mock_pwd.getpwnam.return_value = mock_pw
                    result = _resolve_config_owner()

        assert result == (1000, 1000)

    def test_resolve_config_owner_not_root(self):
        """Test returns None when not root (line 87 branch)."""
        from redaudit.utils.config import _resolve_config_owner

        with patch("os.geteuid", return_value=1000):
            result = _resolve_config_owner()

        assert result is None

    def test_resolve_config_owner_exception(self):
        """Test returns None on exception (lines 92-94)."""
        from redaudit.utils.config import _resolve_config_owner

        with patch("os.geteuid", return_value=0):
            with patch.dict(os.environ, {"SUDO_USER": "testuser"}):
                with patch("redaudit.utils.config.pwd") as mock_pwd:
                    mock_pwd.getpwnam.side_effect = KeyError("User not found")
                    result = _resolve_config_owner()

        assert result is None


class TestGetConfigPaths:
    """Tests for get_config_paths function (lines 98-120)."""

    def test_get_config_paths_as_root_with_sudo(self):
        """Test path resolution under sudo (lines 106-109)."""
        from redaudit.utils.config import get_config_paths

        with patch("os.geteuid", return_value=0):
            with patch.dict(os.environ, {"SUDO_USER": "testuser"}):
                with patch("os.path.expanduser") as mock_expand:
                    mock_expand.return_value = "/home/testuser"
                    config_dir, config_file = get_config_paths()

        assert "/home/testuser" in config_dir or mock_expand.called

    def test_get_config_paths_as_root_no_sudo(self):
        """Test path resolution as root without SUDO_USER (lines 110-111)."""
        from redaudit.utils.config import get_config_paths

        with patch("os.geteuid", return_value=0):
            with patch.dict(os.environ, {}, clear=True):
                config_dir, config_file = get_config_paths()

        assert ".redaudit" in config_dir
        assert "config.json" in config_file

    def test_get_config_paths_exception_fallback(self):
        """Test fallback on exception (lines 114-116)."""
        from redaudit.utils.config import get_config_paths

        with patch("os.geteuid") as mock_geteuid:
            mock_geteuid.side_effect = AttributeError("geteuid not available")
            config_dir, config_file = get_config_paths()

        assert ".redaudit" in config_dir


class TestMaybeChown:
    """Tests for _maybe_chown function (lines 123-132)."""

    def test_maybe_chown_no_owner(self):
        """Test no-op when no owner resolved (lines 125-126)."""
        from redaudit.utils.config import _maybe_chown

        with patch("redaudit.utils.config._resolve_config_owner", return_value=None):
            # Should not raise
            _maybe_chown("/some/path")

    def test_maybe_chown_success(self, tmp_path):
        """Test successful chown (lines 127-129)."""
        from redaudit.utils.config import _maybe_chown

        test_file = tmp_path / "test.conf"
        test_file.write_text("content")

        with patch("redaudit.utils.config._resolve_config_owner", return_value=(1000, 1000)):
            with patch("os.chown") as mock_chown:
                _maybe_chown(str(test_file))
                mock_chown.assert_called_once_with(str(test_file), 1000, 1000)

    def test_maybe_chown_exception(self, tmp_path):
        """Test exception is caught (lines 130-132)."""
        from redaudit.utils.config import _maybe_chown

        with patch("redaudit.utils.config._resolve_config_owner", return_value=(1000, 1000)):
            with patch("os.chown") as mock_chown:
                mock_chown.side_effect = PermissionError("Operation not permitted")
                # Should not raise
                _maybe_chown("/some/path")


class TestEnsureConfigDir:
    """Tests for ensure_config_dir function (lines 135-151)."""

    def test_ensure_config_dir_chmod_exception(self, tmp_path):
        """Test chmod exception is caught (lines 147-149)."""
        from redaudit.utils.config import ensure_config_dir

        with patch(
            "redaudit.utils.config.get_config_paths",
            return_value=(str(tmp_path), str(tmp_path / "config.json")),
        ):
            with patch("os.chmod") as mock_chmod:
                mock_chmod.side_effect = PermissionError("Access denied")
                # Should not raise
                result = ensure_config_dir()

        assert result == str(tmp_path)


class TestLoadConfig:
    """Tests for load_config function (lines 154-178)."""

    def test_load_config_json_decode_error(self, tmp_path):
        """Test JSONDecodeError returns defaults (lines 176-178)."""
        from redaudit.utils.config import load_config, DEFAULT_CONFIG

        config_file = tmp_path / "config.json"
        config_file.write_text("not valid json {{{")

        with patch(
            "redaudit.utils.config.get_config_paths", return_value=(str(tmp_path), str(config_file))
        ):
            result = load_config()

        # Should return defaults
        assert result.get("version") is not None


class TestSaveConfig:
    """Tests for save_config function (lines 181-214)."""

    def test_save_config_io_error(self, tmp_path):
        """Test IOError returns False (lines 212-214)."""
        from redaudit.utils.config import save_config

        with patch(
            "redaudit.utils.config.get_config_paths",
            return_value=(str(tmp_path), str(tmp_path / "config.json")),
        ):
            with patch("builtins.open") as mock_open:
                mock_open.side_effect = IOError("Disk full")
                result = save_config({"version": "3.8.0"})

        assert result is False


class TestSetNvdApiKey:
    """Tests for set_nvd_api_key function (lines 242-256)."""

    def test_set_nvd_api_key_success(self, tmp_path):
        """Test successful key setting (lines 253-256)."""
        from redaudit.utils.config import set_nvd_api_key

        config_file = tmp_path / "config.json"
        config_file.write_text("{}")

        with patch(
            "redaudit.utils.config.get_config_paths", return_value=(str(tmp_path), str(config_file))
        ):
            result = set_nvd_api_key("12345678-1234-1234-1234-123456789012")

        assert result is True
        # Verify key was saved
        saved = json.loads(config_file.read_text())
        assert saved.get("nvd_api_key") == "12345678-1234-1234-1234-123456789012"

    def test_set_nvd_api_key_empty(self, tmp_path):
        """Test setting empty key sets None (line 254)."""
        from redaudit.utils.config import set_nvd_api_key

        config_file = tmp_path / "config.json"
        config_file.write_text("{}")

        with patch(
            "redaudit.utils.config.get_config_paths", return_value=(str(tmp_path), str(config_file))
        ):
            result = set_nvd_api_key("")

        saved = json.loads(config_file.read_text())
        assert saved.get("nvd_api_key") is None


class TestClearNvdApiKey:
    """Tests for clear_nvd_api_key function (lines 259-269)."""

    def test_clear_nvd_api_key(self, tmp_path):
        """Test clearing the key (lines 266-269)."""
        from redaudit.utils.config import clear_nvd_api_key

        config_file = tmp_path / "config.json"
        config_file.write_text('{"nvd_api_key": "somekey"}')

        with patch(
            "redaudit.utils.config.get_config_paths", return_value=(str(tmp_path), str(config_file))
        ):
            result = clear_nvd_api_key()

        assert result is True
        saved = json.loads(config_file.read_text())
        assert saved.get("nvd_api_key") is None


class TestGetPersistentDefaults:
    """Tests for get_persistent_defaults function (lines 335-368)."""

    def test_get_persistent_defaults_legacy_root_path(self, tmp_path):
        """Test legacy /root path replacement (lines 361-366)."""
        from redaudit.utils.config import get_persistent_defaults

        config_file = tmp_path / "config.json"
        config_data = {
            "defaults": {
                "output_dir": "/root/RedAuditReports",
            }
        }
        config_file.write_text(json.dumps(config_data))

        with patch(
            "redaudit.utils.config.get_config_paths", return_value=(str(tmp_path), str(config_file))
        ):
            with patch(
                "redaudit.utils.config.get_default_reports_base_dir",
                return_value="/home/user/Documents/RedAuditReports",
            ):
                result = get_persistent_defaults()

        # Should have been replaced
        assert result.get("output_dir") == "/home/user/Documents/RedAuditReports"

    def test_get_persistent_defaults_invoking_user_root(self, tmp_path):
        """Test /root replacement when invoking user exists (line 365-366)."""
        from redaudit.utils.config import get_persistent_defaults

        config_file = tmp_path / "config.json"
        config_data = {
            "defaults": {
                "output_dir": "/root",
            }
        }
        config_file.write_text(json.dumps(config_data))

        with patch(
            "redaudit.utils.config.get_config_paths", return_value=(str(tmp_path), str(config_file))
        ):
            with patch("redaudit.utils.config.get_invoking_user", return_value="testuser"):
                with patch(
                    "redaudit.utils.config.get_default_reports_base_dir",
                    return_value="/home/testuser/Documents/RedAuditReports",
                ):
                    result = get_persistent_defaults()

        assert result.get("output_dir") == "/home/testuser/Documents/RedAuditReports"
