#!/usr/bin/env python3
"""
RedAudit - Configuration Module Tests
Copyright (C) 2026  Dorin Badea
GPLv3 License

Tests for redaudit/utils/config.py
"""

import os
import json
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

# Import the module under test
from redaudit.utils.config import (
    validate_nvd_api_key,
    load_config,
    save_config,
    get_nvd_api_key,
    set_nvd_api_key,
    clear_nvd_api_key,
    get_persistent_defaults,
    update_persistent_defaults,
    DEFAULT_CONFIG,
    CONFIG_VERSION,
    ensure_config_dir,
    get_config_paths,
)
import redaudit.utils.config as config_module


class TestValidateNvdApiKey(unittest.TestCase):
    """Tests for validate_nvd_api_key function."""

    def test_valid_uuid_lowercase(self):
        """Valid UUID with lowercase hex."""
        key = "12345678-1234-1234-1234-123456789abc"
        self.assertTrue(validate_nvd_api_key(key))

    def test_valid_uuid_uppercase(self):
        """Valid UUID with uppercase hex."""
        key = "12345678-1234-1234-1234-123456789ABC"
        self.assertTrue(validate_nvd_api_key(key))

    def test_valid_uuid_mixed_case(self):
        """Valid UUID with mixed case."""
        key = "12345678-ABcd-1234-efEF-123456789abc"
        self.assertTrue(validate_nvd_api_key(key))

    def test_invalid_empty(self):
        """Empty string is invalid."""
        self.assertFalse(validate_nvd_api_key(""))

    def test_invalid_none(self):
        """None is invalid."""
        self.assertFalse(validate_nvd_api_key(None))

    def test_invalid_wrong_format(self):
        """Wrong format (not UUID)."""
        self.assertFalse(validate_nvd_api_key("not-a-uuid"))
        self.assertFalse(validate_nvd_api_key("12345678"))
        self.assertFalse(validate_nvd_api_key("12345678-1234-1234-1234"))

    def test_invalid_wrong_lengths(self):
        """UUID with wrong segment lengths."""
        # Missing characters
        self.assertFalse(validate_nvd_api_key("1234567-1234-1234-1234-123456789abc"))
        # Extra characters
        self.assertFalse(validate_nvd_api_key("123456789-1234-1234-1234-123456789abc"))

    def test_invalid_non_hex(self):
        """UUID with non-hex characters."""
        self.assertFalse(validate_nvd_api_key("1234567g-1234-1234-1234-123456789abc"))


class TestDefaultConfig(unittest.TestCase):
    """Tests for default configuration structure."""

    def test_default_config_has_version(self):
        """DEFAULT_CONFIG should have version key."""
        self.assertIn("version", DEFAULT_CONFIG)
        self.assertEqual(DEFAULT_CONFIG["version"], CONFIG_VERSION)

    def test_default_config_has_nvd_key(self):
        """DEFAULT_CONFIG should have nvd_api_key key."""
        self.assertIn("nvd_api_key", DEFAULT_CONFIG)
        self.assertIsNone(DEFAULT_CONFIG["nvd_api_key"])

    def test_default_config_has_storage_method(self):
        """DEFAULT_CONFIG should have nvd_api_key_storage key."""
        self.assertIn("nvd_api_key_storage", DEFAULT_CONFIG)

    def test_default_config_has_persistent_defaults(self):
        """DEFAULT_CONFIG should have defaults dict for persistent settings."""
        self.assertIn("defaults", DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG["defaults"], dict)
        for k in [
            "target_networks",
            "threads",
            "output_dir",
            "rate_limit",
            "low_impact_enrichment",
            "udp_mode",
            "udp_top_ports",
            "topology_enabled",
            "lang",
            "nuclei_enabled",
            "nuclei_max_runtime",
            "net_discovery_enabled",
            "net_discovery_redteam",
            "net_discovery_active_l2",
            "net_discovery_kerberos_userenum",
            "net_discovery_kerberos_realm",
            "net_discovery_kerberos_userlist",
            "windows_verify_enabled",
            "windows_verify_max_targets",
        ]:
            self.assertIn(k, DEFAULT_CONFIG["defaults"])


class TestEnvPriority(unittest.TestCase):
    """Tests for environment variable priority over config file."""

    @patch.dict(os.environ, {"NVD_API_KEY": "env-12345678-1234-1234-1234-123456789abc"})
    @patch("redaudit.utils.config.load_config")
    def test_env_takes_priority_over_config(self, mock_load):
        """Environment variable should take priority over config file."""
        mock_load.return_value = {"nvd_api_key": "config-key-should-not-be-used"}
        result = get_nvd_api_key()
        self.assertEqual(result, "env-12345678-1234-1234-1234-123456789abc")

    @patch.dict(os.environ, {}, clear=True)
    @patch("redaudit.utils.config.load_config")
    def test_config_used_when_no_env(self, mock_load):
        """Config file should be used when no env var."""
        # Clear NVD_API_KEY if it exists
        if "NVD_API_KEY" in os.environ:
            del os.environ["NVD_API_KEY"]
        mock_load.return_value = {"nvd_api_key": "config-key-value"}
        result = get_nvd_api_key()
        self.assertEqual(result, "config-key-value")


class TestPersistentDefaultsOutputDir(unittest.TestCase):
    def test_root_output_dir_is_rewritten_under_sudo(self):
        with (
            patch("redaudit.utils.config.load_config") as mock_load,
            patch(
                "redaudit.utils.config.get_default_reports_base_dir",
                return_value="/home/dorin/Documents/RedAuditReports",
            ),
        ):
            mock_load.return_value = {"defaults": {"output_dir": "/root/Documents/RedAuditReports"}}
            defaults = get_persistent_defaults()
            self.assertEqual(defaults.get("output_dir"), "/home/dorin/Documents/RedAuditReports")

    def test_root_output_dir_is_rewritten_without_sudo_when_preferred_home_changes(self):
        with (
            patch("redaudit.utils.config.load_config") as mock_load,
            patch("redaudit.utils.config.get_invoking_user", return_value=None),
            patch(
                "redaudit.utils.config.get_default_reports_base_dir",
                return_value="/home/kali/Documents/RedAuditReports",
            ),
        ):
            mock_load.return_value = {"defaults": {"output_dir": "/root/Documents/RedAuditReports"}}
            defaults = get_persistent_defaults()
            self.assertEqual(defaults.get("output_dir"), "/home/kali/Documents/RedAuditReports")


class TestConfigFilePermissions(unittest.TestCase):
    """Tests for config file security permissions."""

    def test_save_config_sets_permissions(self):
        """save_config should set 0o600 permissions on config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.json")

            with patch(
                "redaudit.utils.config.get_config_paths", return_value=(tmpdir, config_file)
            ):
                with patch("redaudit.utils.config.ensure_config_dir", return_value=tmpdir):
                    result = save_config({"test": "value"})

                    self.assertTrue(result)
                    self.assertTrue(os.path.exists(config_file))

                    # Check permissions
                    file_stat = os.stat(config_file)
                    mode = stat.S_IMODE(file_stat.st_mode)
                    self.assertEqual(mode, 0o600)


class TestPersistentDefaults(unittest.TestCase):
    """Tests for v3.1+ persistent defaults storage."""

    def test_get_persistent_defaults_returns_all_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.json")
            with patch(
                "redaudit.utils.config.get_config_paths", return_value=(tmpdir, config_file)
            ):
                with patch("redaudit.utils.config.ensure_config_dir", return_value=tmpdir):
                    defaults = get_persistent_defaults()

        self.assertIsInstance(defaults, dict)
        for k in DEFAULT_CONFIG["defaults"].keys():
            self.assertIn(k, defaults)

    def test_update_persistent_defaults_roundtrip_and_does_not_mutate_default(self):
        before = DEFAULT_CONFIG["defaults"].copy()
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.json")
            with patch(
                "redaudit.utils.config.get_config_paths", return_value=(tmpdir, config_file)
            ):
                with patch("redaudit.utils.config.ensure_config_dir", return_value=tmpdir):
                    ok = update_persistent_defaults(
                        threads=5,
                        output_dir="~/Reports",
                        rate_limit=1.5,
                        udp_mode="full",
                        udp_top_ports=150,
                        topology_enabled=True,
                        lang="es",
                        net_discovery_enabled=True,
                        net_discovery_redteam=True,
                        net_discovery_active_l2=False,
                        net_discovery_kerberos_userenum=True,
                        net_discovery_kerberos_realm="EXAMPLE.LOCAL",
                        net_discovery_kerberos_userlist="~/users.txt",
                        windows_verify_enabled=True,
                        windows_verify_max_targets=25,
                        bogus_key="ignored",
                    )
                    self.assertTrue(ok)

                    defaults = get_persistent_defaults()

        self.assertEqual(DEFAULT_CONFIG["defaults"], before)
        self.assertEqual(defaults["threads"], 5)
        self.assertEqual(defaults["output_dir"], "~/Reports")
        self.assertEqual(defaults["rate_limit"], 1.5)
        self.assertEqual(defaults["udp_mode"], "full")
        self.assertEqual(defaults["udp_top_ports"], 150)
        self.assertEqual(defaults["topology_enabled"], True)
        self.assertEqual(defaults["lang"], "es")
        self.assertEqual(defaults["net_discovery_enabled"], True)
        self.assertEqual(defaults["net_discovery_redteam"], True)
        self.assertEqual(defaults["net_discovery_active_l2"], False)
        self.assertEqual(defaults["net_discovery_kerberos_userenum"], True)
        self.assertEqual(defaults["net_discovery_kerberos_realm"], "EXAMPLE.LOCAL")
        self.assertEqual(defaults["net_discovery_kerberos_userlist"], "~/users.txt")
        self.assertEqual(defaults["windows_verify_enabled"], True)
        self.assertEqual(defaults["windows_verify_max_targets"], 25)
        self.assertNotIn("bogus_key", defaults)


class TestConfigEdgeCases(unittest.TestCase):
    def test_resolve_config_owner_sudo(self):
        with (
            patch("os.geteuid", return_value=0),
            patch.dict(os.environ, {"SUDO_USER": "alice"}, clear=True),
            patch.object(config_module, "pwd") as mock_pwd,
        ):
            mock_pwd.getpwnam.return_value = MagicMock(pw_uid=1000, pw_gid=1001)
            assert config_module._resolve_config_owner() == (1000, 1001)

    def test_resolve_config_owner_exception(self):
        with (
            patch("os.geteuid", return_value=0),
            patch.dict(os.environ, {"SUDO_USER": "alice"}, clear=True),
            patch.object(config_module, "pwd") as mock_pwd,
        ):
            mock_pwd.getpwnam.side_effect = RuntimeError("boom")
            assert config_module._resolve_config_owner() is None

    def test_get_config_paths_fallback_on_exception(self):
        calls = {"count": 0}

        def _expanduser(path):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("boom")
            return "/tmp/home"

        with patch("os.path.expanduser", side_effect=_expanduser):
            config_dir, config_file = config_module.get_config_paths()
        assert config_dir == "/tmp/home/.redaudit"
        assert config_file == "/tmp/home/.redaudit/config.json"

    def test_maybe_chown_handles_error(self):
        with (
            patch.object(config_module, "_resolve_config_owner", return_value=(1, 2)),
            patch("os.chown", side_effect=OSError("nope")),
        ):
            config_module._maybe_chown("/tmp/path")

    def test_ensure_config_dir_creates_and_chmods(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.json")
            with (
                patch("redaudit.utils.config.get_config_paths", return_value=(tmpdir, config_file)),
                patch("os.path.isdir", return_value=False),
                patch("os.makedirs") as mock_makedirs,
                patch("os.chmod", side_effect=OSError("nope")),
                patch.object(config_module, "_maybe_chown") as mock_chown,
            ):
                result = ensure_config_dir()
        assert result == tmpdir
        mock_makedirs.assert_called_once()
        mock_chown.assert_called_once()

    def test_load_config_decode_error_returns_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.json")
            with (
                patch("redaudit.utils.config.get_config_paths", return_value=(tmpdir, config_file)),
                patch("os.path.isfile", return_value=True),
                patch("json.load", side_effect=json.JSONDecodeError("bad", "doc", 1)),
                patch("builtins.open", MagicMock()),
            ):
                config = load_config()
        assert config == DEFAULT_CONFIG

    def test_save_config_raises_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "config.json")
            with (
                patch("redaudit.utils.config.get_config_paths", return_value=(tmpdir, config_file)),
                patch("redaudit.utils.config.ensure_config_dir", return_value=tmpdir),
                patch("os.replace", side_effect=OSError("nope")),
            ):
                assert save_config({"nvd_api_key": "x"}) is False

    def test_set_and_clear_nvd_api_key(self):
        with patch("redaudit.utils.config.load_config", return_value={}):
            with patch("redaudit.utils.config.save_config", return_value=True) as mock_save:
                assert set_nvd_api_key(" abc ") is True
                saved = mock_save.call_args[0][0]
                assert saved["nvd_api_key"] == "abc"
                assert saved["nvd_api_key_storage"] == "config"

        with patch("redaudit.utils.config.load_config", return_value={"nvd_api_key": "x"}):
            with patch("redaudit.utils.config.save_config", return_value=True) as mock_save:
                assert clear_nvd_api_key() is True
                saved = mock_save.call_args[0][0]
                assert saved["nvd_api_key"] is None
                assert saved["nvd_api_key_storage"] is None

    def test_get_persistent_defaults_root_rewrite_with_invoking_user(self):
        with (
            patch(
                "redaudit.utils.config.load_config",
                return_value={"defaults": {"output_dir": "/root"}},
            ),
            patch("redaudit.utils.config.get_invoking_user", return_value="user"),
            patch(
                "redaudit.utils.config.get_default_reports_base_dir",
                return_value="/home/user/Documents/RedAuditReports",
            ),
        ):
            defaults = get_persistent_defaults()
        assert defaults["output_dir"] == "/home/user/Documents/RedAuditReports"


class TestSudoConfigPaths(unittest.TestCase):
    """Tests for sudo-aware config path resolution."""

    @patch.dict(os.environ, {"SUDO_USER": "alice"})
    @patch("redaudit.utils.config.os.geteuid", return_value=0)
    def test_get_config_paths_prefers_sudo_user_home(self, _mock_geteuid):
        def fake_expanduser(path):
            if path == "~alice":
                return "/home/alice"
            if path == "~":
                return "/root"
            return path

        with patch("redaudit.utils.config.os.path.expanduser", side_effect=fake_expanduser):
            config_dir, config_file = get_config_paths()

        self.assertEqual(config_dir, "/home/alice/.redaudit")
        self.assertEqual(config_file, "/home/alice/.redaudit/config.json")


if __name__ == "__main__":
    unittest.main()
