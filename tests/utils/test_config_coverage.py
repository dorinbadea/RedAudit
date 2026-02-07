import os
import json
import stat
import unittest
from unittest.mock import patch, MagicMock
from redaudit.utils import config


class TestConfigCoverageSupplemental(unittest.TestCase):
    def setUp(self):
        # Reset ENV
        if "SUDO_USER" in os.environ:
            del os.environ["SUDO_USER"]

    @patch("os.geteuid", return_value=0)
    @patch("os.environ.get")
    def test_get_config_paths_root_no_sudo_user(self, mock_env_get, mock_geteuid):
        """Line 123: SUDO_USER is None while running as root."""
        mock_env_get.side_effect = lambda k: None if k == "SUDO_USER" else "dummy"
        config_dir, _ = config.get_config_paths()
        self.assertIn(os.path.expanduser("~"), config_dir)

    @patch("redaudit.utils.config._backup_invalid_config")
    @patch("redaudit.utils.config.save_config", return_value=False)
    def test_recover_default_config_save_fail(self, mock_save, mock_backup):
        """Line 206: backup_file is None in _recover_default_config."""
        mock_backup.return_value = None
        # This triggers the else at line 208/212 logic in _recover_default_config
        res = config._recover_default_config("dummy_path", "test-reason")
        self.assertEqual(res, config.DEFAULT_CONFIG)

    @patch("redaudit.utils.config._backup_invalid_config", return_value="/tmp/backup")
    @patch("redaudit.utils.config.save_config", return_value=True)
    def test_recover_default_config_backup_warning(self, mock_save, mock_backup):
        """Exercise line 200+ warning."""
        res = config._recover_default_config("dummy_path", "test-reason")
        self.assertEqual(res, config.DEFAULT_CONFIG)

    @patch("redaudit.utils.config.ensure_config_dir")
    @patch("redaudit.utils.config.get_config_paths")
    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open")
    @patch("json.load")
    def test_load_config_invalid_root_type(
        self, mock_json_load, mock_open, mock_isfile, mock_paths, mock_ensure
    ):
        """Line 233: config is not a dict."""
        mock_paths.return_value = ("/tmp", "/tmp/config.json")
        mock_json_load.return_value = ["not", "a", "dict"]

        with patch("redaudit.utils.config._recover_default_config") as mock_recover:
            mock_recover.return_value = {"recovered": True}
            res = config.load_config()
            self.assertTrue(res["recovered"])
            mock_recover.assert_called_once()

    @patch("redaudit.utils.config.ensure_config_dir")
    @patch("redaudit.utils.config.get_config_paths")
    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", side_effect=IOError("Permission denied"))
    def test_load_config_io_error(self, mock_open, mock_isfile, mock_paths, mock_ensure):
        """Lines 248-250: IOError during load_config."""
        mock_paths.return_value = ("/tmp", "/tmp/config.json")
        res = config.load_config()
        self.assertEqual(res, config.DEFAULT_CONFIG)

    @patch("redaudit.utils.config.load_config")
    def test_get_nvd_api_key_none(self, mock_load):
        """Line 311: No key in env or file."""
        mock_load.return_value = {}
        with patch.dict(os.environ, {}, clear=True):
            res = config.get_nvd_api_key()
            self.assertIsNone(res)

    @patch("redaudit.utils.config.get_nvd_api_key", return_value=None)
    def test_is_nvd_api_key_configured_false(self, mock_get):
        """Line 351: Key not configured."""
        self.assertFalse(config.is_nvd_api_key_configured())

    @patch("redaudit.utils.config.load_config")
    @patch("redaudit.utils.config.get_config_paths")
    @patch("os.path.isfile")
    def test_get_config_summary_miss(self, mock_isfile, mock_paths, mock_load):
        """Lines 393-399: get_config_summary logic."""
        mock_load.return_value = {"nvd_api_key": "test-key"}
        mock_paths.return_value = ("/tmp", "/tmp/config.json")
        mock_isfile.return_value = True

        with patch.dict(os.environ, {"NVD_API_KEY": "env-key"}):
            summary = config.get_config_summary()
            self.assertEqual(summary["nvd_key_source"], "env")

        with patch.dict(os.environ, {}, clear=True):
            summary = config.get_config_summary()
            self.assertEqual(summary["nvd_key_source"], "config")

    @patch("os.replace")
    @patch("os.chmod", side_effect=Exception("chmod fail"))
    def test_backup_invalid_config_chmod_fail(self, mock_chmod, mock_replace):
        """Lines 179-181: chmod fails during backup."""
        # This exercises the catch block
        res = config._backup_invalid_config("/tmp/bogus.json")
        self.assertIsNotNone(res)

    @patch("os.replace", side_effect=Exception("replace fail"))
    def test_backup_invalid_config_replace_fail(self, mock_replace):
        """Lines 184-186: replace fails during backup."""
        res = config._backup_invalid_config("/tmp/bogus.json")
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
