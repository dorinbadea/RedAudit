import unittest
from unittest.mock import MagicMock, patch, call
import os
import sys
from redaudit.core.updater import (
    perform_git_update,
    _maybe_sync_local_repo,
    _get_update_check_cache_path,
    _read_update_check_cache,
    _write_update_check_cache,
    auto_check_updates_on_startup,
)
import json


class TestCacheHelpers(unittest.TestCase):
    def test_get_update_check_cache_path_exception(self):
        # 208-210
        logger = MagicMock()
        with patch("redaudit.core.updater.os.path.join", side_effect=Exception("Path error")):
            path = _get_update_check_cache_path(logger)
            self.assertTrue(path.endswith(".redaudit/update_check_cache.json"))
            logger.debug.assert_called()

    def test_read_update_check_cache_exceptions(self):
        # 217-218: Not a file
        with patch("os.path.isfile", return_value=False):
            self.assertIsNone(_read_update_check_cache())

        # 222-224: JSON error or other exception
        logger = MagicMock()
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=Exception("Read error")),
        ):
            self.assertIsNone(_read_update_check_cache(logger))
            logger.debug.assert_called()

    def test_write_update_check_cache_exceptions(self):
        # 236-239: chmod exception
        # 240-242: main exception (e.g. makedirs)
        # 243-247: cleanup exception
        logger = MagicMock()

        # chmod exception
        with (
            patch("redaudit.core.updater._get_update_check_cache_path", return_value="/tmp/cache"),
            patch("os.makedirs"),
            patch("builtins.open", unittest.mock.mock_open()),
            patch("os.replace"),
            patch("os.chmod", side_effect=Exception("Chmod fail")),
        ):
            _write_update_check_cache({"a": 1}, logger)
            # Should pass silently

        # Write exception and cleanup exception
        with (
            patch("redaudit.core.updater._get_update_check_cache_path", return_value="/tmp/cache"),
            patch("os.makedirs", side_effect=Exception("Mkdirs fail")),
            patch("os.path.exists", return_value=True),
            patch("os.remove", side_effect=Exception("Remove fail")),
        ):
            _write_update_check_cache({"a": 1}, logger)
            logger.debug.assert_called()

    def test_auto_check_updates_checked_at_parsing_error(self):
        # 295-296
        with patch(
            "redaudit.core.updater._read_update_check_cache", return_value={"checked_at": "invalid"}
        ):
            # Should not raise
            auto_check_updates_on_startup(logger=MagicMock())


class TestUpdaterFinalCoverage(unittest.TestCase):
    def setUp(self):
        self.mock_logger = MagicMock()
        self.mock_print = MagicMock()
        self.mock_t = MagicMock(return_value="t_msg")

    def test_maybe_sync_local_repo_scenarios(self):
        # 1514: cwd_path broken
        _maybe_sync_local_repo(
            cwd_path=None,
            home_redaudit_path="/home",
            target_ref="main",
            runner=MagicMock(),
            print_fn=MagicMock(),
            t_fn=MagicMock(),
        )

        # 1519: cwd == home
        with patch("os.path.realpath", side_effect=lambda x: x):
            _maybe_sync_local_repo(
                cwd_path="/home/repo",
                home_redaudit_path="/home/repo",
                target_ref="main",
                runner=MagicMock(),
                print_fn=MagicMock(),
                t_fn=MagicMock(),
            )

        # 1554: status check exception
        runner = MagicMock()
        runner.check_output.side_effect = [
            "https://github.com/dorinbadea/RedAudit",  # origin
            Exception("Status check fail"),
        ]
        logger = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("os.path.realpath", side_effect=lambda x: x),
        ):
            _maybe_sync_local_repo(
                cwd_path="/cwd",
                home_redaudit_path="/home",
                target_ref="main",
                runner=runner,
                print_fn=MagicMock(),
                t_fn=MagicMock(),
                logger=logger,
            )
            logger.debug.assert_called_with("Repo sync skipped (status check failed): %s", "/cwd")

        # 1567: fetch failed (Warning)
        runner.reset_mock()
        runner.check_output.side_effect = [
            "https://github.com/dorinbadea/RedAudit",  # origin
            "",  # status clean
            Exception("Fetch failed"),
        ]
        print_fn = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("os.path.realpath", side_effect=lambda x: x),
        ):
            _maybe_sync_local_repo(
                cwd_path="/cwd",
                home_redaudit_path="/home",
                target_ref="main",
                runner=runner,
                print_fn=print_fn,
                t_fn=self.mock_t,
                logger=logger,
            )
            print_fn.assert_called_with("t_msg", "WARNING")

        # 1580, 1593: rev-parse fail, pull fail
        runner.reset_mock()
        # Origin, Status, Fetch, RevParse(fail) -> branch=""
        runner.check_output.side_effect = [
            "https://github.com/dorinbadea/RedAudit",
            "",
            "",
            Exception("RevParse failed"),
        ]
        with (
            patch("os.path.isdir", return_value=True),
            patch("os.path.realpath", side_effect=lambda x: x),
        ):
            _maybe_sync_local_repo(
                cwd_path="/cwd",
                home_redaudit_path="/home",
                target_ref="main",
                runner=runner,
                print_fn=print_fn,
                t_fn=self.mock_t,
                logger=logger,
            )

        # Main pull fail
        runner.reset_mock()
        runner.check_output.side_effect = [
            "https://github.com/dorinbadea/RedAudit",
            "",
            "",
            "main",  # branch
            Exception("Pull failed"),
        ]
        with (
            patch("os.path.isdir", return_value=True),
            patch("os.path.realpath", side_effect=lambda x: x),
        ):
            _maybe_sync_local_repo(
                cwd_path="/cwd",
                home_redaudit_path="/home",
                target_ref="main",
                runner=runner,
                print_fn=print_fn,
                t_fn=self.mock_t,
                logger=logger,
            )
            # print_fn called with WARNING
            print_fn.assert_called_with("t_msg", "WARNING")


if __name__ == "__main__":
    unittest.main()
