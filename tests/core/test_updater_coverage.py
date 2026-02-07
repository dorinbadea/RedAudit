#!/usr/bin/env python3
"""
Supplemental tests for redaudit.core.updater to improve coverage.
Focuses on low-level file operations, complex git flows, and error handling.
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import time
from unittest.mock import patch, MagicMock, mock_open

from redaudit.core.updater import (
    _iter_files,
    compute_tree_diff,
    _inject_default_lang,
    _ensure_version_file,
    _read_update_check_cache,
    _write_update_check_cache,
    auto_check_updates_on_startup,
    _maybe_sync_local_repo,
    perform_git_update,
    restart_self,
)


class TestUpdaterCoverage(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_iter_files_excludes_cache(self):
        # Create structure
        # root/
        #   __pycache__/bad.pyc
        #   src/
        #     good.py
        #     bad.pyc
        #     bad.pyo
        os.makedirs(os.path.join(self.tmp_dir, "__pycache__"))
        with open(os.path.join(self.tmp_dir, "__pycache__", "bad.pyc"), "w") as f:
            f.write("x")

        os.makedirs(os.path.join(self.tmp_dir, "src"))
        with open(os.path.join(self.tmp_dir, "src", "good.py"), "w") as f:
            f.write("x")
        with open(os.path.join(self.tmp_dir, "src", "bad.pyc"), "w") as f:
            f.write("x")
        with open(os.path.join(self.tmp_dir, "src", "bad.pyo"), "w") as f:
            f.write("x")

        files = _iter_files(self.tmp_dir)
        self.assertEqual(files, ["src/good.py"])

    def test_compute_tree_diff_complex(self):
        dir_a = os.path.join(self.tmp_dir, "a")
        dir_b = os.path.join(self.tmp_dir, "b")
        os.makedirs(dir_a)
        os.makedirs(dir_b)

        # 1. Added file
        with open(os.path.join(dir_b, "added.txt"), "w") as f:
            f.write("new")

        # 2. Removed file
        with open(os.path.join(dir_a, "removed.txt"), "w") as f:
            f.write("old")

        # 3. Modified content (same size, different hash)
        # Using bytes to ensure same size but different content easily
        with open(os.path.join(dir_a, "mod_hash.txt"), "wb") as f:
            f.write(b"123")
        with open(os.path.join(dir_b, "mod_hash.txt"), "wb") as f:
            f.write(b"321")

        # 4. Modified size
        with open(os.path.join(dir_a, "mod_size.txt"), "w") as f:
            f.write("sooooort")
        with open(os.path.join(dir_b, "mod_size.txt"), "w") as f:
            f.write("looooooong")

        # 5. Unchanged
        with open(os.path.join(dir_a, "same.txt"), "w") as f:
            f.write("same")
        with open(os.path.join(dir_b, "same.txt"), "w") as f:
            f.write("same")

        # 6. Error during hash computation (simulated)
        with open(os.path.join(dir_a, "error.txt"), "w") as f:
            f.write("x")
        with open(os.path.join(dir_b, "error.txt"), "w") as f:
            f.write("x")

        # Mock compute_file_hash to raise error for "error.txt" only in dir_a
        original_hash = compute_tree_diff.__globals__.get("compute_file_hash", None)  # type: ignore

        # We can mock os.path.getsize to force equality then fail hash
        diff = compute_tree_diff(dir_a, dir_b)

        self.assertIn("added.txt", diff["added"])
        self.assertIn("removed.txt", diff["removed"])
        self.assertIn("mod_hash.txt", diff["modified"])
        self.assertIn("mod_size.txt", diff["modified"])
        self.assertNotIn("same.txt", diff["modified"])

        # Test exception path:
        # We patch os.path.getsize to return equal for error.txt
        # and compute_file_hash to raise exception
        with patch("redaudit.core.updater.compute_file_hash", side_effect=Exception("Boom")):
            diff_err = compute_tree_diff(dir_a, dir_b)
            # If hash fails, we assume modified
            self.assertIn("same.txt", diff_err["modified"])

    def test_cache_operations_failure(self):
        # Read with permission error
        with patch("builtins.open", side_effect=PermissionError("denied")):
            self.assertIsNone(_read_update_check_cache())

        # Write with mkdir error
        with patch("os.makedirs", side_effect=OSError("fail")):
            _write_update_check_cache({"test": 1})
            # Should catch exception and log debug if logger provided

        # Write clean up failure
        # Simulate successful open/dump, but then error in replace/chmod
        # And error in remove cleanup
        with (
            patch("json.dump"),
            patch("os.replace", side_effect=OSError("fail")),
            patch("os.path.exists", return_value=True),
            patch("os.remove", side_effect=OSError("fail cleanup")),
        ):
            _write_update_check_cache({"test": 1})
            # Should not crash

    def test_auto_check_updates_startup_complex(self):
        # 1. Valid cache, fresh
        now = time.time()
        with (
            patch("redaudit.core.updater._read_update_check_cache") as mock_read,
            patch("redaudit.core.updater.fetch_latest_version") as mock_fetch,
        ):
            mock_read.return_value = {
                "checked_at": now,
                "latest_version": "9.9.9",
                "release_url": "http://url",
            }
            # Mock print to verify output
            mock_print = MagicMock()
            # Pass cache_ttl to ensure cache is considered fresh
            res = auto_check_updates_on_startup(print_fn=mock_print, cache_ttl_seconds=3600)
            self.assertTrue(res["update_available"])
            self.assertEqual(res["source"], "cache")
            mock_print.assert_called()
            mock_fetch.assert_not_called()

        # 2. Stale cache, network fail, cache fallback
        # return_value=-1 means update available
        # We must re-patch _read_update_check_cache and fetch_latest_version
        with (
            patch("redaudit.core.updater._read_update_check_cache") as mock_read,
            patch("redaudit.core.updater.fetch_latest_version", return_value=None),
            patch("redaudit.core.updater.compare_versions", return_value=-1),
        ):

            mock_read.return_value = {
                "checked_at": 0,  # Stale
                "latest_version": "9.9.9",
                "release_url": "http://url",
            }
            res = auto_check_updates_on_startup()
            self.assertTrue(res["update_available"])
            self.assertEqual(res["source"], "cache_fallback")

    def test_inject_default_lang(self):
        f = os.path.join(self.tmp_dir, "constants.py")

        # 1. Create file with existing lang
        with open(f, "w") as f_obj:
            f_obj.write('DEFAULT_LANG = "en"\n')

        # Change to es
        changed = _inject_default_lang(f, "es")
        self.assertTrue(changed)
        with open(f, "r") as f_obj:
            self.assertIn('DEFAULT_LANG = "es"', f_obj.read())

        # 2. Invalid lang -> fallback en
        _inject_default_lang(f, "fr")
        with open(f, "r") as f_obj:
            self.assertIn('DEFAULT_LANG = "en"', f_obj.read())

        # 3. File missing
        self.assertFalse(_inject_default_lang("missing.py", "en"))

        # 4. Append if missing
        with open(f, "w") as f_obj:
            f_obj.write("FOO=1\n")
        _inject_default_lang(f, "es")
        with open(f, "r") as f_obj:
            content = f_obj.read()
            self.assertIn('DEFAULT_LANG = "es"', content)

    def test_ensure_version_file_paths(self):
        vtag = "3.1.0"

        # 1. Create new
        self.assertTrue(_ensure_version_file(self.tmp_dir, vtag))
        vpath = os.path.join(self.tmp_dir, "VERSION")
        with open(vpath, "r") as f:
            self.assertEqual(f.read().strip(), vtag)

        # 2. Mismatch
        with open(vpath, "w") as f:
            f.write("0.0.0")
        mock_print = MagicMock()
        self.assertTrue(_ensure_version_file(self.tmp_dir, vtag, print_fn=mock_print))
        with open(vpath, "r") as f:
            self.assertEqual(f.read().strip(), vtag)
        mock_print.assert_called()

        # 3. Permission error
        # We patch write_text which is called when mismatch occurs.
        # We also need to ensure read_text works or is bypassed to reach write.
        with (
            patch("pathlib.Path.read_text", return_value="0.0.0"),
            patch("pathlib.Path.write_text", side_effect=PermissionError("denied")),
        ):
            with patch("builtins.print") as mock_print:
                self.assertFalse(_ensure_version_file(self.tmp_dir, vtag, print_fn=mock_print))

    @patch("redaudit.core.updater.CommandRunner")
    def test_maybe_sync_local_repo_scenarios(self, MockRunner):
        runner = MockRunner.return_value
        print_fn = MagicMock()
        t_fn = lambda k, *a: k

        cwd = self.tmp_dir
        home = os.path.join(tempfile.gettempdir(), "other")

        # 1. No git dir
        _maybe_sync_local_repo(
            cwd_path=cwd,
            home_redaudit_path=home,
            target_ref="v1",
            runner=runner,
            print_fn=print_fn,
            t_fn=t_fn,
        )
        runner.check_output.assert_not_called()

        # 2. Git origin mismatch
        os.makedirs(os.path.join(cwd, ".git"))
        runner.check_output.side_effect = ["https://github.com/other/repo.git"]
        _maybe_sync_local_repo(
            cwd_path=cwd,
            home_redaudit_path=home,
            target_ref="v1",
            runner=runner,
            print_fn=print_fn,
            t_fn=t_fn,
        )
        # Should stop after origin check
        self.assertEqual(runner.check_output.call_count, 1)

        # 3. Dirty status
        runner.check_output.side_effect = None
        # origin_url, status
        runner.check_output.side_effect = [
            "https://github.com/dorinbadea/RedAudit.git",
            "M modified.py",
        ]
        _maybe_sync_local_repo(
            cwd_path=cwd,
            home_redaudit_path=home,
            target_ref="v1",
            runner=runner,
            print_fn=print_fn,
            t_fn=t_fn,
        )
        print_fn.assert_called_with("update_repo_sync_skip_dirty", "WARNING")

        # 4. Fetch failure
        runner.check_output.side_effect = [
            "https://github.com/dorinbadea/RedAudit.git",
            "",  # clean status
            Exception("fetch fail"),
        ]
        _maybe_sync_local_repo(
            cwd_path=cwd,
            home_redaudit_path=home,
            target_ref="v1",
            runner=runner,
            print_fn=print_fn,
            t_fn=t_fn,
        )
        print_fn.assert_called_with("update_repo_sync_fetch_failed", "WARNING")

    def test_restart_self_fallback(self):
        # 1. Argv empty (should not happen usually)
        with patch("sys.argv", []):
            self.assertFalse(restart_self())

        # 2. Execvp fail, execv fail
        with (
            patch("sys.argv", ["script.py"]),
            patch("os.execvp", side_effect=OSError("fail")),
            patch("shutil.which", return_value=None),
            patch("os.path.isfile", return_value=True),
            patch("os.execv", side_effect=OSError("fail2")),
        ):
            self.assertFalse(restart_self())

    # We patch the modules where they are used. If they are imported as modules in updater.py
    # we should patch them there. If updater.py uses 'import shutil', then 'redaudit.core.updater.shutil' should work.
    # However, if it's not working, let's patch the global modules which is safer for standard libs.
    @patch("redaudit.core.updater.CommandRunner")
    @patch("redaudit.core.updater.subprocess.Popen")
    @patch("redaudit.core.updater._ensure_version_file")
    @patch("redaudit.core.updater._inject_default_lang")
    @patch("redaudit.core.updater.compute_tree_diff")
    @patch("tempfile.mkdtemp")
    @patch("shutil.rmtree")
    @patch("shutil.copytree")
    @patch("os.makedirs")
    @patch("os.rename")
    @patch("os.chmod")
    @patch("os.path.exists")
    @patch("os.path.isdir")
    @patch("os.geteuid")
    def test_perform_git_update_full_mock(
        self,
        mock_geteuid,
        mock_isdir,
        mock_exists,
        mock_chmod,
        mock_rename,
        mock_makedirs,
        mock_copytree,
        mock_rmtree,
        mock_mkdtemp,
        mock_compute_diff,
        mock_inject_lang,
        mock_ensure_version,
        mock_popen,
        MockRunner,
    ):
        runner = MockRunner.return_value
        print_fn = MagicMock()
        logger = MagicMock()
        t_fn = lambda k, *a: k

        mock_mkdtemp.return_value = "/tmp/mock_clone"
        mock_geteuid.return_value = 0  # Simulate root
        mock_exists.return_value = True
        mock_isdir.return_value = True
        mock_copytree.return_value = None
        mock_rename.return_value = None
        mock_chmod.return_value = None
        mock_compute_diff.return_value = {"modified": [], "added": [], "removed": []}

        # Setup Popen mock for git clone
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.stdout.readline.side_effect = [
            "Cloning into 'RedAudit'...\n",
            "",
        ]  # Simulate output then EOF (strings for text=True)
        mock_process.poll.return_value = 0
        mock_process.returncode = 0
        mock_process.wait.return_value = 0  # wait() return code

        # Setup Runner mock for install script
        # CommandRunner.run returns an object with .returncode
        mock_run_result = MagicMock()
        mock_run_result.returncode = 0
        runner.run.return_value = mock_run_result

        # We also need to mock check_output for verification step (rev-parse HEAD)
        runner.check_output.return_value = "commit_hash"

        # And we need to ensure expected_commit matches cloned_commit
        # expected_commit comes from ls-remote check_output call earlier in the function
        # Sequence of check_output calls:
        # 1. git ls-remote ... (to get expected commit)
        # 2. git rev-parse HEAD (verification)
        runner.check_output.side_effect = ["commit_hash", "commit_hash"]

        # Scenario 1: Success flow
        with patch("os.path.isfile", return_value=True):
            result = perform_git_update(
                "/path/to/repo", print_fn=print_fn, logger=logger, t_fn=t_fn
            )

        self.assertEqual(result, (True, "UPDATE_SUCCESS_RESTART"))

        # Scenario 2: Clone failure
        # Simulate Popen failure
        mock_process.returncode = 128
        mock_process.wait.return_value = 128
        mock_process.stdout.readline.side_effect = ["fatal: destination path already exists\n", ""]

        # We need to ensure we call reset usage for next run
        runner.reset_mock()
        runner.check_output.side_effect = ["commit_hash", "commit_hash"]  # Reset side effect

        with patch("os.path.isfile", return_value=True):
            result = perform_git_update(
                "/path/to/repo", print_fn=print_fn, logger=logger, t_fn=t_fn
            )
        self.assertEqual(result[0], False)
        self.assertIn("Git clone failed", result[1])

        # Scenario 3: Verify failure (Hash mismatch after install)
        # We simulate that verification of staged install fails (missing key file)
        mock_process.returncode = 0
        mock_process.wait.return_value = 0
        mock_process.stdout.readline.side_effect = ["Cloning...\n", ""]
        mock_run_result.returncode = 0  # Install success

        runner.reset_mock()
        runner.check_output.side_effect = ["commit_hash", "commit_hash"]

        # Fail verification by making key file check return False
        def side_effect_isfile(path):
            # The code checks for key files in staged_install_path
            # key_files = ["__init__.py", "cli.py", "core/auditor.py"]
            # If any is missing, it fails.
            # We fail on __init__.py
            if "redaudit.new" in str(path) and "__init__.py" in str(path):
                return False
            return True

        with patch("os.path.isfile", side_effect=side_effect_isfile):
            result = perform_git_update(
                "/path/to/repo", print_fn=print_fn, logger=logger, t_fn=t_fn
            )

        self.assertEqual(result[0], False)
        self.assertIn("Staged install missing key file", result[1])

        # Scenario 4: Clone verification failure
        # 1. ls-remote -> expected_hash
        # 2. git clone success
        # 3. rev-parse HEAD -> wrong_hash
        runner.reset_mock()
        # Enough items for potential fallback calls + rev-parse
        runner.check_output.side_effect = ["expected_hash", "wrong_hash", "extra", "extra"]

        # Configure mock_popen for git clone
        mock_process_clone = MagicMock()
        mock_process_clone.stdout.readline.return_value = ""  # EOF
        mock_process_clone.poll.return_value = 0  # Done
        mock_process_clone.wait.return_value = 0  # Success
        mock_popen.return_value = mock_process_clone

        mock_process.returncode = 0

        # Ensure clone dir checks pass to allow reaching verification
        mock_isdir.return_value = True

        success, msg = perform_git_update(
            "/path/to/repo", print_fn=print_fn, logger=logger, t_fn=t_fn
        )
        self.assertFalse(success)
        self.assertIn("Clone verification failed", msg)
        mock_rmtree.assert_called()


if __name__ == "__main__":
    unittest.main()
    unittest.main()
