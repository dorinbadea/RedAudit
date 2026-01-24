#!/usr/bin/env python3
"""
RedAudit - CommandRunner Tests
"""

import os
import sys
import unittest
import subprocess
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.command_runner import CommandRunner


class _Logger:
    def __init__(self):
        self.messages = []

    def debug(self, msg):
        self.messages.append(("debug", msg))

    def info(self, msg):
        self.messages.append(("info", msg))

    def warning(self, msg):
        self.messages.append(("warning", msg))

    def error(self, msg):
        self.messages.append(("error", msg))


class TestCommandRunner(unittest.TestCase):
    def test_rejects_string_args(self):
        runner = CommandRunner()
        with self.assertRaises(TypeError):
            runner.run("echo hi")  # type: ignore[arg-type]

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_dry_run_does_not_execute(self, mock_run):
        logger = _Logger()
        runner = CommandRunner(logger=logger, dry_run=True)
        res = runner.run(["echo", "hello"])
        self.assertTrue(res.ok)
        self.assertEqual(res.attempts, 0)
        mock_run.assert_not_called()
        self.assertTrue(any("dry-run" in m[1] for m in logger.messages if m[0] == "info"))

    def test_command_wrapper_applies(self):
        def _wrap(cmd):
            return ["proxychains"] + list(cmd)

        runner = CommandRunner(dry_run=True, command_wrapper=_wrap)
        res = runner.run(["nmap", "-sV"])
        self.assertEqual(res.args[0], "proxychains")

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_dry_run_binary_mode_returns_bytes(self, mock_run):
        runner = CommandRunner(dry_run=True)
        res = runner.run(["curl", "http://example.com"], capture_output=True, text=False)
        mock_run.assert_not_called()
        self.assertEqual(res.stdout, b"")
        self.assertEqual(res.stderr, b"")

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_retries_on_timeout_then_succeeds(self, mock_run):
        import subprocess

        def side_effect(*args, **kwargs):
            if side_effect.calls == 0:
                side_effect.calls += 1
                raise subprocess.TimeoutExpired(cmd=args[0], timeout=1)
            completed = MagicMock()
            completed.returncode = 0
            completed.stdout = "ok"
            completed.stderr = ""
            return completed

        side_effect.calls = 0
        mock_run.side_effect = side_effect

        runner = CommandRunner(default_timeout=1, default_retries=1, backoff_base_s=0)
        res = runner.run(["echo", "hi"])
        self.assertTrue(res.ok)
        self.assertEqual(res.attempts, 2)

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_redacts_env_values_in_output(self, mock_run):
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = "token=SECRET123"
        completed.stderr = ""
        mock_run.return_value = completed

        logger = _Logger()
        runner = CommandRunner(logger=logger, redact_env_keys={"TEST_SECRET"}, backoff_base_s=0)
        res = runner.run(["echo", "token=SECRET123"], env={"TEST_SECRET": "SECRET123"})
        self.assertIn("***", res.stdout)
        self.assertNotIn("SECRET123", res.stdout)

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_allows_devnull_when_capture_output_false(self, mock_run):
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = None
        completed.stderr = None
        mock_run.return_value = completed

        runner = CommandRunner(default_timeout=1)
        res = runner.run(
            ["echo", "hi"],
            capture_output=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertTrue(res.ok)
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs["capture_output"])
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_file_not_found_returns_127(self, mock_run):
        mock_run.side_effect = FileNotFoundError("missing binary")
        runner = CommandRunner()
        result = runner.run(["missing-binary"])
        self.assertEqual(result.returncode, 127)
        self.assertIn("missing binary", str(result.stderr))

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_called_process_error_returns_result(self, mock_run):
        exc = subprocess.CalledProcessError(2, ["cmd"], output="oops", stderr="bad")
        mock_run.side_effect = exc
        runner = CommandRunner(default_retries=0)
        result = runner.run(["cmd"], check=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("oops", result.stdout)
        self.assertIn("bad", result.stderr)

    def test_check_output_requires_text(self):
        runner = CommandRunner()
        with self.assertRaises(ValueError):
            runner.check_output(["echo", "hi"], text=False)

    def test_validate_args_empty(self):
        runner = CommandRunner()
        with self.assertRaises(ValueError):
            runner.run([])

    def test_merge_env_ignores_non_str(self):
        runner = CommandRunner()
        merged = runner._merge_env({1: "bad", "OK": 2, "GOOD": "yes"})  # type: ignore[arg-type]
        self.assertIn("GOOD", merged)
        self.assertNotIn(1, merged)

    def test_redact_known_flag_values(self):
        runner = CommandRunner()
        text = "--nvd-key SECRET --encrypt-password pass socks5://user:token@host"
        redacted = runner._redact_known_flag_values(text)
        self.assertNotIn("SECRET", redacted)
        self.assertIn("***", redacted)
        self.assertIn("--encrypt-password ***", redacted)

    def test_capture_output_conflict_raises(self):
        runner = CommandRunner()
        with self.assertRaises(ValueError):
            runner.run(["echo", "hi"], capture_output=True, stdout=subprocess.DEVNULL)

    @patch("builtins.print", side_effect=RuntimeError("fail"))
    def test_dry_run_print_exception(self, _mock_print):
        runner = CommandRunner(dry_run=True)
        res = runner.run(["echo", "hi"])
        self.assertTrue(res.ok)

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_timeout_returns_result(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["sleep"], timeout=1, output="out", stderr="err"
        )
        runner = CommandRunner(default_timeout=1, default_retries=0, backoff_base_s=0)
        result = runner.run(["sleep", "1"])
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)

    def test_command_wrapper_failures(self):
        logger = _Logger()

        def _boom(_cmd):
            raise RuntimeError("wrap fail")

        runner = CommandRunner(logger=logger, command_wrapper=_boom)
        cmd = runner._apply_command_wrapper(("echo", "hi"))
        self.assertEqual(cmd, ("echo", "hi"))

        def _bad(_cmd):
            return [""]

        runner_bad = CommandRunner(logger=logger, command_wrapper=_bad)
        cmd_bad = runner_bad._apply_command_wrapper(("echo", "hi"))
        self.assertEqual(cmd_bad, ("echo", "hi"))

    def test_validate_args_casts_non_str(self):
        runner = CommandRunner()
        with patch("redaudit.core.command_runner.subprocess.run") as mock_run:
            completed = MagicMock()
            completed.returncode = 0
            completed.stdout = ""
            completed.stderr = ""
            mock_run.return_value = completed
            result = runner.run(["echo", 1])
            self.assertTrue(result.ok)

    def test_sleep_backoff_handles_exception(self):
        runner = CommandRunner(backoff_base_s=0.01)
        with patch("redaudit.core.command_runner.time.sleep", side_effect=RuntimeError("sleep")):
            runner._sleep_backoff(1)

    def test_log_handles_logger_exception(self):
        class _BadLogger:
            def debug(self, _msg):
                raise RuntimeError("boom")

        runner = CommandRunner(logger=_BadLogger())
        runner._log("DEBUG", "x")

    def test_dry_run_no_capture_output(self):
        runner = CommandRunner(dry_run=True)
        result = runner.run(["echo", "hi"], capture_output=False)
        self.assertIsNone(result.stdout)

    def test_dry_run_property(self):
        runner = CommandRunner(dry_run=True)
        self.assertTrue(runner.dry_run)

    def test_sleep_backoff_zero(self):
        runner = CommandRunner()
        runner._sleep_backoff(0)

    def test_redact_text_skips_empty_values(self):
        runner = CommandRunner()
        text = runner._redact_text("secret", {""})
        self.assertEqual(text, "secret")


if __name__ == "__main__":
    unittest.main()
