#!/usr/bin/env python3
"""
RedAudit - CommandRunner Tests
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


if __name__ == "__main__":
    unittest.main()
