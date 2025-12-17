#!/usr/bin/env python3
"""
RedAudit - Power/Sleep Inhibition Tests
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.power import SleepInhibitor


class TestSleepInhibitor(unittest.TestCase):
    @patch("redaudit.core.power.subprocess.Popen")
    @patch("redaudit.core.power.shutil.which", return_value="/usr/bin/caffeinate")
    @patch("redaudit.core.power.platform.system", return_value="Darwin")
    def test_macos_uses_caffeinate(self, mock_sys, mock_which, mock_popen):
        inst = SleepInhibitor()
        inst.start()
        mock_popen.assert_called()
        args = mock_popen.call_args[0][0]
        self.assertIn("caffeinate", args[0])
        self.assertIn("-dimsu", args)

    @patch("redaudit.core.power.subprocess.Popen")
    @patch("redaudit.core.power.shutil.which")
    @patch("redaudit.core.power.platform.system", return_value="Linux")
    def test_linux_uses_systemd_inhibit_when_available(self, mock_sys, mock_which, mock_popen):
        def which_side_effect(name):
            if name == "systemd-inhibit":
                return "/usr/bin/systemd-inhibit"
            return None

        mock_which.side_effect = which_side_effect
        inst = SleepInhibitor()
        inst.start()
        mock_popen.assert_called()
        args = mock_popen.call_args[0][0]
        self.assertIn("systemd-inhibit", args[0])

    @patch("redaudit.core.command_runner.subprocess.run")
    @patch("redaudit.core.power.subprocess.Popen")
    @patch("redaudit.core.power.shutil.which")
    @patch("redaudit.core.power.platform.system", return_value="Linux")
    def test_x11_xset_applied_when_display_set(self, mock_sys, mock_which, mock_popen, mock_run):
        def which_side_effect(name):
            if name == "xset":
                return "/usr/bin/xset"
            if name == "systemd-inhibit":
                return "/usr/bin/systemd-inhibit"
            return None

        mock_which.side_effect = which_side_effect
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=False):
            inst = SleepInhibitor()
            inst.start()
        # xset q + the 3 xset modifications
        self.assertGreaterEqual(mock_run.call_count, 1)

    @patch("redaudit.core.command_runner.subprocess.run")
    @patch("redaudit.core.power.subprocess.Popen")
    def test_dry_run_skips_all_external_commands(self, mock_popen, mock_run):
        inst = SleepInhibitor(dry_run=True)
        inst.start()
        inst.stop()
        mock_popen.assert_not_called()
        mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
