#!/usr/bin/env python3
"""
Unit tests for redaudit.core.rustscan.
"""

import unittest
from unittest.mock import MagicMock, patch
from redaudit.core.rustscan import (
    is_rustscan_available,
    get_rustscan_version,
    run_rustscan,
    run_rustscan_discovery_only,
    run_rustscan_multi,
    _make_runner,
    _parse_rustscan_ports,
    _parse_rustscan_greppable,
    _parse_rustscan_greppable_map,
)


class TestRustScan(unittest.TestCase):
    def test_is_rustscan_available(self):
        with patch("shutil.which", return_value="/usr/bin/rustscan"):
            self.assertTrue(is_rustscan_available())
        with patch("shutil.which", return_value=None):
            self.assertFalse(is_rustscan_available())

    def test_get_rustscan_version(self):
        with patch("shutil.which", return_value="/usr/bin/rustscan"):
            with patch("subprocess.run") as mock_run:
                # Success case
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = "rustscan 1.0.0"
                self.assertEqual(get_rustscan_version(), "1.0.0")

                # Fail case
                mock_run.return_value.returncode = 1
                self.assertIsNone(get_rustscan_version())

                # Exception case
                mock_run.side_effect = Exception("Error")
                self.assertIsNone(get_rustscan_version())

    def test_get_rustscan_version_not_available(self):
        with patch("redaudit.core.rustscan.is_rustscan_available", return_value=False):
            self.assertIsNone(get_rustscan_version())

    def test_parse_rustscan_ports(self):
        stdout = """
        Open 10.0.0.1:80
        Open 10.0.0.1:443
        junk line
        """
        ports = _parse_rustscan_ports(stdout)
        self.assertEqual(ports, [80, 443])

    def test_parse_rustscan_ports_invalid(self):
        stdout = "Open 10.0.0.1:notaport"
        ports = _parse_rustscan_ports(stdout)
        self.assertEqual(ports, [])

    def test_parse_rustscan_greppable(self):
        stdout = "10.0.0.1 -> [80,443, 8080]"
        ports = _parse_rustscan_greppable(stdout)
        self.assertEqual(ports, [80, 443, 8080])

        stdout_garbage = "garbage"
        self.assertEqual(_parse_rustscan_greppable(stdout_garbage), [])

    def test_parse_rustscan_greppable_invalid_line(self):
        stdout = "10.0.0.1 -> [80,443"
        self.assertEqual(_parse_rustscan_greppable(stdout), [])

    def test_parse_rustscan_greppable_map(self):
        stdout = """
        10.0.0.1 -> [80, 443]
        10.0.0.2 -> [22]
        garbage
        """
        mapping = _parse_rustscan_greppable_map(stdout)
        self.assertEqual(mapping["10.0.0.1"], [80, 443])
        self.assertEqual(mapping["10.0.0.2"], [22])

    def test_parse_rustscan_greppable_map_invalid_line(self):
        stdout = "10.0.0.1 -> [80,443"
        mapping = _parse_rustscan_greppable_map(stdout)
        self.assertEqual(mapping, {})

    def test_make_runner_returns_command_runner(self):
        runner = _make_runner()
        self.assertIsNotNone(runner)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_success(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner

        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Open 1.2.3.4:80"
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        result = run_rustscan("1.2.3.4", ports=[80])

        self.assertTrue(result["success"])
        self.assertEqual(result["ports"], [80])
        self.assertIsNone(result["error"])

        # Verify nmap args
        call_args = mock_runner.run.call_args[0][0]
        self.assertIn("-A", call_args)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=False)
    def test_run_rustscan_not_installed(self, mock_avail):
        result = run_rustscan("1.2.3.4")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "RustScan not installed")

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_timeout(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner

        mock_res = MagicMock()
        mock_res.returncode = 0  # Force it to pass error check to hit timeout check
        mock_res.timed_out = True
        mock_runner.run.return_value = mock_res

        result = run_rustscan("1.2.3.4")
        self.assertFalse(result["success"])
        self.assertIn("Timeout", result["error"])

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_exception(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_runner.run.side_effect = Exception("Boom")

        result = run_rustscan("1.2.3.4")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Boom")

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_discovery_only(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner

        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "1.2.3.4 -> [80, 443]"
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        ports, error = run_rustscan_discovery_only("1.2.3.4")
        self.assertEqual(ports, [80, 443])
        self.assertIsNone(error)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=False)
    def test_run_rustscan_discovery_only_not_installed(self, mock_avail):
        ports, error = run_rustscan_discovery_only("1.2.3.4")
        self.assertEqual(ports, [])
        self.assertEqual(error, "RustScan not installed")

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_discovery_only_timeout(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = ""
        mock_res.timed_out = True
        mock_runner.run.return_value = mock_res

        ports, error = run_rustscan_discovery_only("1.2.3.4")
        self.assertEqual(ports, [])
        self.assertIn("timeout", error.lower())

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_discovery_only_stdout_bytes(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = b"1.2.3.4 -> [80]"
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        ports, error = run_rustscan_discovery_only("1.2.3.4")
        self.assertEqual(ports, [80])
        self.assertIsNone(error)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_discovery_only_exception(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_runner.run.side_effect = RuntimeError("boom")

        ports, error = run_rustscan_discovery_only("1.2.3.4")
        self.assertEqual(ports, [])
        self.assertEqual(error, "boom")

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_multi(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner

        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "1.2.3.4 -> [80]\n5.6.7.8 -> [22]"
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        mapping, error = run_rustscan_multi(["1.2.3.4", "5.6.7.8"])
        self.assertEqual(mapping["1.2.3.4"], [80])
        self.assertEqual(mapping["5.6.7.8"], [22])
        self.assertIsNone(error)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    def test_run_rustscan_multi_no_targets(self, mock_avail):
        mapping, error = run_rustscan_multi([])
        self.assertEqual(mapping, {})
        self.assertEqual(error, "No targets provided")

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=False)
    def test_run_rustscan_multi_not_installed(self, mock_avail):
        mapping, error = run_rustscan_multi(["1.2.3.4"])
        self.assertEqual(mapping, {})
        self.assertEqual(error, "RustScan not installed")

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_multi_stdout_bytes(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = b"1.2.3.4 -> [80]"
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        mapping, error = run_rustscan_multi(["1.2.3.4"])
        self.assertEqual(mapping["1.2.3.4"], [80])
        self.assertIsNone(error)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_discovery_fail(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stderr = "Error"
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        ports, error = run_rustscan_discovery_only("1.2.3.4")
        self.assertEqual(ports, [])
        self.assertIn("RustScan failed", error)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_discovery_only_args(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = ""
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        # Test valid ports list
        run_rustscan_discovery_only("1.2.3.4", ports=[80, 443])
        args = mock_runner.run.call_args[0][0]
        self.assertIn("-p", args)
        self.assertIn("80,443", args)

        # Test valid port range
        run_rustscan_discovery_only("1.2.3.4", port_range="1-1000")
        args = mock_runner.run.call_args[0][0]
        self.assertIn("-r", args)
        self.assertIn("1-1000", args)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_multi_args(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = ""
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        run_rustscan_multi(["1.2.3.4"], ports=[22, 80])
        args = mock_runner.run.call_args[0][0]
        self.assertIn("-p", args)
        self.assertIn("22,80", args)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_multi_failure(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stderr = "Error"
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res

        mapping, error = run_rustscan_multi(["1.2.3.4"])
        self.assertEqual(mapping, {})
        self.assertIn("RustScan failed", error)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_multi_timeout(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_res = MagicMock()
        mock_res.returncode = 0  # Force pass error check
        mock_res.timed_out = True
        mock_runner.run.return_value = mock_res

        mapping, error = run_rustscan_multi(["1.2.3.4"])
        self.assertEqual(mapping, {})
        self.assertIn("timeout", error)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan._make_runner")
    def test_run_rustscan_multi_exception(self, mock_make_runner, mock_avail):
        mock_runner = MagicMock()
        mock_make_runner.return_value = mock_runner
        mock_runner.run.side_effect = Exception("Boom")

        mapping, error = run_rustscan_multi(["1.2.3.4"])
        self.assertEqual(mapping, {})
        self.assertIn("Boom", error)


if __name__ == "__main__":
    unittest.main()
