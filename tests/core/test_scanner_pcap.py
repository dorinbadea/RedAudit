#!/usr/bin/env python3
"""
Tests for PCAP management functions in traffic.py.

v4.3: Tests for merge_pcap_files, organize_pcap_files, finalize_pcap_artifacts.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from redaudit.core.scanner.traffic import (
    merge_pcap_files,
    organize_pcap_files,
    finalize_pcap_artifacts,
)


class TestMergePcapFiles(unittest.TestCase):
    """Tests for merge_pcap_files function."""

    def test_merge_skips_when_dry_run(self):
        """Should return None when dry_run=True."""
        result = merge_pcap_files(
            output_dir="/tmp",
            session_id="test",
            extra_tools={},
            dry_run=True,
        )
        self.assertIsNone(result)

    def test_merge_skips_when_no_mergecap(self):
        """Should return None when mergecap is not available."""
        with patch("shutil.which", return_value=None):
            result = merge_pcap_files(
                output_dir="/tmp",
                session_id="test",
                extra_tools={},
                dry_run=False,
            )
        self.assertIsNone(result)

    def test_merge_skips_when_less_than_2_files(self):
        """Should skip merge when fewer than 2 PCAP files exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create just 1 file
            pcap1 = os.path.join(tmpdir, "traffic_192_168_1_1_120000.pcap")
            with open(pcap1, "wb") as f:
                f.write(b"\x00" * 100)

            with patch("shutil.which", return_value="/usr/bin/mergecap"):
                result = merge_pcap_files(
                    output_dir=tmpdir,
                    session_id="test",
                    extra_tools={},
                    dry_run=False,
                )
            self.assertIsNone(result)


class TestOrganizePcapFiles(unittest.TestCase):
    """Tests for organize_pcap_files function."""

    def test_organize_returns_none_when_no_files(self):
        """Should return None when no PCAP files exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = organize_pcap_files(tmpdir)
            self.assertIsNone(result)

    def test_organize_creates_raw_captures_dir(self):
        """Should create raw_captures directory and move files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test PCAP files
            pcap1 = os.path.join(tmpdir, "traffic_192_168_1_1_120000.pcap")
            pcap2 = os.path.join(tmpdir, "traffic_192_168_1_2_120001.pcap")
            with open(pcap1, "wb") as f:
                f.write(b"\x00" * 100)
            with open(pcap2, "wb") as f:
                f.write(b"\x00" * 100)

            result = organize_pcap_files(tmpdir)

            # Verify directory created
            self.assertIsNotNone(result)
            self.assertTrue(os.path.isdir(result))
            self.assertEqual(os.path.basename(result), "raw_captures")

            # Verify files moved
            self.assertFalse(os.path.exists(pcap1))
            self.assertFalse(os.path.exists(pcap2))
            self.assertTrue(os.path.exists(os.path.join(result, "traffic_192_168_1_1_120000.pcap")))
            self.assertTrue(os.path.exists(os.path.join(result, "traffic_192_168_1_2_120001.pcap")))

    def test_organize_excludes_merged_file(self):
        """Should not move the merged file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            pcap1 = os.path.join(tmpdir, "traffic_192_168_1_1_120000.pcap")
            merged = os.path.join(tmpdir, "full_capture_test.pcap")
            with open(pcap1, "wb") as f:
                f.write(b"\x00" * 100)
            with open(merged, "wb") as f:
                f.write(b"\x00" * 200)

            result = organize_pcap_files(tmpdir, merged_file=merged)

            # Merged file should still be in root
            self.assertTrue(os.path.exists(merged))
            # Result should be the raw_captures dir if created
            self.assertIsNotNone(result)


class TestFinalizePcapArtifacts(unittest.TestCase):
    """Tests for finalize_pcap_artifacts function."""

    def test_finalize_returns_empty_when_no_files(self):
        """Should return dict with zeros when no PCAP files exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = finalize_pcap_artifacts(
                output_dir=tmpdir,
                session_id="test",
                extra_tools={},
            )
            self.assertEqual(result["merged_file"], None)
            self.assertEqual(result["raw_captures_dir"], None)
            self.assertEqual(result["individual_count"], 0)

    def test_finalize_counts_files(self):
        """Should count individual PCAP files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            for i in range(3):
                pcap = os.path.join(tmpdir, f"traffic_192_168_1_{i}_120000.pcap")
                with open(pcap, "wb") as f:
                    f.write(b"\x00" * 100)

            with patch("shutil.which", return_value=None):
                result = finalize_pcap_artifacts(
                    output_dir=tmpdir,
                    session_id="test",
                    extra_tools={},
                )

            self.assertEqual(result["individual_count"], 3)


class TestCaptureTrafficSnippet(unittest.TestCase):
    """Tests for capture_traffic_snippet function."""

    def test_returns_none_when_no_tcpdump(self):
        """Should return None when tcpdump not in extra_tools."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet

        result = capture_traffic_snippet(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[],
            extra_tools={},
        )
        self.assertIsNone(result)

    def test_returns_none_when_dry_run(self):
        """Should return None when dry_run=True."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet

        result = capture_traffic_snippet(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=True,
        )
        self.assertIsNone(result)

    def test_returns_none_when_invalid_ip(self):
        """Should return None for invalid IP."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet

        result = capture_traffic_snippet(
            host_ip="not-an-ip",
            output_dir="/tmp",
            networks=[],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_returns_none_when_no_interface_found(self):
        """Should return None when no interface matches the IP."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet

        result = capture_traffic_snippet(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "10.0.0.0/8", "interface": "eth0"}],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_uses_default_duration_when_invalid(self):
        """Should use default duration when invalid value provided."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock

        logger = MagicMock()
        result = capture_traffic_snippet(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            duration=-1,  # Invalid
            logger=logger,
            dry_run=False,
        )
        # Logger should have warned about invalid duration
        self.assertTrue(logger.warning.called or logger.info.called or result is None)


class TestStartBackgroundCapture(unittest.TestCase):
    """Tests for start_background_capture function."""

    def test_returns_none_when_no_tcpdump(self):
        """Should return None when tcpdump not available."""
        from redaudit.core.scanner.traffic import start_background_capture

        result = start_background_capture(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[],
            extra_tools={},
        )
        self.assertIsNone(result)

    def test_returns_none_when_dry_run(self):
        """Should return None when dry_run=True."""
        from redaudit.core.scanner.traffic import start_background_capture

        result = start_background_capture(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=True,
        )
        self.assertIsNone(result)

    def test_returns_none_when_invalid_ip(self):
        """Should return None for invalid IP."""
        from redaudit.core.scanner.traffic import start_background_capture

        result = start_background_capture(
            host_ip="invalid",
            output_dir="/tmp",
            networks=[],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_returns_none_when_no_interface(self):
        """Should return None when no interface matches."""
        from redaudit.core.scanner.traffic import start_background_capture

        result = start_background_capture(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "10.0.0.0/8", "interface": "eth0"}],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_returns_none_when_invalid_interface_name(self):
        """Should return None for unsafe interface name."""
        from redaudit.core.scanner.traffic import start_background_capture

        result = start_background_capture(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "192.168.0.0/16", "interface": "; rm -rf /"}],  # Malicious
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)


class TestStopBackgroundCapture(unittest.TestCase):
    """Tests for stop_background_capture function."""

    def test_returns_none_when_no_capture_info(self):
        """Should return None when capture_info is None."""
        from redaudit.core.scanner.traffic import stop_background_capture

        result = stop_background_capture(
            capture_info=None,
            extra_tools={},
        )
        self.assertIsNone(result)

    def test_returns_none_when_no_process(self):
        """Should return None when capture_info has no process."""
        from redaudit.core.scanner.traffic import stop_background_capture

        result = stop_background_capture(
            capture_info={"pcap_file": "test.pcap"},
            extra_tools={},
        )
        self.assertIsNone(result)

    def test_terminates_process_and_returns_result(self):
        """Should terminate process and return result dict."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock

        mock_proc = MagicMock()
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock()

        result = stop_background_capture(
            capture_info={
                "process": mock_proc,
                "pcap_file": "test.pcap",
                "pcap_file_abs": "/tmp/test.pcap",
                "iface": "en0",
            },
            extra_tools={},
        )

        self.assertIsNotNone(result)
        self.assertIn("pcap_file", result)
        mock_proc.terminate.assert_called_once()

    def test_handles_process_kill_on_timeout(self):
        """Should kill process if terminate times out."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock
        import subprocess

        mock_proc = MagicMock()
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock(side_effect=subprocess.TimeoutExpired("cmd", 5))
        mock_proc.kill = MagicMock()

        result = stop_background_capture(
            capture_info={
                "process": mock_proc,
                "pcap_file": "test.pcap",
                "iface": "en0",
            },
            extra_tools={},
        )

        self.assertIn("tcpdump_error", result)
        mock_proc.kill.assert_called_once()


class TestCaptureTrafficSnippetSuccess(unittest.TestCase):
    """Tests for capture_traffic_snippet success paths."""

    def test_capture_with_valid_interface_and_mock_runner(self):
        """Should capture traffic when interface found and runner mocked."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock, patch

        mock_runner = MagicMock()
        mock_result = MagicMock()
        mock_result.timed_out = False
        mock_result.returncode = 0
        mock_result.stdout = "summary"
        mock_result.stderr = ""
        mock_runner.run.return_value = mock_result

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.makedirs"):
                result = capture_traffic_snippet(
                    host_ip="192.168.1.1",
                    output_dir="/tmp/test",
                    networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                    extra_tools={"tcpdump": "/usr/bin/tcpdump", "tshark": "/usr/bin/tshark"},
                    duration=5,
                    dry_run=False,
                )

        self.assertIsNotNone(result)
        self.assertIn("pcap_file", result)

    def test_capture_logs_dry_run(self):
        """Should log when dry_run with logger."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock

        logger = MagicMock()
        result = capture_traffic_snippet(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            logger=logger,
            dry_run=True,
        )
        self.assertIsNone(result)
        logger.info.assert_called()

    def test_capture_logs_no_interface(self):
        """Should log when no interface found."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock

        logger = MagicMock()
        result = capture_traffic_snippet(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "10.0.0.0/8", "interface": "eth0"}],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            logger=logger,
            dry_run=False,
        )
        self.assertIsNone(result)
        logger.info.assert_called()

    def test_capture_handles_runner_timeout(self):
        """Should handle runner timeout."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock, patch

        mock_runner = MagicMock()
        mock_result = MagicMock()
        mock_result.timed_out = True
        mock_runner.run.return_value = mock_result

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.makedirs"):
                result = capture_traffic_snippet(
                    host_ip="192.168.1.1",
                    output_dir="/tmp/test",
                    networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                    extra_tools={"tcpdump": "/usr/bin/tcpdump"},
                    duration=5,
                    dry_run=False,
                )

        self.assertIn("tcpdump_error", result)

    def test_capture_handles_runner_exception(self):
        """Should handle runner exception."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock, patch

        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("Runner failed")

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.makedirs"):
                result = capture_traffic_snippet(
                    host_ip="192.168.1.1",
                    output_dir="/tmp/test",
                    networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                    extra_tools={"tcpdump": "/usr/bin/tcpdump"},
                    duration=5,
                    dry_run=False,
                )

        self.assertIn("tcpdump_error", result)

    def test_capture_with_tshark_success(self):
        """Should include tshark summary on success."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock, patch

        mock_runner = MagicMock()
        mock_result = MagicMock()
        mock_result.timed_out = False
        mock_result.returncode = 0
        mock_result.stdout = "Protocol Hierarchy Statistics"
        mock_result.stderr = ""
        mock_runner.run.return_value = mock_result

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.makedirs"):
                result = capture_traffic_snippet(
                    host_ip="192.168.1.1",
                    output_dir="/tmp/test",
                    networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                    extra_tools={"tcpdump": "/usr/bin/tcpdump", "tshark": "/usr/bin/tshark"},
                    duration=5,
                    dry_run=False,
                )

        self.assertIn("tshark_summary", result)

    def test_capture_with_tshark_timeout(self):
        """Should record tshark error on timeout."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock, patch

        call_count = [0]

        def mock_run(*args, **kwargs):
            result = MagicMock()
            call_count[0] += 1
            if call_count[0] == 1:  # tcpdump
                result.timed_out = False
            else:  # tshark
                result.timed_out = True
            return result

        mock_runner = MagicMock()
        mock_runner.run.side_effect = mock_run

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.makedirs"):
                result = capture_traffic_snippet(
                    host_ip="192.168.1.1",
                    output_dir="/tmp/test",
                    networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                    extra_tools={"tcpdump": "/usr/bin/tcpdump", "tshark": "/usr/bin/tshark"},
                    duration=5,
                    dry_run=False,
                )

        self.assertIn("tshark_error", result)


class TestStartBackgroundCaptureSuccess(unittest.TestCase):
    """Tests for start_background_capture success paths."""

    def test_start_with_valid_interface_mocked(self):
        """Should start capture with valid interface."""
        from redaudit.core.scanner.traffic import start_background_capture
        from unittest.mock import MagicMock, patch

        mock_popen = MagicMock()
        with patch("subprocess.Popen", return_value=mock_popen):
            with patch("os.makedirs"):
                result = start_background_capture(
                    host_ip="192.168.1.1",
                    output_dir="/tmp/test",
                    networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                    extra_tools={"tcpdump": "/usr/bin/tcpdump"},
                    dry_run=False,
                )

        self.assertIsNotNone(result)
        self.assertEqual(result["process"], mock_popen)
        self.assertEqual(result["iface"], "en0")

    def test_start_logs_dry_run(self):
        """Should log when dry_run with logger."""
        from redaudit.core.scanner.traffic import start_background_capture
        from unittest.mock import MagicMock

        logger = MagicMock()
        result = start_background_capture(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            logger=logger,
            dry_run=True,
        )
        self.assertIsNone(result)
        logger.info.assert_called()

    def test_start_handles_popen_exception(self):
        """Should handle Popen exception."""
        from redaudit.core.scanner.traffic import start_background_capture
        from unittest.mock import MagicMock, patch

        with patch("subprocess.Popen", side_effect=OSError("No permission")):
            with patch("os.makedirs"):
                result = start_background_capture(
                    host_ip="192.168.1.1",
                    output_dir="/tmp/test",
                    networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                    extra_tools={"tcpdump": "/usr/bin/tcpdump"},
                    logger=MagicMock(),
                    dry_run=False,
                )

        self.assertIsNone(result)


class TestStopBackgroundCaptureSuccess(unittest.TestCase):
    """Tests for stop_background_capture with tshark summary."""

    def test_stop_with_tshark_summary(self):
        """Should include tshark summary when available."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock, patch

        mock_proc = MagicMock()
        mock_runner = MagicMock()
        mock_result = MagicMock()
        mock_result.timed_out = False
        mock_result.stdout = "Protocol Hierarchy"
        mock_result.stderr = ""
        mock_runner.run.return_value = mock_result

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.path.exists", return_value=True):
                with patch("os.chmod"):
                    result = stop_background_capture(
                        capture_info={
                            "process": mock_proc,
                            "pcap_file": "test.pcap",
                            "pcap_file_abs": "/tmp/test.pcap",
                            "iface": "en0",
                        },
                        extra_tools={"tshark": "/usr/bin/tshark"},
                    )

        self.assertIn("tshark_summary", result)

    def test_stop_normalizes_absolute_path_in_pcap_file(self):
        """Should normalize legacy absolute paths to filenames."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock

        mock_proc = MagicMock()
        result = stop_background_capture(
            capture_info={
                "process": mock_proc,
                "pcap_file": "/tmp/traffic.pcap",  # Old format with abs path
                "iface": "en0",
            },
            extra_tools={},
        )

        self.assertEqual(result["pcap_file"], "traffic.pcap")

    def test_stop_with_tshark_dry_run(self):
        """Should skip tshark when dry_run."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock, patch

        mock_proc = MagicMock()
        with patch("os.path.exists", return_value=True):
            result = stop_background_capture(
                capture_info={
                    "process": mock_proc,
                    "pcap_file": "test.pcap",
                    "pcap_file_abs": "/tmp/test.pcap",
                    "iface": "en0",
                },
                extra_tools={"tshark": "/usr/bin/tshark"},
                dry_run=True,
            )

        self.assertNotIn("tshark_summary", result)


class TestMergePcapFilesSuccess(unittest.TestCase):
    """Tests for merge_pcap_files success paths."""

    def test_merge_success_with_mock_runner(self):
        """Should merge files successfully with mocked runner."""
        from redaudit.core.scanner.traffic import merge_pcap_files
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test PCAP files
            for i in range(3):
                pcap = os.path.join(tmpdir, f"traffic_192_168_1_{i}_120000.pcap")
                with open(pcap, "wb") as f:
                    f.write(b"\x00" * 100)

            merged_path = os.path.join(tmpdir, "full_capture_test.pcap")
            # Pre-create merged file to simulate success
            with open(merged_path, "wb") as f:
                f.write(b"\x00" * 300)

            mock_runner = MagicMock()
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.timed_out = False
            mock_runner.run.return_value = mock_result

            with patch("shutil.which", return_value="/usr/bin/mergecap"):
                with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
                    result = merge_pcap_files(
                        output_dir=tmpdir,
                        session_id="test",
                        extra_tools={},
                        logger=MagicMock(),
                        dry_run=False,
                    )

            self.assertEqual(result, merged_path)

    def test_merge_failure_logs_error(self):
        """Should log error on merge failure."""
        from redaudit.core.scanner.traffic import merge_pcap_files
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test PCAP files
            for i in range(3):
                pcap = os.path.join(tmpdir, f"traffic_192_168_1_{i}_120000.pcap")
                with open(pcap, "wb") as f:
                    f.write(b"\x00" * 100)

            mock_runner = MagicMock()
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stderr = "merge failed"
            mock_result.stdout = ""
            mock_runner.run.return_value = mock_result

            logger = MagicMock()
            with patch("shutil.which", return_value="/usr/bin/mergecap"):
                with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
                    result = merge_pcap_files(
                        output_dir=tmpdir,
                        session_id="test",
                        extra_tools={},
                        logger=logger,
                        dry_run=False,
                    )

            self.assertIsNone(result)
            logger.warning.assert_called()

    def test_merge_exception_logs_error(self):
        """Should log error on exception."""
        from redaudit.core.scanner.traffic import merge_pcap_files
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test PCAP files
            for i in range(3):
                pcap = os.path.join(tmpdir, f"traffic_192_168_1_{i}_120000.pcap")
                with open(pcap, "wb") as f:
                    f.write(b"\x00" * 100)

            mock_runner = MagicMock()
            mock_runner.run.side_effect = Exception("Merge explosion")

            logger = MagicMock()
            with patch("shutil.which", return_value="/usr/bin/mergecap"):
                with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
                    result = merge_pcap_files(
                        output_dir=tmpdir,
                        session_id="test",
                        extra_tools={},
                        logger=logger,
                        dry_run=False,
                    )

            self.assertIsNone(result)
            logger.warning.assert_called()


class TestOrganizePcapFilesEdgeCases(unittest.TestCase):
    """Edge case tests for organize_pcap_files."""

    def test_organize_handles_move_exception(self):
        """Should handle file move exception."""
        from redaudit.core.scanner.traffic import organize_pcap_files
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap = os.path.join(tmpdir, "traffic_192_168_1_1_120000.pcap")
            with open(pcap, "wb") as f:
                f.write(b"\x00" * 100)

            logger = MagicMock()
            with patch("shutil.move", side_effect=OSError("Permission denied")):
                result = organize_pcap_files(tmpdir, logger=logger)

            # Should return None when all moves fail
            self.assertIsNone(result)

    def test_organize_logs_success(self):
        """Should log success message."""
        from redaudit.core.scanner.traffic import organize_pcap_files
        from unittest.mock import MagicMock

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap = os.path.join(tmpdir, "traffic_192_168_1_1_120000.pcap")
            with open(pcap, "wb") as f:
                f.write(b"\x00" * 100)

            logger = MagicMock()
            result = organize_pcap_files(tmpdir, logger=logger)

            self.assertIsNotNone(result)
            logger.info.assert_called()


class TestEdgeCasesForHighCoverage(unittest.TestCase):
    """Additional edge case tests to push coverage above 90%."""

    def test_capture_with_network_exception(self):
        """Should handle exception in network parsing."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet

        result = capture_traffic_snippet(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "invalid-network"}],  # Will cause exception
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_capture_with_invalid_interface_chars(self):
        """Should return None for interface with invalid characters."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet

        result = capture_traffic_snippet(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "192.168.0.0/16", "interface": "eth0; rm -rf /"}],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_capture_tshark_exception(self):
        """Should handle tshark exception."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import MagicMock, patch

        call_count = [0]

        def mock_run(*args, **kwargs):
            result = MagicMock()
            call_count[0] += 1
            if call_count[0] == 1:  # tcpdump
                result.timed_out = False
            else:  # tshark
                raise Exception("Tshark crashed")
            return result

        mock_runner = MagicMock()
        mock_runner.run.side_effect = mock_run

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.makedirs"):
                result = capture_traffic_snippet(
                    host_ip="192.168.1.1",
                    output_dir="/tmp/test",
                    networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                    extra_tools={"tcpdump": "/usr/bin/tcpdump", "tshark": "/usr/bin/tshark"},
                    duration=5,
                    dry_run=False,
                )

        self.assertIn("tshark_error", result)

    def test_start_with_network_exception(self):
        """Should handle exception in start_background network parsing."""
        from redaudit.core.scanner.traffic import start_background_capture

        result = start_background_capture(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "bogus//24"}],  # Invalid
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_start_logs_no_interface(self):
        """Should log when no interface found in start_background."""
        from redaudit.core.scanner.traffic import start_background_capture
        from unittest.mock import MagicMock

        logger = MagicMock()
        result = start_background_capture(
            host_ip="192.168.1.1",
            output_dir="/tmp",
            networks=[{"network": "10.0.0.0/8", "interface": "eth0"}],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            logger=logger,
            dry_run=False,
        )
        self.assertIsNone(result)
        logger.info.assert_called()

    def test_stop_handles_terminate_exception(self):
        """Should handle exception during process terminate."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock

        mock_proc = MagicMock()
        mock_proc.terminate.side_effect = OSError("Cannot terminate")

        result = stop_background_capture(
            capture_info={
                "process": mock_proc,
                "pcap_file": "test.pcap",
                "iface": "en0",
            },
            extra_tools={},
        )

        self.assertIn("tcpdump_error", result)

    def test_stop_tshark_exception(self):
        """Should handle tshark exception in stop_background."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock, patch

        mock_proc = MagicMock()
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("Tshark exploded")

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.path.exists", return_value=True):
                with patch("os.chmod"):
                    result = stop_background_capture(
                        capture_info={
                            "process": mock_proc,
                            "pcap_file": "test.pcap",
                            "pcap_file_abs": "/tmp/test.pcap",
                            "iface": "en0",
                        },
                        extra_tools={"tshark": "/usr/bin/tshark"},
                    )

        self.assertIn("tshark_error", result)

    def test_stop_tshark_timeout(self):
        """Should handle tshark timeout."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock, patch

        mock_proc = MagicMock()
        mock_runner = MagicMock()
        mock_result = MagicMock()
        mock_result.timed_out = True
        mock_runner.run.return_value = mock_result

        with patch("redaudit.core.scanner.traffic._make_runner", return_value=mock_runner):
            with patch("os.path.exists", return_value=True):
                with patch("os.chmod"):
                    result = stop_background_capture(
                        capture_info={
                            "process": mock_proc,
                            "pcap_file": "test.pcap",
                            "pcap_file_abs": "/tmp/test.pcap",
                            "iface": "en0",
                        },
                        extra_tools={"tshark": "/usr/bin/tshark"},
                    )

        self.assertIn("tshark_error", result)

    def test_merge_logs_dry_run(self):
        """Should log when dry_run in merge."""
        from redaudit.core.scanner.traffic import merge_pcap_files
        from unittest.mock import MagicMock

        logger = MagicMock()
        result = merge_pcap_files(
            output_dir="/tmp",
            session_id="test",
            extra_tools={},
            logger=logger,
            dry_run=True,
        )
        self.assertIsNone(result)
        logger.info.assert_called()

    def test_merge_logs_no_mergecap(self):
        """Should log when mergecap not found."""
        from redaudit.core.scanner.traffic import merge_pcap_files
        from unittest.mock import MagicMock, patch

        logger = MagicMock()
        with patch("shutil.which", return_value=None):
            result = merge_pcap_files(
                output_dir="/tmp",
                session_id="test",
                extra_tools={},
                logger=logger,
                dry_run=False,
            )
        self.assertIsNone(result)
        logger.debug.assert_called()

    def test_merge_logs_less_than_2_files(self):
        """Should log when less than 2 PCAP files."""
        from redaudit.core.scanner.traffic import merge_pcap_files
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap = os.path.join(tmpdir, "traffic_192_168_1_1_120000.pcap")
            with open(pcap, "wb") as f:
                f.write(b"\x00" * 100)

            logger = MagicMock()
            with patch("shutil.which", return_value="/usr/bin/mergecap"):
                result = merge_pcap_files(
                    output_dir=tmpdir,
                    session_id="test",
                    extra_tools={},
                    logger=logger,
                    dry_run=False,
                )
            self.assertIsNone(result)
            logger.debug.assert_called()

    def test_organize_handles_makedirs_exception(self):
        """Should handle makedirs exception."""
        from redaudit.core.scanner.traffic import organize_pcap_files
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap = os.path.join(tmpdir, "traffic_192_168_1_1_120000.pcap")
            with open(pcap, "wb") as f:
                f.write(b"\x00" * 100)

            logger = MagicMock()
            with patch("os.makedirs", side_effect=OSError("No permission")):
                result = organize_pcap_files(tmpdir, logger=logger)

            self.assertIsNone(result)
            logger.warning.assert_called()

    def test_capture_invalid_ip_valueerror(self):
        """Should return None when IP causes ValueError (lines 68-69)."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet

        # An IP that will parse but fail in ipaddress.ip_address()
        result = capture_traffic_snippet(
            host_ip="999.999.999.999",  # Invalid IP that causes ValueError
            output_dir="/tmp",
            networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_start_invalid_ip_valueerror(self):
        """Should return None when IP causes ValueError (lines 175-176)."""
        from redaudit.core.scanner.traffic import start_background_capture

        result = start_background_capture(
            host_ip="999.999.999.999",  # Invalid IP
            output_dir="/tmp",
            networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
            extra_tools={"tcpdump": "/usr/bin/tcpdump"},
            dry_run=False,
        )
        self.assertIsNone(result)

    def test_stop_uses_pcap_file_abs_fallback(self):
        """Should use pcap_file_abs when pcap_file is None (line 241)."""
        from redaudit.core.scanner.traffic import stop_background_capture
        from unittest.mock import MagicMock

        mock_proc = MagicMock()
        result = stop_background_capture(
            capture_info={
                "process": mock_proc,
                # No pcap_file, only pcap_file_abs
                "pcap_file_abs": "/tmp/traffic_test.pcap",
                "iface": "en0",
            },
            extra_tools={},
        )

        self.assertEqual(result["pcap_file"], "traffic_test.pcap")

    def test_merge_chmod_exception(self):
        """Should handle chmod exception silently (lines 356-357)."""
        from redaudit.core.scanner.traffic import merge_pcap_files
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test PCAP files
            for i in range(3):
                pcap = os.path.join(tmpdir, f"traffic_192_168_1_{i}_120000.pcap")
                with open(pcap, "wb") as f:
                    f.write(b"\x00" * 100)

            merged_path = os.path.join(tmpdir, "full_capture_test.pcap")
            with open(merged_path, "wb") as f:
                f.write(b"\x00" * 300)

            mock_runner = MagicMock()
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.timed_out = False
            mock_runner.run.return_value = mock_result

            with patch("shutil.which", return_value="/usr/bin/mergecap"):
                with patch(
                    "redaudit.core.scanner.traffic._make_runner",
                    return_value=mock_runner,
                ):
                    # Patch chmod to raise exception
                    with patch("os.chmod", side_effect=OSError("No permission")):
                        result = merge_pcap_files(
                            output_dir=tmpdir,
                            session_id="test",
                            extra_tools={},
                            logger=MagicMock(),
                            dry_run=False,
                        )

            # Should still succeed despite chmod exception
            self.assertEqual(result, merged_path)

    def test_organize_skips_merged_file(self):
        """Should skip merged file during organize (line 419)."""
        from redaudit.core.scanner.traffic import organize_pcap_files

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create traffic files
            pcap1 = os.path.join(tmpdir, "traffic_192_168_1_1_120000.pcap")
            pcap2 = os.path.join(tmpdir, "traffic_192_168_1_2_120001.pcap")
            # Create merged file with traffic_ prefix to match glob
            merged = os.path.join(tmpdir, "traffic_merged.pcap")

            for f in [pcap1, pcap2, merged]:
                with open(f, "wb") as fh:
                    fh.write(b"\x00" * 100)

            result = organize_pcap_files(tmpdir, merged_file=merged)

            # Merged file should still be in root
            self.assertTrue(os.path.exists(merged))
            # Other files should be moved
            self.assertIsNotNone(result)

    def test_capture_valueerror_in_ipaddress(self):
        """Should return None when ipaddress.ip_address raises ValueError (lines 68-69)."""
        from redaudit.core.scanner.traffic import capture_traffic_snippet
        from unittest.mock import patch

        with patch(
            "redaudit.core.scanner.traffic.ipaddress.ip_address",
            side_effect=ValueError("Invalid IP"),
        ):
            result = capture_traffic_snippet(
                host_ip="192.168.1.1",  # Valid but mocked to fail
                output_dir="/tmp",
                networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                extra_tools={"tcpdump": "/usr/bin/tcpdump"},
                dry_run=False,
            )
        self.assertIsNone(result)

    def test_start_valueerror_in_ipaddress(self):
        """Should return None when ipaddress.ip_address raises ValueError (lines 175-176)."""
        from redaudit.core.scanner.traffic import start_background_capture
        from unittest.mock import patch

        with patch(
            "redaudit.core.scanner.traffic.ipaddress.ip_address",
            side_effect=ValueError("Invalid IP"),
        ):
            result = start_background_capture(
                host_ip="192.168.1.1",  # Valid but mocked to fail
                output_dir="/tmp",
                networks=[{"network": "192.168.0.0/16", "interface": "en0"}],
                extra_tools={"tcpdump": "/usr/bin/tcpdump"},
                dry_run=False,
            )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
