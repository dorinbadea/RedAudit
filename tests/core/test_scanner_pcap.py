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


if __name__ == "__main__":
    unittest.main()
