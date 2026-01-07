#!/usr/bin/env python3
"""
RedAudit - Tests for verify_vuln module
v2.9 Smart-Check false positive filtering
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.verify_vuln import (
    extract_path_from_finding,
    is_sensitive_file,
    is_false_positive_by_content_type,
    is_false_positive_by_size,
    check_nuclei_false_positive,
    filter_nuclei_false_positives,
    verify_content_type,
    verify_magic_bytes,
    verify_nikto_finding,
    filter_nikto_false_positives,
)


class TestVerifyVuln(unittest.TestCase):
    """Tests for Nikto false positive filtering."""

    def test_extract_path_standard(self):
        """Test path extraction from standard Nikto format."""
        finding = "+ /backup.tar: This file may contain sensitive data."
        result = extract_path_from_finding(finding)
        self.assertEqual(result, "/backup.tar")

    def test_extract_path_osvdb(self):
        """Test path extraction from OSVDB format."""
        finding = "OSVDB-12345: /admin/.htpasswd found on the server."
        result = extract_path_from_finding(finding)
        self.assertEqual(result, "/admin/.htpasswd")

    def test_extract_path_no_path(self):
        """Test that None is returned for findings without paths."""
        finding = "+ Server: Apache/2.4.49 appears to be outdated."
        result = extract_path_from_finding(finding)
        # This may or may not find a path depending on the content
        # The important thing is it doesn't crash
        self.assertIsInstance(result, (str, type(None)))

    def test_is_sensitive_file_tar(self):
        """Test sensitive file detection for tar."""
        self.assertTrue(is_sensitive_file("/backup.tar"))
        self.assertTrue(is_sensitive_file("/config.bak"))
        self.assertTrue(is_sensitive_file("/server.pem"))

    def test_is_sensitive_file_non_sensitive(self):
        """Test non-sensitive file detection."""
        self.assertFalse(is_sensitive_file("/index.html"))
        self.assertFalse(is_sensitive_file("/robots.txt"))
        self.assertFalse(is_sensitive_file(""))

    def test_fp_by_content_type_json(self):
        """Test that JSON content-type is flagged as FP for tar files."""
        result = is_false_positive_by_content_type(".tar", "application/json")
        self.assertTrue(result)

    def test_fp_by_content_type_html(self):
        """Test that HTML content-type is flagged as FP for zip files."""
        result = is_false_positive_by_content_type(".zip", "text/html")
        self.assertTrue(result)

    def test_fp_by_content_type_binary(self):
        """Test that binary content-type is NOT flagged as FP."""
        result = is_false_positive_by_content_type(".tar", "application/x-tar")
        self.assertFalse(result)

    def test_fp_by_size_small_archive(self):
        """Test that very small archive sizes are flagged as FP."""
        result = is_false_positive_by_size(".tar", 47)  # 47 bytes JSON response
        self.assertTrue(result)

    def test_fp_by_size_valid_archive(self):
        """Test that larger archive sizes are NOT flagged as FP."""
        result = is_false_positive_by_size(".tar", 50000)  # 50KB
        self.assertFalse(result)

    def test_nuclei_false_positive_router_vendor(self):
        finding = {
            "template-id": "CVE-2022-26143",
            "response": "HTTP/1.1 200 OK\\r\\nServer: FRITZ!OS Guest information Server\\r\\n\\r\\n{}",
        }
        is_fp, reason = check_nuclei_false_positive(finding, {"device_vendor": "AVM"})
        self.assertTrue(is_fp)
        self.assertIn("fp_vendor_detected", reason)

    @patch("redaudit.core.verify_vuln.verify_content_type")
    def test_verify_finding_filtered(self, mock_verify):
        """Test that a finding with JSON response is filtered."""
        mock_verify.return_value = ("application/json", 47)

        finding = "+ /backup.tar: May contain sensitive config."
        is_valid, reason = verify_nikto_finding(finding, "http://192.168.1.1:8189")

        self.assertFalse(is_valid)
        self.assertIn("filtered", reason)

    @patch("redaudit.core.verify_vuln.verify_content_type")
    def test_verify_finding_kept(self, mock_verify):
        """Test that a finding with binary response is kept."""
        mock_verify.return_value = ("application/x-tar", 102400)

        finding = "+ /backup.tar: May contain sensitive config."
        is_valid, reason = verify_nikto_finding(finding, "http://192.168.1.1")

        self.assertTrue(is_valid)
        self.assertIn("kept", reason)

    def test_filter_empty_list(self):
        """Test filtering empty list returns empty."""
        result = filter_nikto_false_positives([], "http://test.com")
        self.assertEqual(result, [])

    @patch("redaudit.core.verify_vuln.verify_nikto_finding")
    def test_filter_removes_fps(self, mock_verify):
        """Test that filter removes false positives."""
        # First finding is FP, second is valid
        mock_verify.side_effect = [
            (False, "filtered:content_type"),
            (True, "kept:verified"),
        ]

        findings = [
            "+ /backup.tar: May contain data.",
            "+ /admin/: Possible admin directory.",
        ]

        result = filter_nikto_false_positives(findings, "http://test.com")

        self.assertEqual(len(result), 1)
        self.assertIn("admin", result[0])

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_verify_content_type_dry_run_does_not_execute(self, mock_run):
        with patch.dict(os.environ, {"REDAUDIT_DRY_RUN": "1"}, clear=False):
            content_type, content_len = verify_content_type("http://example.com", extra_tools={})
        mock_run.assert_not_called()
        self.assertIsNone(content_type)
        self.assertIsNone(content_len)


if __name__ == "__main__":
    unittest.main()


def test_verify_content_type_no_curl():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = "Content-Type: text/html\n"
        mock_runner.run.return_value = mock_result

        content_type, length = verify_content_type("http://example.com", extra_tools={})
        assert content_type == "text/html"


def test_verify_content_type_content_length_value_error():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = "Content-Length: invalid\n"
        mock_runner.run.return_value = mock_result

        content_type, length = verify_content_type("http://example.com")
        assert length is None


def test_verify_magic_bytes_no_curl():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = b"PK\x03\x04test"
        mock_runner.run.return_value = mock_result

        is_valid, reason = verify_magic_bytes("http://example.com/file.zip", ".zip", extra_tools={})
        assert isinstance(is_valid, bool)


def test_verify_magic_bytes_no_magic_defined():
    is_valid, reason = verify_magic_bytes("http://example.com/file.unknown", ".unknown")
    assert is_valid is True
    assert "kept:no_magic_check_for_ext" in reason


def test_verify_magic_bytes_html_response():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = b"<html>" + (b"x" * 300)
        mock_runner.run.return_value = mock_result

        is_valid, reason = verify_magic_bytes("http://example.com/backup.tar", ".tar")
        assert isinstance(is_valid, bool)


def test_verify_nikto_finding_size_false_positive():
    with patch("redaudit.core.verify_vuln.verify_content_type") as mock_verify:
        mock_verify.return_value = ("application/octet-stream", 100)

        is_valid, reason = verify_nikto_finding(
            "+ /backup.tar: This file may contain...", "http://example.com"
        )
        assert is_valid is False
        assert "too_small" in reason


def test_verify_nikto_finding_magic_bytes_fail():
    with patch("redaudit.core.verify_vuln.verify_content_type") as mock_verify:
        with patch("redaudit.core.verify_vuln.verify_magic_bytes") as mock_magic:
            mock_verify.return_value = ("application/octet-stream", 5000)
            mock_magic.return_value = (False, "filtered:magic_mismatch")

            is_valid, reason = verify_nikto_finding(
                "+ /backup.tar: This file may contain...", "http://example.com"
            )
            assert is_valid is False


def test_filter_nikto_false_positives_with_logger():
    logger = MagicMock()

    with patch("redaudit.core.verify_vuln.verify_nikto_finding") as mock_verify:
        mock_verify.side_effect = [
            (True, "kept:verified"),
            (False, "filtered:content_type_mismatch"),
        ]

        findings = ["finding1", "finding2"]
        result = filter_nikto_false_positives(findings, "http://example.com", logger=logger)

        assert len(result) == 1
        assert logger.debug.called
        assert logger.info.called


def test_check_nuclei_false_positive_no_template_id():
    finding = {}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False
    assert reason == "no_template_id"


def test_check_nuclei_false_positive_raw_dict():
    finding = {"template-id": "CVE-2022-26143", "raw": {"response": "Server: Fritz!Box\r\n"}}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True


def test_check_nuclei_false_positive_server_header_parsing():
    finding = {
        "template-id": "CVE-2022-26143",
        "response": "HTTP/1.1 200 OK\r\nServer: Mitel-MiCollab\r\n",
    }
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False


def test_check_nuclei_false_positive_expected_vendor():
    finding = {"template-id": "CVE-2022-26143", "response": "Server: Mitel\r\n"}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False
    assert reason == "expected_vendor_found"


def test_check_nuclei_false_positive_infrastructure_device():
    finding = {"template-id": "CVE-2022-26143", "response": "Server: Netgear\r\n"}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True
    assert "netgear" in reason.lower()


def test_filter_nuclei_false_positives_empty():
    genuine, fps = filter_nuclei_false_positives([])
    assert genuine == []
    assert fps == []


def test_filter_nuclei_false_positives_url_parsing():
    findings = [
        {
            "template-id": "CVE-2022-26143",
            "ip": "http://192.168.1.1:8080",
            "response": "Server: Fritz!Box\r\n",
        }
    ]
    host_agentless = {"192.168.1.1": {"device_vendor": "AVM"}}

    genuine, fps = filter_nuclei_false_positives(findings, host_agentless)
    assert len(fps) == 1


def test_filter_nuclei_false_positives_with_logger():
    logger = MagicMock()
    findings = [
        {"template-id": "CVE-2022-26143", "ip": "192.168.1.1", "response": "Server: Fritz!Box\r\n"}
    ]

    genuine, fps = filter_nuclei_false_positives(findings, logger=logger)
    assert len(fps) == 1
    assert logger.info.called


def test_check_nuclei_false_positive_lf_line_endings():
    """Test header parsing with LF line endings (v4.3.1 fix)."""
    finding = {
        "template-id": "CVE-2022-26143",
        "response": "HTTP/1.1 200 OK\nServer: FRITZ!OS Guest information Server\nDate: Mon, 01 Jan 2026",
    }
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True
    assert "vendor_detected" in reason or "fritz" in reason.lower()
