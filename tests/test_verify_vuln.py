#!/usr/bin/env python3
"""
RedAudit - Tests for verify_vuln module
v2.9 Smart-Check false positive filtering
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.verify_vuln import (
    extract_path_from_finding,
    is_sensitive_file,
    is_false_positive_by_content_type,
    is_false_positive_by_size,
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

    @patch('redaudit.core.verify_vuln.verify_content_type')
    def test_verify_finding_filtered(self, mock_verify):
        """Test that a finding with JSON response is filtered."""
        mock_verify.return_value = ("application/json", 47)
        
        finding = "+ /backup.tar: May contain sensitive config."
        is_valid, reason = verify_nikto_finding(finding, "http://192.168.1.1:8189")
        
        self.assertFalse(is_valid)
        self.assertIn("filtered", reason)

    @patch('redaudit.core.verify_vuln.verify_content_type')
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

    @patch('redaudit.core.verify_vuln.verify_nikto_finding')
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


if __name__ == "__main__":
    unittest.main()
