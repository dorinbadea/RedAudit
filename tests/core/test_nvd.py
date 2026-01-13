#!/usr/bin/env python3
"""
RedAudit - NVD Module Tests
Copyright (C) 2026  Dorin Badea
GPLv3 License

Tests for redaudit/core/nvd.py
"""

import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

# Import the module under test
from redaudit.core.nvd import (
    build_cpe_query,
    extract_product_version,
    get_cache_key,
    ensure_cache_dir,
    NVD_CACHE_DIR,
    enrich_port_with_cves,
    enrich_host_with_cves,
)
from redaudit.core.models import Host


class TestBuildCpeQuery(unittest.TestCase):
    """Tests for CPE query string building."""

    def test_basic_cpe_format(self):
        """Basic CPE 2.3 string format."""
        result = build_cpe_query("apache", "2.4.49")
        self.assertTrue(result.startswith("cpe:2.3:a:"))
        self.assertIn("apache", result)
        self.assertIn("2.4.49", result)

    def test_with_vendor(self):
        """CPE with specific vendor."""
        result = build_cpe_query("httpd", "2.4.49", "apache")
        self.assertIn(":apache:", result)
        self.assertIn(":httpd:", result)

    def test_sanitizes_special_chars(self):
        """Special characters should be removed."""
        result = build_cpe_query("apache!@#$", "2.4.49")
        self.assertNotIn("!", result)
        self.assertNotIn("@", result)
        self.assertNotIn("#", result)

    def test_lowercase_conversion(self):
        """Product and vendor should be lowercase."""
        result = build_cpe_query("Apache", "2.4.49", "APACHE")
        self.assertIn(":apache:", result.lower())

    def test_version_preserved(self):
        """Version string should be preserved."""
        result = build_cpe_query("openssh", "7.9p1")
        self.assertIn("7.9p1", result)


class TestExtractProductVersion(unittest.TestCase):
    """Tests for product/version extraction from service strings."""

    def test_apache_httpd_format(self):
        """Extract from 'Apache httpd 2.4.49' format."""
        product, version = extract_product_version("Apache httpd 2.4.49")
        self.assertEqual(product.lower(), "apache")
        self.assertEqual(version, "2.4.49")

    def test_openssh_format(self):
        """Extract from 'OpenSSH 7.9p1' format."""
        product, version = extract_product_version("OpenSSH 7.9p1")
        self.assertEqual(product.lower(), "openssh")
        self.assertEqual(version, "7.9p1")

    def test_nginx_slash_format(self):
        """Extract from 'nginx/1.18.0' format."""
        product, version = extract_product_version("nginx/1.18.0")
        self.assertEqual(product.lower(), "nginx")
        self.assertEqual(version, "1.18.0")

    def test_empty_string(self):
        """Empty string returns None, None."""
        product, version = extract_product_version("")
        self.assertIsNone(product)
        self.assertIsNone(version)

    def test_none_input(self):
        """None input returns None, None."""
        product, version = extract_product_version(None)
        self.assertIsNone(product)
        self.assertIsNone(version)

    def test_no_version(self):
        """String without version returns None, None."""
        product, version = extract_product_version("unknown service")
        self.assertIsNone(product)
        self.assertIsNone(version)


class TestGetCacheKey(unittest.TestCase):
    """Tests for cache key generation."""

    def test_returns_md5_hex(self):
        """Should return 32-char hex string (MD5)."""
        result = get_cache_key("test query")
        self.assertEqual(len(result), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_deterministic(self):
        """Same input should give same output."""
        result1 = get_cache_key("apache 2.4.49")
        result2 = get_cache_key("apache 2.4.49")
        self.assertEqual(result1, result2)

    def test_different_inputs(self):
        """Different inputs should give different outputs."""
        result1 = get_cache_key("apache 2.4.49")
        result2 = get_cache_key("nginx 1.18.0")
        self.assertNotEqual(result1, result2)


class TestCacheDirPermissions(unittest.TestCase):
    """Tests for cache directory permissions."""

    def test_ensure_cache_dir_creates_with_permissions(self):
        """ensure_cache_dir should create directory with 0o700 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_cache_dir = os.path.join(tmpdir, "test_cache", "nvd")

            with patch("redaudit.core.nvd.NVD_CACHE_DIR", test_cache_dir):
                # Re-import to get patched value
                from redaudit.core import nvd

                nvd.NVD_CACHE_DIR = test_cache_dir

                result = nvd.ensure_cache_dir()

                self.assertTrue(os.path.isdir(test_cache_dir))

                # Check permissions
                dir_stat = os.stat(test_cache_dir)
                mode = stat.S_IMODE(dir_stat.st_mode)
                self.assertEqual(mode, 0o700)


class TestEnrichPortWithCves(unittest.TestCase):
    """Tests for port enrichment logic (no network)."""

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_uses_nmap_cpe_without_version(self, _mock_sleep, mock_query):
        mock_query.return_value = []
        port = {
            "service": "http",
            "product": "Apache httpd",
            "version": "",
            "cpe": ["cpe:/a:apache:http_server:2.4.49"],
        }
        enrich_port_with_cves(port, api_key="12345678-1234-1234-1234-123456789abc", logger=None)
        args, kwargs = mock_query.call_args
        self.assertIn("cpe_name", kwargs)
        self.assertTrue(kwargs["cpe_name"].startswith("cpe:2.3:a:apache:http_server:2.4.49"))

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_skips_wildcard_cpe_without_version_info(self, _mock_sleep, mock_query):
        """Avoid querying NVD for CPEs without a specific version (too broad)."""
        port = {
            "service": "dns",
            "product": "",
            "version": "",
            "cpe": ["cpe:/a:nlnetlabs:nsd"],
        }
        enrich_port_with_cves(port, api_key="12345678-1234-1234-1234-123456789abc", logger=None)
        mock_query.assert_not_called()

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_cpe_23_passthrough_and_critical_severity(self, _mock_sleep, mock_query):
        mock_query.return_value = [{"cvss_score": 9.8}]
        port = {
            "service": "http",
            "product": "",
            "version": "",
            "cpe": "cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*",
        }
        result = enrich_port_with_cves(port, api_key=None, logger=None)
        self.assertEqual(result.get("cve_max_severity"), "CRITICAL")

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_cpe_legacy_conversion(self, _mock_sleep, mock_query):
        mock_query.return_value = []
        port = {
            "service": "",
            "product": "",
            "version": "",
            "cpe": "cpe:/a:vendor:prod:1.2.3",
        }
        enrich_port_with_cves(port, api_key=None, logger=None)
        _, kwargs = mock_query.call_args
        self.assertIn("cpe:2.3:a:vendor:prod:1.2.3", kwargs.get("cpe_name", ""))

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_cpe_legacy_short_skips_query(self, _mock_sleep, mock_query):
        port = {
            "service": "svc",
            "product": "",
            "version": "",
            "cpe": "cpe:/a:vendor",
        }
        enrich_port_with_cves(port, api_key=None, logger=None)
        mock_query.assert_not_called()

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_cpe_23_wildcard_version_requires_version(self, _mock_sleep, mock_query):
        port = {
            "service": "svc",
            "product": "svc",
            "version": "",
            "cpe": "cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*",
        }
        enrich_port_with_cves(port, api_key=None, logger=None)
        mock_query.assert_not_called()

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_cpe_23_wildcard_version_sanitized_empty(self, _mock_sleep, mock_query):
        port = {
            "service": "svc",
            "product": "svc",
            "version": "???",
            "cpe": "cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*",
        }
        enrich_port_with_cves(port, api_key=None, logger=None)
        mock_query.assert_not_called()

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_keyword_fallback_sets_medium_severity(self, _mock_sleep, mock_query):
        mock_query.side_effect = [[], [{"cvss_score": 4.2}]]
        port = {"service": "nginx/1.2.3", "product": "", "version": "", "cpe": None}
        result = enrich_port_with_cves(port, api_key=None, logger=None)
        self.assertEqual(result.get("cve_max_severity"), "MEDIUM")
        self.assertEqual(result.get("cve_count"), 1)
        self.assertEqual(mock_query.call_count, 2)

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_severity_high_and_low(self, _mock_sleep, mock_query):
        mock_query.return_value = [{"cvss_score": 7.5}]
        port = {
            "service": "http",
            "product": "",
            "version": "1.0",
            "cpe": "cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*",
        }
        result = enrich_port_with_cves(port, api_key=None, logger=None)
        self.assertEqual(result.get("cve_max_severity"), "HIGH")

        mock_query.return_value = [{"cvss_score": 0.1}]
        port = {
            "service": "http",
            "product": "",
            "version": "1.0",
            "cpe": "cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*",
        }
        result = enrich_port_with_cves(port, api_key=None, logger=None)
        self.assertEqual(result.get("cve_max_severity"), "LOW")

    @patch("redaudit.core.nvd.query_nvd")
    @patch("redaudit.core.nvd.time.sleep")
    def test_no_product_no_version_returns(self, _mock_sleep, mock_query):
        port = {"service": "", "product": "", "version": "", "cpe": None}
        result = enrich_port_with_cves(port, api_key=None, logger=None)
        self.assertEqual(result, port)
        mock_query.assert_not_called()


class TestEnrichHostWithCves(unittest.TestCase):
    @patch("redaudit.core.nvd.enrich_port_with_cves")
    def test_enrich_host_dict_summary(self, mock_enrich):
        mock_enrich.side_effect = [
            {"cve_count": 2, "cve_max_severity": "HIGH", "version": "1.0"},
        ]
        host = {"ports": [{"version": "1.0"}, {"service": "noop"}]}
        result = enrich_host_with_cves(host, api_key=None, logger=None)
        self.assertEqual(result["cve_summary"]["total"], 2)
        self.assertEqual(mock_enrich.call_count, 1)

    @patch("redaudit.core.nvd.enrich_port_with_cves")
    def test_enrich_host_object_summary(self, mock_enrich):
        mock_enrich.return_value = {
            "cve_count": 1,
            "cve_max_severity": "CRITICAL",
            "version": "1.0",
            "cpe": ["cpe:/a:vendor:prod:1.0"],
        }
        host = Host(ip="1.1.1.1", ports=[{"version": "1.0", "cpe": ["cpe:/a:vendor:prod:1.0"]}])
        result = enrich_host_with_cves(host, api_key=None, logger=None)
        self.assertIs(result, host)
        self.assertEqual(host.cve_summary.get("critical"), 1)


if __name__ == "__main__":
    unittest.main()
