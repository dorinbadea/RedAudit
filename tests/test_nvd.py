#!/usr/bin/env python3
"""
RedAudit - NVD Module Tests
Copyright (C) 2025  Dorin Badea
GPLv3 License

Tests for redaudit/core/nvd.py
"""

import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the module under test
from redaudit.core.nvd import (
    build_cpe_query,
    extract_product_version,
    get_cache_key,
    ensure_cache_dir,
    NVD_CACHE_DIR,
    enrich_port_with_cves,
)


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


if __name__ == "__main__":
    unittest.main()
