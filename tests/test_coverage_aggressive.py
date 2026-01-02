"""Cleaned coverage tests for auditor_scan.py"""

import unittest
from unittest.mock import Mock


class TestAuditorScanDeepCoverage(unittest.TestCase):
    """Tests for auditor_scan.py edge cases."""

    def _make_auditor(self):
        """Create mock for auditor_scan methods."""
        auditor = Mock()
        auditor.config = {
            "scan_mode": "normal",
            "threads": 4,
            "target_networks": ["192.168.1.0/24"],
        }
        auditor.results = {"hosts": [], "network_info": []}
        auditor.extra_tools = {}
        auditor.logger = None
        auditor.rate_limit_delay = 0.0
        auditor.interrupted = False
        auditor.t = lambda k, *a: str(k)
        auditor.print_status = Mock()
        return auditor

    def test_prune_weak_identity_reasons(self):
        """Test _prune_weak_identity_reasons method."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        smart_scan = {
            "reasons": ["low_visibility", "no_ports", "other"],
            "weak_reasons": [],
        }

        AuditorScanMixin._prune_weak_identity_reasons(auditor, smart_scan)
        self.assertIn("reasons", smart_scan)

    def test_scan_mode_host_timeout(self):
        """Test _scan_mode_host_timeout_s method."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["scan_mode"] = "fast"

        timeout = AuditorScanMixin._scan_mode_host_timeout_s(auditor)
        self.assertIsInstance(timeout, float)
        self.assertGreater(timeout, 0)

    def test_scan_mode_host_timeout_normal(self):
        """Test _scan_mode_host_timeout_s for normal mode."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["scan_mode"] = "normal"

        timeout = AuditorScanMixin._scan_mode_host_timeout_s(auditor)
        self.assertIsInstance(timeout, float)

    def test_scan_mode_host_timeout_full(self):
        """Test _scan_mode_host_timeout_s for full mode."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["scan_mode"] = "completo"

        timeout = AuditorScanMixin._scan_mode_host_timeout_s(auditor)
        self.assertIsInstance(timeout, float)

    def test_extract_nmap_xml_valid(self):
        """Test _extract_nmap_xml with valid XML."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        raw = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/></host>
</nmaprun>"""

        result = AuditorScanMixin._extract_nmap_xml(raw)
        self.assertIn("<nmaprun>", result)

    def test_sanitize_ip_valid(self):
        """Test sanitize_ip with valid IP."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        result = AuditorScanMixin.sanitize_ip("192.168.1.1")
        self.assertEqual(result, "192.168.1.1")

    def test_sanitize_ip_ipv6(self):
        """Test sanitize_ip with IPv6."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        result = AuditorScanMixin.sanitize_ip("::1")
        self.assertEqual(result, "::1")

    def test_sanitize_ip_invalid(self):
        """Test sanitize_ip with invalid IP."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        result = AuditorScanMixin.sanitize_ip("not.an.ip.address")
        self.assertIsNone(result)

    def test_sanitize_hostname_valid(self):
        """Test sanitize_hostname with valid hostname."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        result = AuditorScanMixin.sanitize_hostname("my-host.local")
        self.assertEqual(result, "my-host.local")

    def test_is_web_service_http(self):
        """Test is_web_service for http."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        self.assertTrue(AuditorScanMixin.is_web_service(auditor, "http"))

    def test_is_web_service_https(self):
        """Test is_web_service for https."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        self.assertTrue(AuditorScanMixin.is_web_service(auditor, "https"))

    def test_is_web_service_proxy(self):
        """Test is_web_service for http-proxy."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        self.assertTrue(AuditorScanMixin.is_web_service(auditor, "http-proxy"))

    def test_is_web_service_ssh(self):
        """Test is_web_service for ssh (non-web)."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        self.assertFalse(AuditorScanMixin.is_web_service(auditor, "ssh"))

    def test_is_web_service_ftp(self):
        """Test is_web_service for ftp (non-web)."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        self.assertFalse(AuditorScanMixin.is_web_service(auditor, "ftp"))


if __name__ == "__main__":
    unittest.main()
