#!/usr/bin/env python3
"""
RedAudit - Playbook Generator Tests
Copyright (C) 2026  Dorin Badea
GPLv3 License
"""

import os
import tempfile
import unittest

from redaudit.core.playbook_generator import (
    classify_finding,
    generate_playbook,
    get_playbooks_for_results,
    render_playbook_markdown,
    save_playbooks,
)


class TestClassifyFinding(unittest.TestCase):
    """Test finding classification logic."""

    def test_classify_tls_finding(self):
        """Test TLS/SSL finding classification."""
        finding = {
            "testssl_analysis": {
                "summary": "Weak cipher RC4 detected",
                "vulnerabilities": ["POODLE", "BEAST"],
            }
        }
        self.assertEqual(classify_finding(finding), "tls_hardening")

    def test_classify_cve_finding(self):
        """Test CVE finding classification."""
        finding = {
            "cve_ids": ["CVE-2021-44228", "CVE-2021-45046"],
        }
        self.assertEqual(classify_finding(finding), "cve_remediation")

    def test_classify_http_headers_finding(self):
        """Test HTTP security headers classification."""
        finding = {
            "parsed_observations": ["Missing HSTS header", "X-Frame-Options not set"],
        }
        self.assertEqual(classify_finding(finding), "http_headers")

    def test_classify_web_hardening(self):
        """Test web hardening classification via Nikto."""
        finding = {
            "nikto_findings": ["Directory listing enabled", "Server banner disclosed"],
        }
        self.assertEqual(classify_finding(finding), "web_hardening")

    def test_classify_port_hardening(self):
        """Test dangerous port classification."""
        finding = {
            "descriptive_title": "Telnet service open on port 23",
        }
        self.assertEqual(classify_finding(finding), "port_hardening")

    def test_classify_unknown(self):
        """Test unknown finding returns None."""
        finding = {"url": "http://example.com", "port": 8080}
        self.assertIsNone(classify_finding(finding))


class TestGeneratePlaybook(unittest.TestCase):
    """Test playbook generation."""

    def test_generate_tls_playbook(self):
        """Test TLS playbook has correct structure."""
        finding = {"severity": "high", "port": 443}
        playbook = generate_playbook(finding, "192.168.1.1", "tls_hardening")

        self.assertEqual(playbook["host"], "192.168.1.1")
        self.assertEqual(playbook["category"], "tls_hardening")
        self.assertIn("steps", playbook)
        self.assertIn("commands", playbook)
        self.assertIn("references", playbook)
        self.assertGreater(len(playbook["steps"]), 0)

    def test_generate_cve_playbook_with_cves(self):
        """Test CVE playbook includes CVE references."""
        finding = {"cve_ids": ["CVE-2021-44228"], "severity": "critical"}
        playbook = generate_playbook(finding, "10.0.0.1", "cve_remediation")

        self.assertIn("nvd.nist.gov", playbook["references"][0])


class TestRenderPlaybookMarkdown(unittest.TestCase):
    """Test Markdown rendering."""

    def test_render_basic_playbook(self):
        """Test Markdown output structure."""
        playbook = {
            "title": "Test Finding",
            "host": "192.168.1.1",
            "port": 443,
            "severity": "HIGH",
            "category": "tls_hardening",
            "generated_at": "2025-12-17 12:00",
            "steps": ["Step 1", "Step 2"],
            "commands": ["echo test"],
            "references": ["https://example.com"],
        }
        md = render_playbook_markdown(playbook)

        self.assertIn("# Test Finding", md)
        self.assertIn("**Host**: 192.168.1.1", md)
        self.assertIn("## Remediation Steps", md)
        self.assertIn("1. Step 1", md)
        self.assertIn("```bash", md)
        self.assertIn("## References", md)


class TestGetPlaybooksForResults(unittest.TestCase):
    """Test playbook extraction from results."""

    def test_get_playbooks_deduplicates_per_host(self):
        """Test only one playbook per category per host."""
        results = {
            "vulnerabilities": [
                {
                    "host": "192.168.1.1",
                    "vulnerabilities": [
                        {"testssl_analysis": {"summary": "RC4 weak"}},
                        {"testssl_analysis": {"summary": "TLS 1.0 enabled"}},
                    ],
                }
            ]
        }
        playbooks = get_playbooks_for_results(results)

        # Should only have 1 TLS playbook for this host
        tls_playbooks = [p for p in playbooks if p["category"] == "tls_hardening"]
        self.assertEqual(len(tls_playbooks), 1)


class TestSavePlaybooks(unittest.TestCase):
    """Test saving playbooks to disk."""

    def test_save_playbooks_creates_directory(self):
        """Test playbooks are saved to playbooks/ directory."""
        results = {
            "vulnerabilities": [
                {
                    "host": "192.168.1.1",
                    "vulnerabilities": [
                        {"testssl_analysis": {"summary": "Weak cipher RC4"}},
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            count, playbook_data = save_playbooks(results, tmpdir)

            self.assertGreater(count, 0)
            self.assertGreater(len(playbook_data), 0)
            playbooks_dir = os.path.join(tmpdir, "playbooks")
            self.assertTrue(os.path.isdir(playbooks_dir))
            self.assertGreater(len(os.listdir(playbooks_dir)), 0)

    def test_save_playbooks_empty_results(self):
        """Test empty results returns 0."""
        results = {"vulnerabilities": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            count, playbook_data = save_playbooks(results, tmpdir)
            self.assertEqual(count, 0)
            self.assertEqual(playbook_data, [])


class TestDeviceAwarePlaybooks(unittest.TestCase):
    """Test device-aware remediation (v4.14)."""

    def test_generate_playbook_with_avm_vendor(self):
        """Test AVM/FRITZ devices get embedded_device remediation."""
        finding = {"cve_ids": ["CVE-2024-54767"], "severity": "high"}
        playbook = generate_playbook(
            finding, "192.168.178.1", "cve_remediation", vendor="AVM GmbH", device_type=None
        )

        # Should NOT contain apt/yum commands for embedded devices
        commands_str = " ".join(playbook.get("commands", []))
        self.assertNotIn("apt update", commands_str)
        self.assertNotIn("yum update", commands_str)
        # Should contain embedded device guidance
        self.assertIn("Embedded", commands_str)

    def test_generate_playbook_with_linux_vendor(self):
        """Test Linux servers get apt/yum remediation."""
        finding = {"cve_ids": ["CVE-2021-44228"], "severity": "critical"}
        playbook = generate_playbook(
            finding, "10.0.0.1", "cve_remediation", vendor="Ubuntu", device_type=None
        )

        # Should contain apt/yum commands for Linux
        commands_str = " ".join(playbook.get("commands", []))
        self.assertIn("apt", commands_str.lower())

    def test_generate_playbook_default_without_vendor(self):
        """Test default behavior without vendor info falls back to linux_server."""
        finding = {"cve_ids": ["CVE-2021-44228"], "severity": "critical"}
        playbook = generate_playbook(
            finding, "10.0.0.1", "cve_remediation", vendor=None, device_type=None
        )

        # Should contain linux commands as default
        commands_str = " ".join(playbook.get("commands", []))
        self.assertIn("apt", commands_str.lower())

    def test_generate_playbook_cisco_network_device(self):
        """Test Cisco devices get network_device remediation."""
        finding = {"cve_ids": ["CVE-2023-1234"], "severity": "high"}
        playbook = generate_playbook(
            finding, "10.0.0.1", "cve_remediation", vendor="Cisco Systems", device_type=None
        )

        # Should contain network device guidance
        commands_str = " ".join(playbook.get("commands", []))
        self.assertIn("Network device", commands_str)

    def test_playbook_title_prefers_finding_title(self):
        """Test that playbook title uses finding title over URL."""
        finding = {
            "title": "SSL/TLS vulnerability detected",
            "url": "https://192.168.1.1:55174/",
            "severity": "high",
        }
        playbook = generate_playbook(finding, "192.168.1.1", "tls_hardening")

        # Title should be the descriptive title, not the URL
        self.assertEqual(playbook["title"], "SSL/TLS vulnerability detected")
        self.assertNotIn("://", playbook["title"])


if __name__ == "__main__":
    unittest.main()
