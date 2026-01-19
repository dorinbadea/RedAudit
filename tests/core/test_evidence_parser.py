#!/usr/bin/env python3
"""
RedAudit - Evidence Parser Tests
"""

import os
import tempfile
import unittest

from redaudit.core.evidence_parser import (
    enrich_with_observations,
    extract_observations,
    parse_nikto_findings,
    parse_testssl_output,
)


class TestEvidenceParserDescriptiveTitle(unittest.TestCase):
    def test_descriptive_title_prefers_missing_header(self):
        record = {
            "url": "http://example.local:80/",
            "port": 80,
            "nikto_findings": [
                "+ Target IP:          10.0.0.1",
                "+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            ],
        }
        enriched = enrich_with_observations(record)
        self.assertIn("parsed_observations", enriched)
        self.assertEqual(enriched.get("descriptive_title"), "Missing X-Frame-Options header")

    def test_descriptive_title_prefers_cve(self):
        record = {
            "url": "http://example.local:80/",
            "port": 80,
            "nikto_findings": [
                "+ /: The web server may reveal its internal IP via Location header. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649",
            ],
        }
        enriched = enrich_with_observations(record)
        self.assertEqual(enriched.get("descriptive_title"), "CVE-2000-0649")


class TestEvidenceParserHelpers(unittest.TestCase):
    def test_parse_nikto_findings_dedupes_and_truncates(self):
        lines = [
            "+ Target IP: 10.0.0.1",
            "+ /: Retrieved x-powered-by header: PHP/8.2",
            "+ /: Retrieved x-powered-by header: PHP/8.2",
            "+ /: The X-Content-Type-Options header is not set",
            "+ /: " + ("A" * 120),
        ]
        observations = parse_nikto_findings(lines)
        self.assertIn("X-Powered-By disclosure: PHP/8.2", observations)
        self.assertIn("Missing X-Content-Type-Options header", observations)
        self.assertTrue(any(obs.endswith("...") for obs in observations))

    def test_parse_testssl_output_protocols_and_ciphers(self):
        data = {
            "vulnerabilities": ["VULNERABLE: BEAST"],
            "weak_ciphers": ["RC4"],
            "protocols": {"TLS1.0": True, "SSLv3": True},
        }
        observations = parse_testssl_output(data)
        self.assertIn("SSL/TLS vulnerability detected", observations)
        self.assertIn("Weak ciphers detected", observations)
        self.assertIn("TLS 1.0 enabled", observations)
        self.assertIn("SSLv3 enabled", observations)

    def test_extract_observations_includes_whatweb_and_raw(self):
        record = {
            "nikto_findings": [
                "+ /: The anti-clickjacking X-Frame-Options header is not present",
            ],
            "whatweb": "[Apache][PHP]",
        }
        observations, raw_output = extract_observations(record)
        self.assertIn("Missing X-Frame-Options header", observations)
        self.assertIn("Technology: Apache", observations)
        self.assertIn("NIKTO", raw_output)

    def test_enrich_with_observations_externalizes_large_output(self):
        record = {
            "url": "http://example.local:80/",
            "port": 80,
            "testssl_analysis": {
                "raw_output": "x" * 5000,
                "vulnerabilities": ["SSL certificate expired"],
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            enriched = enrich_with_observations(record, output_dir=tmpdir)
            ref = enriched.get("raw_tool_output_ref")
            self.assertTrue(ref)
            self.assertTrue(os.path.exists(os.path.join(tmpdir, ref)))

        self.assertIn("raw_tool_output_sha256", enriched)
        self.assertIn("raw_tool_output_ref", enriched)


class TestFallbackObservations(unittest.TestCase):
    """Test v4.14 fallback observations from service data."""

    def test_extract_observations_fallback_from_url(self):
        """Test observations generated from URL when no tool findings."""
        record = {
            "url": "https://192.168.1.1:443/admin",
            "port": 443,
        }
        observations, _ = extract_observations(record)
        self.assertTrue(len(observations) > 0)
        self.assertTrue(any("192.168.1.1" in obs or "443" in obs for obs in observations))

    def test_extract_observations_fallback_from_service(self):
        """Test observations generated from service info."""
        record = {
            "port": 80,
            "service": "http",
            "banner": "Apache/2.4.52 (Ubuntu)",
        }
        observations, _ = extract_observations(record)
        self.assertTrue(any("Service: http" in obs for obs in observations))
        self.assertTrue(any("Banner:" in obs and "Apache" in obs for obs in observations))

    def test_extract_observations_fallback_from_headers(self):
        """Test observations generated from HTTP headers."""
        record = {
            "url": "http://192.168.1.1/",
            "port": 80,
            "headers": {
                "server": "nginx/1.18.0",
                "x-powered-by": "PHP/8.1",
            },
        }
        observations, _ = extract_observations(record)
        self.assertTrue(any("nginx" in obs for obs in observations))
        self.assertTrue(any("PHP" in obs for obs in observations))

    def test_extract_observations_no_fallback_when_tool_findings(self):
        """Test that fallback is NOT used when tool findings exist."""
        record = {
            "url": "http://192.168.1.1/",
            "port": 80,
            "nikto_findings": [
                "+ /: Missing HSTS header",
            ],
        }
        observations, _ = extract_observations(record)
        # Should have nikto observation, not fallback from url
        self.assertTrue(any("HSTS" in obs for obs in observations))
        # Should NOT have "Endpoint:" prefix from fallback
        self.assertFalse(any(obs.startswith("Endpoint:") for obs in observations))


if __name__ == "__main__":
    unittest.main()
