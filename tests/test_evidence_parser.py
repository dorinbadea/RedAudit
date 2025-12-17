#!/usr/bin/env python3
"""
RedAudit - Evidence Parser Tests
"""

import unittest

from redaudit.core.evidence_parser import enrich_with_observations


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


if __name__ == "__main__":
    unittest.main()
