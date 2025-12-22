#!/usr/bin/env python3
"""
RedAudit - JSONL exporter tests

Validates that JSONL exports include provenance fields for SIEM ingestion.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.jsonl_exporter import export_all, _extract_title


class TestJsonlExporter(unittest.TestCase):
    def test_export_all_includes_provenance_fields(self):
        results = {
            "schema_version": "1.0",
            "generated_at": "2025-12-17T00:00:00",
            "timestamp": "2025-12-17T00:00:00",
            "timestamp_end": "2025-12-17T00:10:00",
            "session_id": "session-123",
            "version": "3.5.0",
            "scanner_versions": {"redaudit": "3.5.0"},
            "targets": ["192.168.1.0/24"],
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "hostname": "test-host",
                    "status": "up",
                    "risk_score": 0,
                    "total_ports_found": 1,
                    "web_ports_count": 0,
                    "observable_hash": "asset-1",
                    "tags": ["test"],
                    "ecs_host": {"mac": ["00:11:22:33:44:55"], "vendor": "TestVendor"},
                }
            ],
            "vulnerabilities": [
                {
                    "host": "192.168.1.10",
                    "vulnerabilities": [
                        {
                            "finding_id": "finding-1",
                            "port": 80,
                            "url": "http://192.168.1.10/",
                            "severity": "low",
                            "normalized_severity": 1.0,
                            "category": "surface",
                            "parsed_observations": ["Missing HSTS"],
                        }
                    ],
                }
            ],
            "summary": {"duration": "0:10:00", "max_risk_score": 0, "high_risk_hosts": 0},
        }

        with tempfile.TemporaryDirectory() as tmp:
            stats = export_all(results, tmp)
            self.assertEqual(stats["findings"], 1)
            self.assertEqual(stats["assets"], 1)

            findings_path = os.path.join(tmp, "findings.jsonl")
            assets_path = os.path.join(tmp, "assets.jsonl")
            summary_path = os.path.join(tmp, "summary.json")

            with open(findings_path, "r", encoding="utf-8") as f:
                finding = json.loads(f.readline())
            for key in ("session_id", "schema_version", "scanner", "scanner_version"):
                self.assertIn(key, finding)
            self.assertEqual(finding["session_id"], "session-123")
            self.assertEqual(finding["scanner"], "RedAudit")
            self.assertEqual(finding["scanner_version"], "3.5.0")

            with open(assets_path, "r", encoding="utf-8") as f:
                asset = json.loads(f.readline())
            for key in ("session_id", "schema_version", "scanner", "scanner_version"):
                self.assertIn(key, asset)
            self.assertEqual(asset["session_id"], "session-123")
            self.assertEqual(asset["scanner"], "RedAudit")
            self.assertEqual(asset["scanner_version"], "3.5.0")

            with open(summary_path, "r", encoding="utf-8") as f:
                summary = json.load(f)
            self.assertEqual(summary.get("session_id"), "session-123")
            self.assertEqual(summary.get("redaudit_version"), "3.5.0")

    def test_extract_title_from_observations(self):
        vuln = {"parsed_observations": ["Missing HSTS on endpoint"]}
        self.assertEqual(
            _extract_title(vuln), "Missing HTTP Strict Transport Security Header"
        )

        vuln = {"parsed_observations": ["Server banner reveals version"], "port": 80}
        self.assertEqual(_extract_title(vuln), "Server Version Disclosed in Banner")

        vuln = {"parsed_observations": ["Detected cve-2024-1234 issue"], "port": 443}
        self.assertEqual(_extract_title(vuln), "Known Vulnerability: CVE-2024-1234")

    def test_extract_title_fallbacks(self):
        vuln = {"port": 443, "url": "https://example.com"}
        self.assertEqual(_extract_title(vuln), "Web Service Finding on Port 443")

        vuln = {"port": 22}
        self.assertEqual(_extract_title(vuln), "Service Finding on Port 22")


if __name__ == "__main__":
    unittest.main()
