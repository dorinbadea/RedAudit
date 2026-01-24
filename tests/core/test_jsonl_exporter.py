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
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.jsonl_exporter import (
    export_all,
    export_assets_jsonl,
    export_findings_jsonl,
    export_summary_json,
)

# v4.6.20: _extract_title moved to siem.py as extract_finding_title
from redaudit.core.siem import extract_finding_title as _extract_title


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
            self.assertEqual(summary.get("total_findings_raw"), summary.get("total_findings"))

    def test_extract_title_from_observations(self):
        vuln = {"parsed_observations": ["Missing HSTS on endpoint"]}
        self.assertEqual(_extract_title(vuln), "Missing HTTP Strict Transport Security Header")

        vuln = {"parsed_observations": ["Server banner reveals version"], "port": 80}
        self.assertEqual(_extract_title(vuln), "Server Version Disclosed in Banner")

        vuln = {"parsed_observations": ["Detected cve-2024-1234 issue"], "port": 443}
        self.assertEqual(_extract_title(vuln), "Known Vulnerability: CVE-2024-1234")

    def test_extract_title_fallbacks(self):
        # v4.6.19: Updated fallback text from "Web Service" to "HTTP Service"
        vuln = {"port": 443, "url": "https://example.com"}
        self.assertEqual(_extract_title(vuln), "HTTP Service Finding on Port 443")

        vuln = {"port": 22}
        self.assertEqual(_extract_title(vuln), "Service Finding on Port 22")


if __name__ == "__main__":
    unittest.main()


def test_export_summary_chmod_exception():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "summary.json")
        results = {
            "schema_version": "3.1",
            "session_id": "test",
            "summary": {},
            "hosts": [],
            "vulnerabilities": [],
        }

        with patch("os.chmod", side_effect=PermissionError("Access denied")):
            summary = export_summary_json(results, output_path)
            assert summary is not None


def test_extract_title_x_frame_options():
    vuln = {"parsed_observations": ["X-Frame-Options header missing"]}
    title = _extract_title(vuln)
    assert "X-Frame-Options" in title


def test_extract_title_x_content_type():
    vuln = {"parsed_observations": ["X-Content-Type-Options header missing"]}
    title = _extract_title(vuln)
    assert "X-Content-Type" in title


def test_extract_title_cert_expired():
    vuln = {"parsed_observations": ["SSL certificate expired"]}
    title = _extract_title(vuln)
    assert "Expired" in title


def test_extract_title_self_signed():
    vuln = {"parsed_observations": ["Self-signed certificate detected"]}
    title = _extract_title(vuln)
    assert "Self-Signed" in title


def test_extract_title_server_banner():
    vuln = {"parsed_observations": ["Server banner: Apache/2.4.41"]}
    title = _extract_title(vuln)
    assert "Server Version" in title or "Banner" in title


def test_extract_title_fallback_no_url():
    vuln = {"port": 8080}
    title = _extract_title(vuln)
    assert "8080" in title


def test_export_findings_skips_invalid_vuln_list_and_chmod_error(tmp_path):
    results = {
        "hosts": [],
        "vulnerabilities": [{"host": "1.2.3.4", "vulnerabilities": "bad"}],
        "summary": {},
    }
    output_path = tmp_path / "findings.jsonl"
    with patch("os.chmod", side_effect=PermissionError("nope")):
        count = export_findings_jsonl(results, str(output_path))
    assert count == 0
    assert output_path.exists()


def test_export_assets_filters_agentless_and_chmod_error(tmp_path):
    results = {
        "hosts": [
            {
                "ip": "10.0.0.1",
                "hostname": "host",
                "ecs_host": {"mac": ["aa:bb:cc:dd:ee:ff"], "vendor": "Vendor"},
                "agentless_fingerprint": {
                    "domain": "corp",
                    "http_title": "UI",
                    "http_server": "",
                    "device_vendor": "Vendor",
                    "device_type": "router",
                    "smb_signing_required": None,
                },
            }
        ],
        "vulnerabilities": [],
        "summary": {},
    }
    output_path = tmp_path / "assets.jsonl"
    with patch("os.chmod", side_effect=PermissionError("nope")):
        count = export_assets_jsonl(results, str(output_path))
    assert count == 1
    asset = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert "agentless" in asset
    assert asset["agentless"]["domain"] == "corp"
    assert "http_server" not in asset["agentless"]
