#!/usr/bin/env python3
"""
RedAudit - Tests for SIEM enhancement module
v2.9 Professional SIEM integration tests
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.siem import (
    calculate_severity,
    calculate_risk_score,
    generate_observable_hash,
    generate_host_tags,
    build_ecs_event,
    build_ecs_host,
    enrich_vulnerability_severity,
    enrich_report_for_siem,
    consolidate_findings,
    ECS_VERSION,
)


class TestSIEM(unittest.TestCase):
    """Tests for SIEM enhancement functionality."""

    def test_calculate_severity_critical(self):
        """Test critical severity detection."""
        finding = "+ OSVDB-1234: Remote Code Execution vulnerability found"
        result = calculate_severity(finding)
        self.assertEqual(result, "critical")

    def test_calculate_severity_high(self):
        """Test high severity detection."""
        finding = "+ SQL injection possible in /admin.php"
        result = calculate_severity(finding)
        self.assertEqual(result, "high")

    def test_calculate_severity_medium(self):
        """Test medium severity detection."""
        finding = "+ Weak cipher TLS 1.0 detected"
        result = calculate_severity(finding)
        self.assertEqual(result, "medium")

    def test_calculate_severity_low(self):
        """Test low severity detection."""
        finding = "+ Missing X-Frame-Options header"
        result = calculate_severity(finding)
        self.assertEqual(result, "low")

    def test_calculate_severity_info(self):
        """Test info severity for generic findings."""
        finding = "+ Server banner: Apache/2.4.41"
        result = calculate_severity(finding)
        self.assertEqual(result, "info")

    def test_calculate_severity_rce_false_positive_force(self):
        """Avoid false-positive RCE classification from substring matches (e.g., fo[rce])."""
        finding = "+ No CGI Directories found (use '-C all' to force check all possible dirs)"
        result = calculate_severity(finding)
        self.assertEqual(result, "info")

    def test_calculate_risk_score_empty(self):
        """Test risk score for host with no ports."""
        host = {"ip": "192.168.1.1", "ports": []}
        score = calculate_risk_score(host)
        self.assertEqual(score, 0)

    def test_calculate_risk_score_with_ports(self):
        """Test risk score increases with ports."""
        host = {
            "ip": "192.168.1.1",
            "ports": [
                {"port": 22, "service": "ssh"},
                {"port": 80, "service": "http"},
            ],
        }
        score = calculate_risk_score(host)
        self.assertGreater(score, 0)

    def test_calculate_risk_score_insecure_service(self):
        """Test risk score penalty for insecure services."""
        host_secure = {"ip": "192.168.1.1", "ports": [{"port": 22, "service": "ssh"}]}
        host_insecure = {"ip": "192.168.1.2", "ports": [{"port": 23, "service": "telnet"}]}

        score_secure = calculate_risk_score(host_secure)
        score_insecure = calculate_risk_score(host_insecure)

        self.assertGreater(score_insecure, score_secure)

    def test_calculate_risk_score_with_exploits(self):
        """Test risk score with known exploits."""
        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 80, "service": "http", "known_exploits": ["CVE-2021-1234"]}],
        }
        score = calculate_risk_score(host)
        self.assertGreaterEqual(score, 15)  # At least exploit penalty

    def test_generate_observable_hash(self):
        """Test observable hash generation."""
        host = {
            "ip": "192.168.1.1",
            "hostname": "test.local",
            "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
        }
        hash1 = generate_observable_hash(host)

        # Same host should produce same hash
        hash2 = generate_observable_hash(host)
        self.assertEqual(hash1, hash2)

        # SHA256 should be 64 chars
        self.assertEqual(len(hash1), 64)

    def test_generate_observable_hash_different(self):
        """Test different hosts produce different hashes."""
        host1 = {"ip": "192.168.1.1", "hostname": "", "ports": []}
        host2 = {"ip": "192.168.1.2", "hostname": "", "ports": []}

        hash1 = generate_observable_hash(host1)
        hash2 = generate_observable_hash(host2)

        self.assertNotEqual(hash1, hash2)

    def test_generate_host_tags_web(self):
        """Test tag generation for web server."""
        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 80, "service": "http", "is_web_service": True}],
        }
        tags = generate_host_tags(host)
        self.assertIn("web", tags)
        self.assertIn("http", tags)

    def test_generate_host_tags_database(self):
        """Test tag generation for database server."""
        host = {"ip": "192.168.1.1", "ports": [{"port": 3306, "service": "mysql"}]}
        tags = generate_host_tags(host)
        self.assertIn("database", tags)
        self.assertIn("sql", tags)

    def test_generate_host_tags_deep_scanned(self):
        """Test tag for deep scanned hosts."""
        host = {"ip": "192.168.1.1", "ports": [], "deep_scan": {"mac_address": "AA:BB:CC:DD:EE:FF"}}
        tags = generate_host_tags(host)
        self.assertIn("deep-scanned", tags)
        self.assertIn("mac-identified", tags)

    def test_build_ecs_event(self):
        """Test ECS event object generation."""
        event = build_ecs_event("completo", "00:05:30")

        self.assertIn("ecs", event)
        self.assertEqual(event["ecs"]["version"], ECS_VERSION)
        self.assertIn("event", event)
        self.assertEqual(event["event"]["module"], "redaudit")
        self.assertEqual(event["event"]["action"], "network-scan-completo")

    def test_build_ecs_host(self):
        """Test ECS host object generation."""
        host = {
            "ip": "192.168.1.10",
            "hostname": "server.local",
            "deep_scan": {"mac_address": "AA:BB:CC:DD:EE:FF", "vendor": "Intel"},
        }
        ecs_host = build_ecs_host(host)

        self.assertEqual(ecs_host["ip"], ["192.168.1.10"])
        self.assertEqual(ecs_host["name"], "server.local")
        self.assertEqual(ecs_host["mac"], ["AA:BB:CC:DD:EE:FF"])
        self.assertEqual(ecs_host["vendor"], "Intel")

    def test_enrich_vulnerability_severity(self):
        """Test vulnerability severity enrichment."""
        vuln = {"url": "http://192.168.1.1/", "nikto_findings": ["+ SQL injection in parameter id"]}
        enriched = enrich_vulnerability_severity(vuln)

        self.assertEqual(enriched["severity"], "high")
        self.assertGreaterEqual(enriched["severity_score"], 70)

    def test_enrich_vulnerability_severity_explicit_nuclei(self):
        """Preserve explicit severity for nuclei-like findings."""
        vuln = {
            "source": "nuclei",
            "severity": "high",
            "template_id": "unit-test-template",
            "name": "Unit Test Finding",
        }
        enriched = enrich_vulnerability_severity(vuln)
        self.assertEqual(enriched["severity"], "high")
        self.assertGreaterEqual(enriched["severity_score"], 70)
        self.assertEqual(enriched["original_severity"]["tool"], "nuclei")

    def test_enrich_report_for_siem(self):
        """Test full SIEM report enrichment."""
        results = {
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "hostname": "test",
                    "status": "up",
                    "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
                }
            ],
            "vulnerabilities": [],
            "summary": {"duration": "00:05:00"},
        }
        config = {"scan_mode": "normal"}

        enriched = enrich_report_for_siem(results, config)

        # Check ECS fields
        self.assertIn("ecs", enriched)
        self.assertIn("event", enriched)

        # Check host enrichment
        host = enriched["hosts"][0]
        self.assertIn("ecs_host", host)
        self.assertIn("risk_score", host)
        self.assertIn("observable_hash", host)
        self.assertIn("tags", host)

        # Check summary stats
        summary = enriched.get("summary", {})
        self.assertIn("max_risk_score", summary)
        self.assertIn("avg_risk_score", summary)

    def test_consolidate_findings_preserves_testssl(self):
        """Ensure consolidation keeps testssl analysis from merged entries."""
        vulnerabilities = [
            {
                "host": "192.168.1.10",
                "vulnerabilities": [
                    {
                        "port": 8008,
                        "descriptive_title": "Missing X-Frame-Options header",
                        "severity_score": 30,
                        "nikto_findings": ["Missing X-Frame-Options header"],
                        "parsed_observations": ["Missing X-Frame-Options header"],
                    },
                    {
                        "port": 8443,
                        "descriptive_title": "Missing X-Frame-Options header",
                        "severity_score": 70,
                        "testssl_analysis": {
                            "summary": "CRITICAL: 1 vulnerabilities detected",
                            "vulnerabilities": ["POODLE vulnerability"],
                        },
                    },
                ],
            }
        ]

        merged = consolidate_findings(vulnerabilities)
        merged_vuln = merged[0]["vulnerabilities"][0]
        self.assertIn(8443, merged_vuln.get("affected_ports", []))
        self.assertEqual(merged_vuln.get("severity_score"), 70)
        self.assertIn("testssl_analysis", merged_vuln)


if __name__ == "__main__":
    unittest.main()
