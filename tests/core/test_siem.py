#!/usr/bin/env python3
"""
RedAudit - Tests for SIEM enhancement module
v2.9 Professional SIEM integration tests
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

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
        """Test risk score with exposed ports and CVEs.

        v4.3: New algorithm returns 0 for ports without vulnerabilities.
        Score only increases with CVEs, exploits, or insecure services.
        """
        # Ports without CVEs = low risk (score 0 is intentional)
        host_clean = {
            "ip": "192.168.1.1",
            "ports": [
                {"port": 22, "service": "ssh"},
                {"port": 80, "service": "http"},
            ],
        }
        score_clean = calculate_risk_score(host_clean)
        self.assertEqual(score_clean, 0)

        # Ports with CVE data should have score > 0
        host_with_cve = {
            "ip": "192.168.1.1",
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "cves": [{"cve_id": "CVE-2021-1234", "cvss_score": 7.5}],
                },
            ],
        }
        score_with_cve = calculate_risk_score(host_with_cve)
        self.assertGreater(score_with_cve, 0)

    def test_calculate_risk_score_insecure_service(self):
        """Test risk score penalty for insecure services."""
        host_secure = {"ip": "192.168.1.1", "ports": [{"port": 22, "service": "ssh"}]}
        host_insecure = {"ip": "192.168.1.2", "ports": [{"port": 23, "service": "telnet"}]}

        score_secure = calculate_risk_score(host_secure)
        score_insecure = calculate_risk_score(host_insecure)

        self.assertGreater(score_insecure, score_secure)

    def test_calculate_risk_score_with_breakdown(self):
        """Test that calculate_risk_score_with_breakdown returns score and breakdown."""
        host = {
            "ip": "192.168.1.1",
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "cves": [{"cve_id": "CVE-2021-1234", "cvss_score": 8.5}],
                },
                {"port": 22, "service": "ssh"},
            ],
        }
        result = calculate_risk_score(host)
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)

    def test_calculate_risk_score_with_breakdown_details(self):
        """Test that breakdown contains expected fields."""
        from redaudit.core.siem import calculate_risk_score_with_breakdown

        host = {
            "ip": "192.168.1.1",
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "cves": [{"cve_id": "CVE-2021-1234", "cvss_score": 9.8}],
                },
            ],
        }
        result = calculate_risk_score_with_breakdown(host)

        self.assertIn("score", result)
        self.assertIn("breakdown", result)
        self.assertEqual(result["breakdown"]["max_cvss"], 9.8)
        self.assertEqual(result["breakdown"]["exposure_multiplier"], 1.15)
        self.assertTrue(result["breakdown"]["has_exposed_port"])
        self.assertGreater(result["score"], 0)

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

    def test_generate_host_tags_web_ports_count(self):
        """Test tag generation when web_ports_count is present."""
        host = {
            "ip": "192.168.1.10",
            "ports": [],
            "web_ports_count": 1,
        }
        tags = generate_host_tags(host)
        self.assertIn("web", tags)

    def test_generate_host_tags_database(self):
        """Test tag generation for database server."""
        host = {"ip": "192.168.1.1", "ports": [{"port": 3306, "service": "mysql"}]}
        tags = generate_host_tags(host)
        self.assertIn("database", tags)
        self.assertIn("sql", tags)

    def test_generate_host_tags_deep_scanned(self):
        """Test tag for deep scanned hosts."""
        # v4.5.16: deep-scanned tag requires smart_scan.deep_scan_executed=True
        host = {
            "ip": "192.168.1.1",
            "ports": [],
            "deep_scan": {"mac_address": "AA:BB:CC:DD:EE:FF"},
            "smart_scan": {"deep_scan_executed": True},
        }
        tags = generate_host_tags(host)
        self.assertIn("deep-scanned", tags)
        self.assertIn("mac-identified", tags)

    def test_generate_host_tags_deep_scanned_not_executed(self):
        """v4.5.16: Test tag NOT added when deep scan was not executed."""
        # deep_scan dict exists but deep_scan_executed is False
        host = {
            "ip": "192.168.1.1",
            "ports": [],
            "deep_scan": {"mac_address": "AA:BB:CC:DD:EE:FF"},
            "smart_scan": {"deep_scan_executed": False},
        }
        tags = generate_host_tags(host)
        self.assertNotIn("deep-scanned", tags)
        # mac-identified also requires deep_scan_executed
        self.assertNotIn("mac-identified", tags)

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

    def test_calculate_risk_score_with_unattached_findings(self):
        """Test risk score calculation from general findings list (v4.3.1)."""
        host = {
            "ip": "10.0.0.1",
            "ports": [],
            "findings": [
                {"severity": "critical", "name": "Finding 1"},
                {"severity": "medium", "name": "Finding 2"},
            ],
        }
        score = calculate_risk_score(host)
        # Critical = 9.5 -> Base ~95
        self.assertGreater(score, 90)

    def test_calculate_severity_empty_string(self):
        """Test severity returns info for empty finding."""
        result = calculate_severity("")
        self.assertEqual(result, "info")

    def test_calculate_severity_none(self):
        """Test severity returns info for None finding."""
        result = calculate_severity(None)
        self.assertEqual(result, "info")

    def test_calculate_severity_benign_nikto_metadata(self):
        """Test severity ignores Nikto metadata lines."""
        finding = "+ Target IP: 192.168.1.1"
        result = calculate_severity(finding)
        self.assertEqual(result, "info")

        finding2 = "+ Start Time: 2024-01-01 12:00:00"
        result2 = calculate_severity(finding2)
        self.assertEqual(result2, "info")


class TestClassifyFindingCategory(unittest.TestCase):
    """Tests for classify_finding_category function."""

    def test_classify_empty_returns_surface(self):
        """Empty text returns surface category."""
        from redaudit.core.siem import classify_finding_category

        result = classify_finding_category("")
        self.assertEqual(result, "surface")

        result_none = classify_finding_category(None)
        self.assertEqual(result_none, "surface")

    def test_classify_vuln_category(self):
        """Vulnerability keywords return vuln category."""
        from redaudit.core.siem import classify_finding_category

        result = classify_finding_category("CVE-2021-12345 SQL injection")
        self.assertEqual(result, "vuln")

    def test_classify_auth_category(self):
        """Authentication keywords return auth category."""
        from redaudit.core.siem import classify_finding_category

        result = classify_finding_category("default credentials detected")
        self.assertEqual(result, "auth")

    def test_classify_crypto_category(self):
        """Crypto keywords return crypto category."""
        from redaudit.core.siem import classify_finding_category

        result = classify_finding_category("weak cipher suite detected")
        self.assertEqual(result, "crypto")


class TestIsRfc1918Address(unittest.TestCase):
    """Tests for is_rfc1918_address function."""

    def test_private_10_network(self):
        """10.x.x.x is RFC-1918 private."""
        from redaudit.core.siem import is_rfc1918_address

        result = is_rfc1918_address("10.0.0.1")
        self.assertTrue(result)

    def test_private_172_network(self):
        """172.16.x.x is RFC-1918 private."""
        from redaudit.core.siem import is_rfc1918_address

        result = is_rfc1918_address("172.16.0.1")
        self.assertTrue(result)

    def test_private_192_network(self):
        """192.168.x.x is RFC-1918 private."""
        from redaudit.core.siem import is_rfc1918_address

        result = is_rfc1918_address("192.168.1.1")
        self.assertTrue(result)

    def test_public_address(self):
        """Public IP is not RFC-1918."""
        from redaudit.core.siem import is_rfc1918_address

        result = is_rfc1918_address("8.8.8.8")
        self.assertFalse(result)

    def test_invalid_address(self):
        """Invalid IP returns False."""
        from redaudit.core.siem import is_rfc1918_address

        result = is_rfc1918_address("not-an-ip")
        self.assertFalse(result)


class TestDetectNiktoFalsePositives(unittest.TestCase):
    """Tests for detect_nikto_false_positives function."""

    def test_no_headers_returns_empty(self):
        """Returns empty when no headers available."""
        from redaudit.core.siem import detect_nikto_false_positives

        vuln = {"nikto_findings": ["X-Content-Type-Options not set"]}
        result = detect_nikto_false_positives(vuln)
        self.assertEqual(result, [])

    def test_detects_xcto_false_positive(self):
        """Detects X-Content-Type-Options false positive."""
        from redaudit.core.siem import detect_nikto_false_positives

        vuln = {
            "nikto_findings": ["X-Content-Type-Options header not set"],
            "curl_headers": "X-Content-Type-Options: nosniff",
        }
        result = detect_nikto_false_positives(vuln)
        self.assertEqual(len(result), 1)
        self.assertIn("X-Content-Type-Options", result[0])

    def test_detects_xfo_false_positive(self):
        """Detects X-Frame-Options false positive."""
        from redaudit.core.siem import detect_nikto_false_positives

        vuln = {
            "nikto_findings": ["X-Frame-Options header not present"],
            "wget_headers": "X-Frame-Options: DENY",
        }
        result = detect_nikto_false_positives(vuln)
        self.assertEqual(len(result), 1)
        self.assertIn("X-Frame-Options", result[0])

    def test_detects_hsts_false_positive(self):
        """Detects HSTS false positive."""
        from redaudit.core.siem import detect_nikto_false_positives

        vuln = {
            "nikto_findings": ["Strict-Transport-Security header not defined"],
            "curl_headers": "Strict-Transport-Security: max-age=31536000",
        }
        result = detect_nikto_false_positives(vuln)
        self.assertEqual(len(result), 1)
        self.assertIn("HSTS", result[0])


class TestGenerateCefLine(unittest.TestCase):
    """Tests for generate_cef_line function."""

    def test_basic_cef_generation(self):
        """Generates valid CEF line."""
        from redaudit.core.siem import generate_cef_line

        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 22}, {"port": 80}],
            "status": "completed",
        }
        result = generate_cef_line(host)
        self.assertTrue(result.startswith("CEF:0|"))
        self.assertIn("src=192.168.1.1", result)
        self.assertIn("spt=2", result)
        self.assertIn("cs1=completed", result)

    def test_cef_with_hostname(self):
        """CEF includes hostname when available."""
        from redaudit.core.siem import generate_cef_line

        host = {
            "ip": "192.168.1.1",
            "hostname": "testhost.local",
            "ports": [],
            "status": "completed",
        }
        result = generate_cef_line(host)
        self.assertIn("shost=testhost.local", result)

    def test_cef_with_mac_address(self):
        """CEF includes MAC when available in deep_scan."""
        from redaudit.core.siem import generate_cef_line

        host = {
            "ip": "192.168.1.1",
            "ports": [],
            "status": "up",
            "deep_scan": {"mac_address": "AA:BB:CC:DD:EE:FF"},
        }
        result = generate_cef_line(host)
        self.assertIn("smac=AA:BB:CC:DD:EE:FF", result)


class TestRiskScoreEdgeCases(unittest.TestCase):
    """Tests for calculate_risk_score edge cases."""

    def test_risk_score_telnet_service(self):
        """Telnet service increases risk score."""
        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 23, "service": "telnet"}],
        }
        score = calculate_risk_score(host)
        # Telnet = 9.0 CVSS -> Base ~90
        self.assertGreaterEqual(score, 90)

    def test_risk_score_ftp_service(self):
        """FTP service increases risk score."""
        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 21, "service": "ftp"}],
        }
        score = calculate_risk_score(host)
        # FTP = 7.5 CVSS -> Base ~75
        self.assertGreaterEqual(score, 70)

    def test_risk_score_ssl_on_non_standard_port(self):
        """SSL on non-standard port increases risk."""
        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 8080, "service": "ssl/http"}],
        }
        score = calculate_risk_score(host)
        # Should have some risk for non-standard SSL
        self.assertGreater(score, 0)

    def test_risk_score_with_known_exploits(self):
        """Known exploits increase risk score."""
        host = {
            "ip": "192.168.1.1",
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "known_exploits": ["exploit-1", "exploit-2"],
                }
            ],
        }
        score = calculate_risk_score(host)
        # Exploits = 8.0 CVSS
        self.assertGreaterEqual(score, 75)

    def test_risk_score_findings_with_normalized_severity(self):
        """Findings with normalized_severity override severity string."""
        host = {
            "ip": "192.168.1.1",
            "ports": [],
            "findings": [
                {"severity": "low", "normalized_severity": 9.5, "name": "Critical finding"},
            ],
        }
        score = calculate_risk_score(host)
        # normalized_severity 9.5 should give high score (~95)
        self.assertGreaterEqual(score, 90)


class TestEnrichVulnerabilityFalsePositives(unittest.TestCase):
    """Tests for false positive detection in enrich_vulnerability_severity."""

    def test_enrich_degrades_severity_on_header_fp(self):
        """Should degrade severity when cross-validation detects false positive."""
        vuln = {
            "nikto_findings": ["Missing X-Frame-Options header not present"],
            "curl_headers": "X-Frame-Options: DENY",
            "port": 80,
        }
        result = enrich_vulnerability_severity(vuln, asset_id="test123")
        # Should detect FP and degrade to info
        self.assertEqual(result.get("severity"), "info")
        self.assertIn("potential_false_positives", result)

    def test_enrich_empty_category_returns_surface(self):
        """Empty vuln_record gets surface category."""
        vuln = {"port": 80}
        result = enrich_vulnerability_severity(vuln, asset_id="test123")
        self.assertEqual(result.get("category"), "surface")


class TestCalculateRiskScoreWithBreakdown(unittest.TestCase):
    """Tests for calculate_risk_score_with_breakdown function."""

    def test_breakdown_returns_dict_with_components(self):
        """Should return score plus breakdown details."""
        from redaudit.core.siem import calculate_risk_score_with_breakdown

        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 23, "service": "telnet"}],
        }
        result = calculate_risk_score_with_breakdown(host)
        self.assertIn("score", result)
        self.assertIn("breakdown", result)
        self.assertIn("max_cvss", result["breakdown"])
        self.assertIn("base_score", result["breakdown"])
        self.assertIn("exposure_multiplier", result["breakdown"])

    def test_breakdown_with_findings(self):
        """Processes findings in breakdown calculation."""
        from redaudit.core.siem import calculate_risk_score_with_breakdown

        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 80, "service": "http"}],
            "findings": [
                {"severity": "critical", "name": "Finding 1"},
                {"severity": "high", "name": "Finding 2"},
            ],
        }
        result = calculate_risk_score_with_breakdown(host)
        # Breakdown should include findings processing
        self.assertIn("score", result)
        self.assertIn("breakdown", result)
        self.assertIn("total_vulns", result["breakdown"])

    def test_breakdown_exposure_multiplier_on_common_ports(self):
        """Exposure multiplier applied for external-facing ports."""
        from redaudit.core.siem import calculate_risk_score_with_breakdown

        host = {
            "ip": "192.168.1.1",
            "ports": [
                {"port": 80, "service": "http", "cves": [{"cve_id": "CVE-1", "cvss_score": 7.0}]},
            ],
        }
        result = calculate_risk_score_with_breakdown(host)
        # Port 80 is external-facing
        self.assertEqual(result["breakdown"]["exposure_multiplier"], 1.15)


class TestGenerateHostTagsEdgeCases(unittest.TestCase):
    """Edge case tests for generate_host_tags."""

    def test_tags_with_asset_type(self):
        """Tags include asset type tags."""
        host = {"ip": "192.168.1.1", "ports": []}
        tags = generate_host_tags(host, asset_type="router")
        self.assertIn("network", tags)
        self.assertIn("infrastructure", tags)

    def test_tags_with_rdp_service(self):
        """RDP service adds admin tag."""
        host = {"ip": "192.168.1.1", "ports": [{"port": 3389, "service": "rdp"}]}
        tags = generate_host_tags(host)
        self.assertIn("remote-access", tags)


class TestGenerateFindingId(unittest.TestCase):
    """Tests for generate_finding_id function."""

    def test_finding_id_is_deterministic(self):
        """Same inputs produce same finding_id."""
        from redaudit.core.siem import generate_finding_id

        id1 = generate_finding_id(
            asset_id="abc123",
            scanner="nikto",
            port=80,
            protocol="tcp",
            signature="CVE-2021-1234",
            title="Test Finding",
        )
        id2 = generate_finding_id(
            asset_id="abc123",
            scanner="nikto",
            port=80,
            protocol="tcp",
            signature="CVE-2021-1234",
            title="Test Finding",
        )
        self.assertEqual(id1, id2)

    def test_finding_id_different_inputs(self):
        """Different inputs produce different finding_id."""
        from redaudit.core.siem import generate_finding_id

        id1 = generate_finding_id("a", "nikto", 80, "tcp", "sig1", "title")
        id2 = generate_finding_id("b", "nikto", 80, "tcp", "sig1", "title")
        self.assertNotEqual(id1, id2)


if __name__ == "__main__":
    unittest.main()
