#!/usr/bin/env python3
"""
RedAudit - Tests for SIEM enhancement module
v2.9 Professional SIEM integration tests
"""

import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.siem import (
    calculate_severity,
    calculate_risk_score,
    calculate_risk_score_with_breakdown,
    generate_observable_hash,
    generate_host_tags,
    build_ecs_event,
    build_ecs_host,
    enrich_vulnerability_severity,
    enrich_report_for_siem,
    consolidate_findings,
    generate_cef_line,
    _build_evidence_meta,
    extract_finding_title,
    _severity_from_label,
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
        self.assertEqual(result["breakdown"]["max_cvss_source"], "evidence")
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

    def test_calculate_risk_score_breakdown_heuristics(self):
        """Heuristic services should be visible without counting as evidence vulns."""
        host = {"ip": "192.168.1.2", "ports": [{"port": 23, "service": "telnet"}]}
        result = calculate_risk_score_with_breakdown(host)
        breakdown = result["breakdown"]
        self.assertEqual(breakdown["evidence_vulns"], 0)
        self.assertIn("telnet", breakdown["heuristic_flags"])
        self.assertEqual(breakdown["max_cvss_source"], "heuristic")

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

    def test_enrich_report_for_siem_recomputes_risk_after_finding_enrichment(self):
        """Risk should be based on enriched findings even when host has no open ports."""
        results = {
            "hosts": [{"ip": "192.168.1.77", "hostname": "nas", "status": "up", "ports": []}],
            "vulnerabilities": [
                {
                    "host": "192.168.1.77",
                    "vulnerabilities": [
                        {"nikto_findings": ["+ SQL injection possible in /admin.php"]}
                    ],
                }
            ],
            "summary": {"duration": "00:00:10"},
        }

        enriched = enrich_report_for_siem(results, {"scan_mode": "normal"})

        host = enriched["hosts"][0]
        self.assertGreater(host.get("risk_score", 0), 0)
        self.assertEqual(enriched["summary"]["max_risk_score"], host["risk_score"])
        self.assertEqual(enriched["summary"]["high_risk_hosts"], 1)
        self.assertTrue(host.get("findings"))
        self.assertGreater(host["findings"][0].get("normalized_severity", 0), 0)

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

    def test_calculate_severity_no_web_server_found(self):
        """No web server found should be informational."""
        finding = "+ No web server found on 192.168.1.10:55443"
        result = calculate_severity(finding)
        self.assertEqual(result, "info")

    # v4.6.19: Tests for SEVERITY_OVERRIDES patterns
    def test_calculate_severity_etag_inode_leak(self):
        """ETag inode leak should be info, not low."""
        finding = "+ ETag inode leak detected on /index.html"
        result = calculate_severity(finding)
        self.assertEqual(result, "info")

    def test_calculate_severity_xpoweredby_disclosure(self):
        """X-Powered-By disclosure should be info."""
        finding = "+ X-Powered-By: PHP/5.4.0"
        result = calculate_severity(finding)
        self.assertEqual(result, "info")

    def test_calculate_severity_uncommon_header(self):
        """Uncommon header findings should be info."""
        finding = "+ Uncommon header 'x-recruiting' found"
        result = calculate_severity(finding)
        self.assertEqual(result, "info")

    def test_calculate_severity_clickjacking_risk(self):
        """Clickjacking risk should be low, not high."""
        finding = "+ Anti-clickjacking header missing (potential clickjacking)"
        result = calculate_severity(finding)
        self.assertEqual(result, "low")

    def test_calculate_severity_httponly_flag(self):
        """Missing httponly flag should be low."""
        finding = "+ Cookie PHPSESSID created without the httponly flag"
        result = calculate_severity(finding)
        self.assertEqual(result, "low")

    def test_calculate_severity_items_checked(self):
        """Nikto scan summary should be info."""
        finding = "+ 6544 items checked: 0 error(s) and 1 item(s) reported"
        result = calculate_severity(finding)
        self.assertEqual(result, "info")


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


class TestFindingPrioritization(unittest.TestCase):
    """v4.6.19: Tests for finding prioritization fields."""

    def test_confirmed_exploitable_with_cve(self):
        """Findings with CVE IDs should be marked as confirmed_exploitable."""
        vuln = {
            "url": "http://192.168.1.1/",
            "cve_ids": ["CVE-2021-1234"],
            "nikto_findings": ["Some finding"],
        }
        result = enrich_vulnerability_severity(vuln)
        self.assertTrue(result.get("confirmed_exploitable"))

    def test_confirmed_exploitable_with_nuclei(self):
        """Nuclei findings should be marked as confirmed_exploitable."""
        vuln = {
            "source": "nuclei",
            "severity": "high",
            "template_id": "CVE-2012-1823",
        }
        result = enrich_vulnerability_severity(vuln)
        self.assertTrue(result.get("confirmed_exploitable"))

    def test_not_confirmed_exploitable_for_header_finding(self):
        """Header findings without CVE should not be confirmed_exploitable."""
        vuln = {
            "url": "http://192.168.1.1/",
            "nikto_findings": ["Missing X-Frame-Options header"],
        }
        result = enrich_vulnerability_severity(vuln)
        self.assertFalse(result.get("confirmed_exploitable"))

    def test_priority_score_cve_higher_than_header(self):
        """CVE finding should have higher priority than header finding."""
        cve_vuln = {
            "url": "http://192.168.1.1/",
            "cve_ids": ["CVE-2021-1234"],
            "nikto_findings": ["SQL injection CVE-2021-1234"],
        }
        header_vuln = {
            "url": "http://192.168.1.1/",
            "nikto_findings": ["Missing X-Frame-Options header"],
        }
        cve_result = enrich_vulnerability_severity(cve_vuln)
        header_result = enrich_vulnerability_severity(header_vuln)
        self.assertGreater(
            cve_result.get("priority_score", 0),
            header_result.get("priority_score", 0),
        )

    def test_priority_score_penalizes_false_positives(self):
        """Findings with false positives should have reduced priority."""
        fp_vuln = {
            "url": "http://192.168.1.1/",
            "nikto_findings": ["X-Frame-Options header not present"],
            "curl_headers": "X-Frame-Options: DENY",  # Cross-validation proves FP
        }
        result = enrich_vulnerability_severity(fp_vuln)
        # Should have low priority due to false positive detection
        self.assertLess(result.get("priority_score", 100), 50)


class TestGetTopCriticalFindings(unittest.TestCase):
    """v4.6.19: Tests for get_top_critical_findings function."""

    def test_returns_empty_for_empty_list(self):
        """Empty input returns empty list."""
        from redaudit.core.siem import get_top_critical_findings

        result = get_top_critical_findings([])
        self.assertEqual(result, [])

    def test_returns_top_5_by_default(self):
        """Returns at most 5 findings by default."""
        from redaudit.core.siem import get_top_critical_findings

        findings = [
            {"confirmed_exploitable": True, "priority_score": 90, "severity_score": 80}
            for _ in range(10)
        ]
        result = get_top_critical_findings(findings)
        self.assertEqual(len(result), 5)

    def test_sorts_by_priority_score(self):
        """Findings are sorted by priority_score descending."""
        from redaudit.core.siem import get_top_critical_findings

        findings = [
            {"confirmed_exploitable": True, "priority_score": 50, "severity_score": 70},
            {"confirmed_exploitable": True, "priority_score": 90, "severity_score": 70},
            {"confirmed_exploitable": True, "priority_score": 70, "severity_score": 70},
        ]
        result = get_top_critical_findings(findings, limit=3)
        self.assertEqual(result[0]["priority_score"], 90)
        self.assertEqual(result[1]["priority_score"], 70)
        self.assertEqual(result[2]["priority_score"], 50)

    def test_filters_low_severity(self):
        """Only includes high-severity or confirmed_exploitable findings."""
        from redaudit.core.siem import get_top_critical_findings

        findings = [
            {"confirmed_exploitable": False, "priority_score": 30, "severity_score": 30},
            {"confirmed_exploitable": True, "priority_score": 80, "severity_score": 80},
        ]
        result = get_top_critical_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["confirmed_exploitable"])


class TestDetectKnownVulnerableServices(unittest.TestCase):
    """v4.6.19: Tests for detect_known_vulnerable_services function."""

    def test_detects_vsftpd_backdoor(self):
        """Detects vsftpd 2.3.4 backdoor."""
        from redaudit.core.siem import detect_known_vulnerable_services

        banner = "220 (vsFTPd 2.3.4)"
        result = detect_known_vulnerable_services(banner)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2011-2523")
        self.assertEqual(result[0]["severity"], "critical")

    def test_detects_unrealircd_backdoor(self):
        """Detects UnrealIRCd 3.2.8.1 backdoor."""
        from redaudit.core.siem import detect_known_vulnerable_services

        banner = "UnrealIRCd 3.2.8.1"
        result = detect_known_vulnerable_services(banner)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2010-2075")
        self.assertEqual(result[0]["severity"], "critical")

    def test_detects_samba_rce(self):
        """Detects Samba 3.0.x username map script RCE."""
        from redaudit.core.siem import detect_known_vulnerable_services

        banner = "Samba 3.0.20-Debian"
        result = detect_known_vulnerable_services(banner)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2007-2447")

    def test_returns_empty_for_safe_version(self):
        """Safe versions return empty list."""
        from redaudit.core.siem import detect_known_vulnerable_services

        banner = "vsftpd 3.0.3"
        result = detect_known_vulnerable_services(banner)
        self.assertEqual(result, [])

    def test_returns_empty_for_empty_banner(self):
        """Empty banner returns empty list."""
        from redaudit.core.siem import detect_known_vulnerable_services

        result = detect_known_vulnerable_services("")
        self.assertEqual(result, [])

    def test_detects_distcc(self):
        """Detects distcc daemon."""
        from redaudit.core.siem import detect_known_vulnerable_services

        banner = "distccd v1 ((GNU) 4.2.4)"
        result = detect_known_vulnerable_services(banner)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2004-2687")


class TestConfidenceScore(unittest.TestCase):
    """v4.6.19: Tests for confidence_score field."""

    def test_confidence_score_with_cve(self):
        """CVE findings should have high confidence."""
        vuln = {
            "url": "http://192.168.1.1/",
            "cve_ids": ["CVE-2021-1234"],
            "nikto_findings": ["SQL injection CVE-2021-1234"],
        }
        result = enrich_vulnerability_severity(vuln)
        self.assertGreater(result.get("confidence_score", 0), 0.8)

    def test_confidence_score_with_false_positive(self):
        """False positives should have low confidence."""
        vuln = {
            "url": "http://192.168.1.1/",
            "nikto_findings": ["X-Frame-Options header not present"],
            "curl_headers": "X-Frame-Options: DENY",  # Proves FP
        }
        result = enrich_vulnerability_severity(vuln)
        self.assertLess(result.get("confidence_score", 1), 0.3)

    def test_confidence_score_baseline(self):
        """Generic findings should have baseline confidence."""
        vuln = {
            "url": "http://192.168.1.1/",
            "nikto_findings": ["Some generic finding"],
        }
        result = enrich_vulnerability_severity(vuln)
        self.assertEqual(result.get("confidence_score", 0), 0.5)


class TestBackdoorIntegration(unittest.TestCase):
    """v4.6.20: Tests for backdoor detection in calculate_risk_score."""

    def test_vsftpd_backdoor_detected_from_port_data(self):
        """vsftpd 2.3.4 backdoor should be detected from port version field."""
        from redaudit.core.siem import calculate_risk_score

        port = {
            "port": 21,
            "service": "ftp",
            "product": "vsftpd",
            "version": "2.3.4",
        }
        host = {"ports": [port]}
        score = calculate_risk_score(host)
        self.assertEqual(score, 100)
        self.assertIn("detected_backdoors", port)
        self.assertEqual(len(port["detected_backdoors"]), 1)
        self.assertEqual(port["detected_backdoors"][0]["cve_id"], "CVE-2011-2523")

    def test_safe_vsftpd_not_flagged(self):
        """vsftpd 3.0.x should NOT be flagged as backdoor."""
        from redaudit.core.siem import calculate_risk_score

        port = {
            "port": 21,
            "service": "ftp",
            "product": "vsftpd",
            "version": "3.0.5",
        }
        host = {"ports": [port]}
        calculate_risk_score(host)
        self.assertNotIn("detected_backdoors", port)


class TestXFrameOptionsSeverity(unittest.TestCase):
    """v4.6.21: Tests for X-Frame-Options severity override."""

    def test_anti_clickjacking_nikto_text_is_low(self):
        """Nikto anti-clickjacking finding should be low, not high."""
        from redaudit.core.siem import calculate_severity

        finding = "The anti-clickjacking X-Frame-Options header is not present."
        self.assertEqual(calculate_severity(finding), "low")

    def test_missing_x_frame_options_is_low(self):
        """Missing X-Frame-Options should be low."""
        from redaudit.core.siem import calculate_severity

        self.assertEqual(calculate_severity("Missing X-Frame-Options header"), "low")

    def test_x_frame_not_present_is_low(self):
        """X-Frame-Options not present variant should be low."""
        from redaudit.core.siem import calculate_severity

        self.assertEqual(calculate_severity("X-Frame-Options header is not present"), "low")


class TestIoTLwIPRiskCapping(unittest.TestCase):
    """v4.6.21: Tests for IoT lwIP false positive detection."""

    def test_iot_with_many_ports_capped_at_30(self):
        """IoT device with >20 ports should have risk capped at 30 (lwIP false positive)."""
        from redaudit.core.siem import calculate_risk_score

        host = {
            "asset_type": "iot",
            "ports": [{"port": i} for i in range(50)],
        }
        self.assertEqual(calculate_risk_score(host), 30)

    def test_iot_with_few_ports_not_capped(self):
        """IoT device with few ports should calculate normally."""
        from redaudit.core.siem import calculate_risk_score

        host = {
            "asset_type": "iot",
            "ports": [{"port": 80}],
        }
        self.assertEqual(calculate_risk_score(host), 0)

    def test_lwip_os_detected_triggers_cap(self):
        """Device with lwIP in os_detected should be capped."""
        from redaudit.core.siem import calculate_risk_score

        host = {
            "os_detected": "lwIP 1.4.0",
            "ports": [{"port": i} for i in range(25)],
        }
        self.assertEqual(calculate_risk_score(host), 30)


class TestFTPCVEInjection(unittest.TestCase):
    """v4.6.22: Tests for FTP CVE injection to port.cves."""

    def test_vsftpd_backdoor_injects_cve_to_port_cves(self):
        """vsftpd 2.3.4 should inject CVE-2011-2523 into port.cves."""
        from redaudit.core.siem import calculate_risk_score

        port = {
            "port": 21,
            "service": "ftp",
            "product": "vsftpd",
            "version": "2.3.4",
        }
        host = {"ports": [port]}
        calculate_risk_score(host)

        self.assertIn("cves", port)
        cve_ids = [c.get("cve_id") for c in port["cves"]]
        self.assertIn("CVE-2011-2523", cve_ids)

    def test_cve_injection_includes_cvss_score(self):
        """Injected CVE should have CVSS score 9.8."""
        from redaudit.core.siem import calculate_risk_score

        port = {"port": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4"}
        host = {"ports": [port]}
        calculate_risk_score(host)

        cve = next((c for c in port.get("cves", []) if c.get("cve_id") == "CVE-2011-2523"), None)
        self.assertIsNotNone(cve)
        self.assertEqual(cve.get("cvss_score"), 9.8)


class TestSIEMAdditionalCoverage(unittest.TestCase):
    def test_severity_from_label_unknown(self):
        label, score = _severity_from_label("weird")
        self.assertEqual(label, "info")
        self.assertEqual(score, 10)

    def test_generate_descriptive_title_template_ids(self):
        vuln = {"template_id": "CVE-2024-1234"}
        self.assertEqual(extract_finding_title(vuln), "Nuclei: CVE-2024-1234")
        vuln = {"template_id": "test_issue"}
        self.assertEqual(extract_finding_title(vuln), "Nuclei: Test Issue")

    def test_generate_descriptive_title_cve_ids(self):
        vuln = {"cve_ids": ["cve-2020-9999"]}
        self.assertEqual(extract_finding_title(vuln), "Known Vulnerability: CVE-2020-9999")

    def test_generate_descriptive_title_ssl_mismatch(self):
        vuln = {"parsed_observations": ["SSL hostname mismatch detected"], "port": 443}
        self.assertEqual(extract_finding_title(vuln), "SSL Certificate Hostname Mismatch")

    def test_generate_descriptive_title_beast(self):
        vuln = {"parsed_observations": ["BEAST vulnerability observed"]}
        self.assertEqual(extract_finding_title(vuln), "BEAST Vulnerability (SSL/TLS)")

    def test_generate_descriptive_title_poodle(self):
        vuln = {"parsed_observations": ["POODLE attack possible"]}
        self.assertEqual(extract_finding_title(vuln), "POODLE Vulnerability (SSL 3.0)")

    def test_generate_descriptive_title_rfc1918(self):
        vuln = {"parsed_observations": ["rfc-1918 private ip leak"]}
        self.assertEqual(extract_finding_title(vuln), "Internal IP Address Disclosed in Headers")

    def test_generate_descriptive_title_directory_listing(self):
        vuln = {"parsed_observations": ["Directory listing enabled"]}
        self.assertEqual(extract_finding_title(vuln), "Directory Listing Enabled")

    def test_generate_descriptive_title_etag_inode(self):
        vuln = {"parsed_observations": ["ETag inode leakage detected"]}
        self.assertEqual(extract_finding_title(vuln), "ETag Inode Disclosure")

    def test_generate_descriptive_title_dangerous_methods(self):
        vuln = {"parsed_observations": ["PUT method allowed"]}
        self.assertEqual(extract_finding_title(vuln), "Dangerous HTTP Methods Enabled")

    def test_generate_descriptive_title_nikto_fallback(self):
        vuln = {
            "nikto_findings": [
                {"bad": "entry"},
                "Target IP: 1.1.1.1",
                "X" * 90,
            ],
            "port": 80,
        }
        title = extract_finding_title(vuln)
        self.assertTrue(title.endswith("..."))

    def test_generate_descriptive_title_fallback_sources(self):
        vuln = {"source": "testssl", "port": 443}
        self.assertEqual(
            extract_finding_title(vuln),
            "SSL/TLS Configuration Issue on Port 443",
        )
        vuln = {"source": "nikto", "port": 80, "url": "http://example.com"}
        self.assertEqual(
            extract_finding_title(vuln),
            "Web Security Finding on Port 80",
        )

    def test_calculate_severity_empty_keyword(self):
        with patch.dict(
            "redaudit.core.siem.SEVERITY_KEYWORDS",
            {"critical": [""], "high": [], "medium": [], "low": []},
            clear=True,
        ):
            self.assertEqual(calculate_severity("no match"), "info")

    def test_calculate_risk_score_with_breakdown_services(self):
        host = {
            "ip": "192.168.1.1",
            "ports": [
                {"port": 21, "service": "ftp"},
                {"port": 444, "service": "ssl"},
                {"port": 80, "service": "http", "known_exploits": ["CVE-1"]},
            ],
        }
        result = calculate_risk_score_with_breakdown(host)
        self.assertGreater(result["breakdown"]["max_cvss"], 0)

    def test_calculate_risk_score_with_breakdown_normalized(self):
        host = {
            "ip": "192.168.1.1",
            "ports": [{"port": 123, "service": "http"}],
            "findings": [{"severity": "low", "normalized_severity": 9.0}],
        }
        result = calculate_risk_score_with_breakdown(host)
        self.assertEqual(result["breakdown"]["max_cvss"], 9.0)

    def test_generate_host_tags_filtered_and_exploitable(self):
        host = {
            "ip": "192.168.1.1",
            "status": "filtered",
            "ports": [{"port": 80, "service": "http"}],
            "known_exploits": ["CVE-1"],
            "deep_scan": {"mac_address": "AA:BB"},
            "smart_scan": {"deep_scan_executed": True},
        }
        tags = generate_host_tags(host)
        self.assertIn("firewall-protected", tags)
        self.assertIn("exploitable", tags)
        self.assertIn("deep-scanned", tags)
        self.assertIn("mac-identified", tags)

    def test_enrich_vulnerability_severity_explicit(self):
        vuln = {
            "severity": "high",
            "source": "nuclei",
            "name": "SQL injection possible",
        }
        enriched = enrich_vulnerability_severity(vuln, asset_id="asset")
        self.assertEqual(enriched["severity"], "high")
        self.assertEqual(enriched["category"], "vuln")

    def test_enrich_vulnerability_severity_testssl_and_rfc1918(self):
        vuln = {
            "nikto_findings": ["RFC-1918 IP address found in response"],
            "testssl_analysis": {"vulnerabilities": ["BREACH"], "weak_ciphers": ["TLS1.0"]},
            "url": "http://192.168.1.1",
        }
        enriched = enrich_vulnerability_severity(vuln, asset_id="asset")
        self.assertEqual(enriched["severity"], "low")
        self.assertIn("RFC-1918", enriched.get("severity_note", ""))

    def test_enrich_vulnerability_severity_testssl_experimental(self):
        vuln = {
            "source": "testssl",
            "cve_ids": ["CVE-2013-0169"],
            "testssl_analysis": {
                "summary": "CRITICAL: 1 vulnerabilities detected",
                "vulnerabilities": [
                    "LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE"
                ],
            },
        }
        enriched = enrich_vulnerability_severity(vuln, asset_id="asset")
        self.assertFalse(enriched["confirmed_exploitable"])
        self.assertIn("potential_false_positives", enriched)
        self.assertLess(enriched["confidence_score"], 0.7)

    def test_enrich_vulnerability_severity_idempotent_info_score(self):
        vuln = {
            "source": "redaudit",
            "severity": "info",
            "severity_score": 0,
            "normalized_severity": 0.0,
            "name": "Service endpoint discovered",
        }
        first = enrich_vulnerability_severity(vuln, asset_id="asset")
        second = enrich_vulnerability_severity(first, asset_id="asset")
        self.assertEqual(first["severity"], "info")
        self.assertEqual(first["severity_score"], 0)
        self.assertEqual(first["normalized_severity"], 0.0)
        self.assertEqual(second["severity"], "info")
        self.assertEqual(second["severity_score"], 0)
        self.assertEqual(second["normalized_severity"], 0.0)

    def test_enrich_vulnerability_severity_testssl_ambiguous_service_degrades(self):
        vuln = {
            "source": "testssl",
            "cve_ids": ["CVE-2013-0169"],
            "nikto_findings": ["No web server found on target host"],
            "testssl_analysis": {
                "vulnerabilities": ["LUCKY13 (CVE-2013-0169), experimental potentially VULNERABLE"]
            },
        }
        enriched = enrich_vulnerability_severity(vuln, asset_id="asset")
        self.assertEqual(enriched["severity"], "low")
        self.assertEqual(enriched["severity_score"], 30)
        self.assertFalse(enriched["confirmed_exploitable"])
        self.assertFalse(enriched.get("verified", True))
        self.assertIn("potential_false_positives", enriched)
        self.assertLessEqual(enriched["confidence_score"], 0.1)

    def test_enrich_vulnerability_severity_verified_boost(self):
        vuln = {"verified": True}
        enriched = enrich_vulnerability_severity(vuln, asset_id="asset")
        self.assertGreaterEqual(enriched["confidence_score"], 0.5)

    def test_build_evidence_meta_fields(self):
        vuln = {
            "raw_tool_output_ref": "ref.txt",
            "extracted_results": [{"a": 1}],
        }
        meta = _build_evidence_meta(vuln)
        self.assertEqual(meta["raw_output_ref"], "ref.txt")
        self.assertIn("extracted_results", meta["signals"])

    def test_consolidate_findings_merges_ports_and_testssl(self):
        entries = [
            {
                "host": "1.1.1.1",
                "vulnerabilities": [
                    {
                        "descriptive_title": "Issue",
                        "port": 80,
                        "affected_ports": [443],
                        "testssl_analysis": {"summary": "a", "vulnerabilities": ["v1"]},
                    },
                    {
                        "descriptive_title": "Issue",
                        "port": 8080,
                        "affected_ports": [8443],
                        "testssl_analysis": {"summary": "b", "vulnerabilities": ["v2"]},
                    },
                ],
            }
        ]
        consolidated = consolidate_findings(entries)
        vulns = consolidated[0]["vulnerabilities"]
        self.assertEqual(len(vulns), 1)
        self.assertIn(8443, vulns[0]["affected_ports"])
        self.assertIn("summary", vulns[0]["testssl_analysis"])

    def test_generate_cef_line_fields(self):
        host = {
            "ip": "192.168.1.1",
            "hostname": "host",
            "ports": [{"port": 22}],
            "deep_scan": {"mac_address": "AA:BB"},
        }
        line = generate_cef_line(host)
        self.assertIn("src=192.168.1.1", line)
        self.assertIn("shost=host", line)
        self.assertIn("smac=AA:BB", line)

    def test_enrich_report_for_siem_handles_import_error(self):
        report = {"hosts": [{"ip": "1.1.1.1", "ports": []}], "vulnerabilities": []}

        orig_import = __import__

        def _fake_import(name, *args, **kwargs):
            if name == "redaudit.core.evidence_parser":
                raise ImportError("nope")
            return orig_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            with patch("redaudit.core.siem.generate_observable_hash", return_value="hash"):
                enriched = enrich_report_for_siem(report, {})
        self.assertIn("hosts", enriched)


if __name__ == "__main__":
    unittest.main()
