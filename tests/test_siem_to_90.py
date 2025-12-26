"""
Tests for siem.py to push coverage to 90%+.
Targets uncovered lines: 203, 249, 309, 373, 383, 493-508, 579-610, 642-660, 669-676, 734, 738, 792-793, 804-805, 870, 887-891.
"""

from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.siem import (
    classify_finding_category,
    calculate_severity,
    calculate_risk_score,
    generate_host_tags,
    generate_observable_hash,
    generate_finding_id,
    detect_nikto_false_positives,
    enrich_vulnerability_severity,
    generate_cef_line,
    is_rfc1918_address,
    consolidate_findings,
    build_ecs_event,
    build_ecs_host,
    enrich_report_for_siem,
    SEVERITY_LEVELS,
)


# -------------------------------------------------------------------------
# classify_finding_category Tests (line 203)
# -------------------------------------------------------------------------


def test_classify_finding_category_empty_text():
    """Test classify_finding_category with empty text returns surface."""
    result = classify_finding_category("")
    assert result == "surface"


def test_classify_finding_category_none():
    """Test classify_finding_category with None returns surface."""
    result = classify_finding_category(None)
    assert result == "surface"


def test_classify_finding_category_vuln():
    """Test classify_finding_category identifies vuln."""
    result = classify_finding_category("CVE-2021-44228 Log4Shell RCE")
    assert result == "vuln"


def test_classify_finding_category_auth():
    """Test classify_finding_category identifies auth."""
    result = classify_finding_category("Unauthenticated access allowed")
    assert result == "auth"


def test_classify_finding_category_crypto():
    """Test classify_finding_category identifies crypto."""
    result = classify_finding_category("Weak TLS 1.0 cipher detected")
    assert result == "crypto"


# -------------------------------------------------------------------------
# calculate_severity - keyword_matches branches (line 249)
# -------------------------------------------------------------------------


def test_calculate_severity_whitespace_keyword():
    """Test calculate_severity with multi-word keyword."""
    result = calculate_severity("Remote code execution vulnerability found")
    assert result in ["critical", "high"]


def test_calculate_severity_prefix_keyword():
    """Test calculate_severity with prefix keyword like cve-."""
    result = calculate_severity("cve-2021-1234 detected")
    assert result == "high"


def test_calculate_severity_short_acronym():
    """Test calculate_severity with short acronym (RCE)."""
    result = calculate_severity("This is an RCE issue")
    assert result == "critical"


def test_calculate_severity_short_acronym_not_matched():
    """Test calculate_severity doesn't false match on partial words."""
    # "force" contains "rce" but shouldn't match
    result = calculate_severity("This will force the update")
    assert result == "info"


def test_calculate_severity_benign_metadata():
    """Test calculate_severity ignores benign nikto metadata."""
    result = calculate_severity("Target IP: 192.168.1.1")
    assert result == "info"


# -------------------------------------------------------------------------
# calculate_risk_score (line 309)
# -------------------------------------------------------------------------


def test_calculate_risk_score_ssl_nonstandard_port():
    """Test calculate_risk_score adds points for SSL on non-standard port."""
    host = {
        "ports": [
            {"port": 9443, "service": "ssl/http"},  # Not 443 or 8443
        ]
    }
    score = calculate_risk_score(host)
    assert score >= 2  # At least port points


def test_calculate_risk_score_insecure_service():
    """Test calculate_risk_score adds points for insecure services."""
    host = {
        "ports": [
            {"port": 23, "service": "telnet"},
        ]
    }
    score = calculate_risk_score(host)
    assert score >= 12  # 2 for port + 10 for telnet


def test_calculate_risk_score_with_exploits():
    """Test calculate_risk_score adds points for exploits."""
    host = {
        "ports": [
            {"port": 22, "service": "ssh", "known_exploits": ["exploit1", "exploit2"]},
        ]
    }
    score = calculate_risk_score(host)
    assert score >= 30  # 2 for port + 30 for exploits


# -------------------------------------------------------------------------
# generate_host_tags (lines 373, 383)
# -------------------------------------------------------------------------


def test_generate_host_tags_filtered_status():
    """Test generate_host_tags adds firewall-protected tag for filtered status."""
    host = {"status": "filtered", "ports": []}
    tags = generate_host_tags(host)
    assert "firewall-protected" in tags


def test_generate_host_tags_exploitable():
    """Test generate_host_tags adds exploitable tag."""
    host = {"ports": [], "known_exploits": [{"name": "EternalBlue"}]}
    tags = generate_host_tags(host)
    assert "exploitable" in tags


def test_generate_host_tags_deep_scan_with_mac():
    """Test generate_host_tags adds mac-identified for deep scan with MAC."""
    host = {"ports": [], "deep_scan": {"mac_address": "AA:BB:CC:DD:EE:FF"}}
    tags = generate_host_tags(host)
    assert "deep-scanned" in tags
    assert "mac-identified" in tags


# -------------------------------------------------------------------------
# detect_nikto_false_positives (lines 493-508)
# -------------------------------------------------------------------------


def test_detect_nikto_false_positives_xcto():
    """Test detect_nikto_false_positives detects X-Content-Type-Options FP."""
    vuln = {
        "nikto_findings": ["X-Content-Type-Options header is not set"],
        "curl_headers": "x-content-type-options: nosniff\n",
    }
    fps = detect_nikto_false_positives(vuln)
    assert len(fps) >= 1
    assert any("X-Content-Type-Options" in fp for fp in fps)


def test_detect_nikto_false_positives_xfo():
    """Test detect_nikto_false_positives detects X-Frame-Options FP."""
    vuln = {
        "nikto_findings": ["X-Frame-Options header is not present"],
        "wget_headers": "x-frame-options: DENY\n",
    }
    fps = detect_nikto_false_positives(vuln)
    assert len(fps) >= 1
    assert any("X-Frame-Options" in fp for fp in fps)


def test_detect_nikto_false_positives_hsts():
    """Test detect_nikto_false_positives detects HSTS FP."""
    vuln = {
        "nikto_findings": ["Strict-Transport-Security header is not defined"],
        "curl_headers": "strict-transport-security: max-age=31536000\n",
    }
    fps = detect_nikto_false_positives(vuln)
    assert len(fps) >= 1
    assert any("HSTS" in fp for fp in fps)


def test_detect_nikto_false_positives_no_headers():
    """Test detect_nikto_false_positives returns empty when no headers."""
    vuln = {"nikto_findings": ["X-Frame-Options not present"]}
    fps = detect_nikto_false_positives(vuln)
    assert fps == []


# -------------------------------------------------------------------------
# enrich_vulnerability_severity - testssl branches (lines 579-610)
# -------------------------------------------------------------------------


def test_enrich_vuln_testssl_vulnerabilities():
    """Test enrich_vulnerability_severity with testssl vulnerabilities."""
    vuln = {
        "testssl_analysis": {
            "vulnerabilities": ["POODLE", "BEAST"],
        }
    }
    enriched = enrich_vulnerability_severity(vuln)
    assert enriched["severity"] == "high"
    assert enriched["severity_score"] >= 70
    assert "crypto" in enriched["category"]


def test_enrich_vuln_testssl_weak_ciphers():
    """Test enrich_vulnerability_severity with testssl weak ciphers."""
    vuln = {
        "testssl_analysis": {
            "weak_ciphers": ["RC4", "DES"],
        }
    }
    enriched = enrich_vulnerability_severity(vuln)
    assert enriched["severity_score"] >= 50
    assert "crypto" in enriched["category"]


def test_enrich_vuln_rfc1918_adjustment():
    """Test enrich_vulnerability_severity adjusts RFC-1918 findings."""
    vuln = {
        "nikto_findings": ["RFC-1918 IP address found in /admin"],
        "url": "http://192.168.1.1/admin",
    }
    enriched = enrich_vulnerability_severity(vuln)
    # RFC-1918 on private network should be low/info
    assert enriched["severity"] in ["low", "info"]


def test_enrich_vuln_false_positive_degradation():
    """Test enrich_vulnerability_severity degrades severity for false positives."""
    vuln = {
        "nikto_findings": ["X-Frame-Options header is not present"],
        "curl_headers": "x-frame-options: DENY\n",
    }
    enriched = enrich_vulnerability_severity(vuln)
    assert enriched.get("verified") is False
    # Primary finding was FP'd header, should be degraded
    assert enriched["severity"] == "info"


def test_enrich_vuln_cve_parsing():
    """Test enrich_vulnerability_severity parses CVE from finding."""
    vuln = {
        "nikto_findings": ["CVE-2021-44228 Log4Shell detected"],
    }
    enriched = enrich_vulnerability_severity(vuln)
    # Should extract CVE as signature
    assert "finding_id" in enriched
    assert len(enriched["finding_id"]) == 32


def test_enrich_vuln_explicit_severity():
    """Test enrich_vulnerability_severity uses explicit severity when no tool findings."""
    vuln = {
        "severity": "critical",
        "source": "nuclei",
        "descriptive_title": "SQL Injection",
    }
    enriched = enrich_vulnerability_severity(vuln)
    assert enriched["severity"] == "critical"
    assert enriched["severity_score"] == 90


# -------------------------------------------------------------------------
# generate_cef_line (lines 734, 738)
# -------------------------------------------------------------------------


def test_generate_cef_line_with_hostname():
    """Test generate_cef_line includes hostname."""
    host = {
        "ip": "192.168.1.1",
        "hostname": "router.local",
        "ports": [{"port": 22}],
        "status": "up",
    }
    cef = generate_cef_line(host)
    assert "CEF:0|" in cef
    assert "shost=router.local" in cef


def test_generate_cef_line_with_mac():
    """Test generate_cef_line includes MAC address."""
    host = {
        "ip": "192.168.1.1",
        "ports": [],
        "deep_scan": {"mac_address": "AA:BB:CC:DD:EE:FF"},
    }
    cef = generate_cef_line(host)
    assert "smac=AA:BB:CC:DD:EE:FF" in cef


# -------------------------------------------------------------------------
# consolidate_findings (lines 870, 887-891)
# -------------------------------------------------------------------------


def test_consolidate_findings_empty():
    """Test consolidate_findings with empty list."""
    result = consolidate_findings([])
    assert result == []


def test_consolidate_findings_merges_same_title():
    """Test consolidate_findings merges findings with same title."""
    vulns = [
        {
            "host": "192.168.1.1",
            "vulnerabilities": [
                {"descriptive_title": "Missing HSTS", "port": 80},
                {"descriptive_title": "Missing HSTS", "port": 443},
                {"descriptive_title": "Missing HSTS", "port": 8080},
            ],
        }
    ]
    result = consolidate_findings(vulns)
    assert len(result) == 1
    assert len(result[0]["vulnerabilities"]) == 1
    merged = result[0]["vulnerabilities"][0]
    assert "affected_ports" in merged
    assert set(merged["affected_ports"]) == {80, 443, 8080}
    assert merged["consolidated_count"] == 3


def test_consolidate_findings_preserves_single():
    """Test consolidate_findings preserves single findings."""
    vulns = [
        {
            "host": "192.168.1.1",
            "vulnerabilities": [
                {"descriptive_title": "Unique Issue", "port": 80},
            ],
        }
    ]
    result = consolidate_findings(vulns)
    assert len(result) == 1
    assert len(result[0]["vulnerabilities"]) == 1
    assert "affected_ports" not in result[0]["vulnerabilities"][0]


def test_consolidate_findings_nuclei_source():
    """Test consolidate_findings handles nuclei source differently."""
    vulns = [
        {
            "host": "192.168.1.1",
            "vulnerabilities": [
                {"descriptive_title": "XSS", "port": 80, "source": "nuclei", "matched_at": "/a"},
                {"descriptive_title": "XSS", "port": 80, "source": "nuclei", "matched_at": "/b"},
            ],
        }
    ]
    result = consolidate_findings(vulns)
    # Should NOT merge because matched_at differs
    assert len(result[0]["vulnerabilities"]) == 2


# -------------------------------------------------------------------------
# Additional coverage tests
# -------------------------------------------------------------------------


def test_is_rfc1918_private():
    """Test is_rfc1918_address with private IP."""
    assert is_rfc1918_address("192.168.1.1") is True
    assert is_rfc1918_address("10.0.0.1") is True
    assert is_rfc1918_address("172.16.0.1") is True


def test_is_rfc1918_public():
    """Test is_rfc1918_address with public IP."""
    assert is_rfc1918_address("8.8.8.8") is False


def test_is_rfc1918_invalid():
    """Test is_rfc1918_address with invalid IP."""
    assert is_rfc1918_address("not-an-ip") is False


def test_build_ecs_host_with_deep_scan():
    """Test build_ecs_host includes deep scan info."""
    host = {
        "ip": "192.168.1.1",
        "hostname": "server.local",
        "deep_scan": {
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "vendor": "Cisco",
        },
    }
    ecs = build_ecs_host(host)
    assert ecs["mac"] == ["AA:BB:CC:DD:EE:FF"]
    assert ecs["vendor"] == "Cisco"


def test_enrich_report_for_siem():
    """Test enrich_report_for_siem adds all expected fields."""
    results = {
        "hosts": [
            {"ip": "192.168.1.1", "ports": [{"port": 22, "service": "ssh"}]},
        ],
        "vulnerabilities": [],
        "summary": {"duration": "5m"},
    }
    config = {"scan_mode": "normal"}

    enriched = enrich_report_for_siem(results, config)

    assert "schema_version" in enriched
    assert "ecs" in enriched
    assert enriched["hosts"][0].get("risk_score") is not None
    assert enriched["hosts"][0].get("observable_hash") is not None
    assert enriched["hosts"][0].get("tags") is not None
