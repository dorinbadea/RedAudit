#!/usr/bin/env python3
"""
Supplemental tests for redaudit.core.jsonl_exporter to improve coverage.
Focuses on helper functions and edge cases not covered by main tests.
"""

from redaudit.core.jsonl_exporter import (
    _cvss_to_severity,
    _count_port_evidence_severity,
    _hostname_fallback,
    export_findings_jsonl,
)


def test_cvss_to_severity():
    assert _cvss_to_severity(9.0) == "critical"
    assert _cvss_to_severity(10.0) == "critical"

    assert _cvss_to_severity(7.0) == "high"
    assert _cvss_to_severity(8.9) == "high"

    assert _cvss_to_severity(4.0) == "medium"
    assert _cvss_to_severity(6.9) == "medium"

    assert _cvss_to_severity(0.1) == "low"
    assert _cvss_to_severity(3.9) == "low"

    assert _cvss_to_severity(0.0) == "info"
    assert _cvss_to_severity(-1.0) == "info"


def test_count_port_evidence_severity_complex():
    results = {
        "hosts": [
            {
                "ports": [
                    {
                        "cves": [
                            # Case 1: cvss_severity present
                            {"cve_id": "CVE-1", "cvss_severity": "critical"},
                            # Case 2: numeric score only
                            {"cve_id": "CVE-2", "cvss_score": 5.0},
                            # Case 3: neither present (fallback to medium)
                            {"cve_id": "CVE-3"},
                            # Case 4: Duplicate ID (should be ignored)
                            {"cve_id": "CVE-1", "cvss_severity": "critical"},
                            # Case 5: Garbage severity key but numeric score
                            {"cve_id": "CVE-4", "cvss_severity": "unknown", "cvss_score": 9.5},
                        ],
                        "known_exploits": [
                            "EXP-1",
                            "EXP-1",  # Duplicate
                            None,  # Ignored/Defaulted
                            "",  # Ignored/Defaulted
                        ],
                        "detected_backdoors": [
                            {"cve_id": "BD-1"},
                            {"description": "Backdoor desc"},
                            {"cve_id": "BD-1"},  # Duplicate
                            None,  # Ignored/Defaulted
                        ],
                    }
                ]
            }
        ]
    }

    counts = _count_port_evidence_severity(results)

    # CVE-1: critical (1)
    # CVE-2: medium (1) (5.0 -> medium)
    # CVE-3: medium (1) (fallback)
    # CVE-4: critical (1) (9.5 -> critical) via score fallback?
    # Wait, check logic:
    # if cvss_sev in severity_counts: ...
    # elif isinstance(cvss_score, ...): ...
    # 'unknown' is NOT in severity_counts keys. So it falls to elif.
    # 9.5 -> critical.

    # Exploits:
    # EXP-1: high (1)
    # None -> "EXPLOIT": high (1)
    # "" -> "EXPLOIT": high (already seen, so 0 more)

    # Backdoors:
    # BD-1: critical (1)
    # Desc: critical (1)
    # None -> "BACKDOOR": critical (1)

    # Totals:
    # Critical: CVE-1(1) + CVE-4(1) + BD-1(1) + Desc(1) + None(1) = 5
    # High: EXP-1(1) + Exploit(1) = 2
    # Medium: CVE-2(1) + CVE-3(1) = 2
    # Low: 0
    # Info: 0

    assert counts["critical"] == 5
    assert counts["high"] == 2
    assert counts["medium"] == 2
    assert counts["low"] == 0


def test_hostname_fallback_variants():
    # 1. Direct hostname
    assert _hostname_fallback({"hostname": "foo"}) == "foo"

    # 2. DNS reverse list
    assert _hostname_fallback({"dns": {"reverse": ["bar.com."]}}) == "bar.com"
    # Skip empty in list
    assert _hostname_fallback({"dns": {"reverse": ["", "bar.com"]}}) == "bar.com"

    # 3. Phase0 DNS reverse list
    assert _hostname_fallback({"phase0_enrichment": {"dns_reverse": ["baz.com."]}}) == "baz.com"

    # 4. Phase0 DNS reverse string
    assert _hostname_fallback({"phase0_enrichment": {"dns_reverse": "qux.com."}}) == "qux.com"

    # 5. Empty
    assert _hostname_fallback({}) == ""


def test_export_findings_edge_cases(tmp_path):
    output = tmp_path / "findings.jsonl"
    results = {
        "vulnerabilities": [
            # Case 1: Bad vulns list
            {"host": "1.1.1.1", "vulnerabilities": None},
            # Case 2: Missing source but finding_id present
            {
                "host": "2.2.2.2",
                "vulnerabilities": [
                    {"original_severity": {"tool": "fallback-tool"}, "finding_id": "F1"}
                ],
            },
        ]
    }

    count = export_findings_jsonl(results, str(output))
    assert count == 1

    import json

    with open(output, "r") as f:
        line = json.loads(f.readline())
        assert line["source"] == "fallback-tool"
