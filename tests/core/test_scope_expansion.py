#!/usr/bin/env python3

from redaudit.core.scope_expansion import (
    build_leak_follow_targets,
    evaluate_leak_follow_candidates,
    extract_leak_follow_candidates,
)


def test_extract_leak_follow_candidates_from_http_evidence():
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.10",
                "vulnerabilities": [
                    {"redirect_url": "http://10.10.10.5/login"},
                    {"curl_headers": "Location: https://internal-gw.local/welcome"},
                    {"nikto_findings": ["redirect http://172.16.1.9/admin"]},
                ],
            }
        ]
    }

    candidates = extract_leak_follow_candidates(results)
    values = {(c["candidate"], c["kind"], c["source_field"]) for c in candidates}

    assert ("10.10.10.5", "ip", "redirect_url") in values
    assert ("172.16.1.9", "ip", "nikto_findings") in values
    assert ("internal-gw.local", "host", "curl_headers") in values


def test_extract_leak_follow_candidates_deduplicates_and_skips_source_host():
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.10",
                "vulnerabilities": [
                    {"redirect_url": "http://192.168.1.10/path"},
                    {"redirect_url": "http://10.0.0.20/path"},
                    {"curl_headers": "Location: http://10.0.0.20/path"},
                ],
            }
        ]
    }

    candidates = extract_leak_follow_candidates(results)
    matches = [c for c in candidates if c["candidate"] == "10.0.0.20"]
    source_self = [c for c in candidates if c["candidate"] == "192.168.1.10"]

    assert len(matches) == 2  # redirect_url + curl_headers
    assert source_self == []


def test_extract_leak_follow_candidates_handles_invalid_payloads():
    assert extract_leak_follow_candidates({"vulnerabilities": "bad"}) == []
    assert (
        extract_leak_follow_candidates({"vulnerabilities": [None, {"vulnerabilities": "x"}]}) == []
    )


def test_evaluate_leak_follow_candidates_mode_off():
    payload = evaluate_leak_follow_candidates(
        [
            {"candidate": "10.0.0.5", "kind": "ip", "source_host": "10.0.0.1", "source_field": "x"},
            {
                "candidate": "internal.local",
                "kind": "host",
                "source_host": "10.0.0.1",
                "source_field": "x",
            },
        ],
        mode="off",
        target_networks=["10.0.0.0/24"],
        allowlist=[],
    )

    assert payload["mode"] == "off"
    assert payload["detected"] == 2
    assert payload["eligible"] == 0
    assert payload["followed"] == 0
    assert payload["skipped"] == 2
    assert all(d["reason"] == "mode_off" for d in payload["decisions"])


def test_evaluate_leak_follow_candidates_safe_with_scope_and_allowlist():
    payload = evaluate_leak_follow_candidates(
        [
            {"candidate": "10.0.0.5", "kind": "ip", "source_host": "10.0.0.1", "source_field": "x"},
            {"candidate": "10.1.0.3", "kind": "ip", "source_host": "10.0.0.1", "source_field": "x"},
            {
                "candidate": "internal.local",
                "kind": "host",
                "source_host": "10.0.0.1",
                "source_field": "x",
            },
            {"candidate": "8.8.8.8", "kind": "ip", "source_host": "10.0.0.1", "source_field": "x"},
            {
                "candidate": "other.local",
                "kind": "host",
                "source_host": "10.0.0.1",
                "source_field": "x",
            },
            {
                "candidate": "not-an-ip",
                "kind": "ip",
                "source_host": "10.0.0.1",
                "source_field": "x",
            },
            {"candidate": "x", "kind": "other", "source_host": "10.0.0.1", "source_field": "x"},
        ],
        mode="safe",
        target_networks=["10.0.0.0/24"],
        allowlist=["10.1.0.0/24", "internal.local"],
    )

    reasons = {d["candidate"]: d["reason"] for d in payload["decisions"]}

    assert payload["mode"] == "safe"
    assert payload["detected"] == 7
    assert payload["eligible"] == 3
    assert payload["skipped"] == 4
    assert reasons["10.0.0.5"] == "in_scope"
    assert reasons["10.1.0.3"] == "allowlisted"
    assert reasons["internal.local"] == "allowlisted_host"
    assert reasons["8.8.8.8"] == "public_candidate"
    assert reasons["other.local"] == "hostname_not_allowlisted"
    assert reasons["not-an-ip"] == "invalid_candidate"
    assert reasons["x"] == "unknown_kind"
    assert payload["accepted_candidates"] == ["10.0.0.5", "10.1.0.3", "internal.local"]


def test_evaluate_leak_follow_candidates_invalid_mode_falls_back_to_off():
    payload = evaluate_leak_follow_candidates(
        [{"candidate": "10.0.0.5", "kind": "ip", "source_host": "10.0.0.1", "source_field": "x"}],
        mode="bad",
        target_networks=["10.0.0.0/24"],
        allowlist=[],
    )

    assert payload["mode"] == "off"
    assert payload["decisions"][0]["reason"] == "mode_off"


def test_build_leak_follow_targets_defaults_and_dedup():
    targets = build_leak_follow_targets(
        [
            {"candidate": "10.0.0.5", "eligible": True},
            {"candidate": "10.0.0.5", "eligible": True},  # duplicate
            {"candidate": "10.0.0.6", "eligible": False},
        ],
        existing_targets=["http://10.0.0.5:80"],
        max_targets=8,
    )
    assert "http://10.0.0.5:80" not in targets
    assert "https://10.0.0.5:443" in targets
    assert len(targets) == 1


def test_build_leak_follow_targets_respects_scheme_port_and_limit():
    targets = build_leak_follow_targets(
        [
            {
                "candidate": "internal.local",
                "eligible": True,
                "candidate_scheme": "https",
                "candidate_port": 8443,
            },
            {"candidate": "10.0.0.5", "eligible": True},
        ],
        existing_targets=[],
        max_targets=3,
    )
    assert "https://internal.local:8443" in targets
    assert len(targets) == 3


def test_build_leak_follow_targets_formats_ipv6():
    targets = build_leak_follow_targets(
        [{"candidate": "fd00::1", "eligible": True}],
        existing_targets=[],
        max_targets=2,
    )
    assert targets == ["http://[fd00::1]:80", "https://[fd00::1]:443"]
