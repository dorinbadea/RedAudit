#!/usr/bin/env python3
"""
Coverage for applying persisted defaults in auditor.
"""

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.utils.constants import DEFAULT_THREADS, MAX_THREADS, MIN_THREADS


def _make_auditor():
    auditor = InteractiveNetworkAuditor.__new__(InteractiveNetworkAuditor)
    auditor.config = {"threads": DEFAULT_THREADS}
    auditor.rate_limit_delay = 0.0
    return auditor


def test_apply_run_defaults_valid():
    auditor = _make_auditor()
    defaults = {
        "scan_mode": "full",
        "threads": MIN_THREADS + 1,
        "rate_limit": 2.5,
        "scan_vulnerabilities": False,
        "nuclei_enabled": True,
        "nuclei_max_runtime": 30,
        "leak_follow_mode": "safe",
        "leak_follow_policy_pack": "safe-extended",
        "leak_follow_allowlist": ["10.0.0.0/24", "10.0.1.5"],
        "leak_follow_allowlist_profiles": ["rfc1918-only", "local-hosts"],
        "leak_follow_denylist": ["10.0.9.0/24"],
        "iot_probes_mode": "safe",
        "iot_probe_packs": ["ssdp", "coap"],
        "iot_probe_budget_seconds": 25,
        "iot_probe_timeout_seconds": 6,
        "cve_lookup_enabled": True,
    }

    InteractiveNetworkAuditor._apply_run_defaults(auditor, defaults)

    assert auditor.config["scan_mode"] == "full"
    assert auditor.config["threads"] == MIN_THREADS + 1
    assert auditor.rate_limit_delay == 2.5
    assert auditor.config["scan_vulnerabilities"] is False
    assert auditor.config["nuclei_enabled"] is True
    assert auditor.config["nuclei_max_runtime"] == 30
    assert auditor.config["leak_follow_mode"] == "safe"
    assert auditor.config["leak_follow_policy_pack"] == "safe-extended"
    assert auditor.config["leak_follow_allowlist"] == ["10.0.0.0/24", "10.0.1.5"]
    assert auditor.config["leak_follow_allowlist_profiles"] == ["rfc1918-only", "local-hosts"]
    assert auditor.config["leak_follow_denylist"] == ["10.0.9.0/24"]
    assert auditor.config["iot_probes_mode"] == "safe"
    assert auditor.config["iot_probe_packs"] == ["ssdp", "coap"]
    assert auditor.config["iot_probe_budget_seconds"] == 25
    assert auditor.config["iot_probe_timeout_seconds"] == 6
    assert auditor.config["cve_lookup_enabled"] is True


def test_apply_run_defaults_invalid_values():
    auditor = _make_auditor()
    defaults = {
        "threads": MAX_THREADS + 100,
        "rate_limit": -1,
        "nuclei_max_runtime": -5,
        "leak_follow_mode": "bad",
        "leak_follow_policy_pack": "bad-pack",
        "leak_follow_allowlist": None,
        "leak_follow_allowlist_profiles": ["bad-profile"],
        "leak_follow_denylist": None,
        "iot_probes_mode": "bad",
        "iot_probe_packs": ["bad-pack"],
        "iot_probe_budget_seconds": 0,
        "iot_probe_timeout_seconds": 0,
    }

    InteractiveNetworkAuditor._apply_run_defaults(auditor, defaults)

    assert auditor.config["threads"] == DEFAULT_THREADS
    assert auditor.rate_limit_delay == 0.0
    assert auditor.config["nuclei_max_runtime"] == 0
    assert auditor.config["leak_follow_mode"] == "off"
    assert auditor.config["leak_follow_policy_pack"] == "safe-default"
    assert auditor.config["leak_follow_allowlist"] == []
    assert auditor.config["leak_follow_allowlist_profiles"] == []
    assert auditor.config["leak_follow_denylist"] == []
    assert auditor.config["iot_probes_mode"] == "off"
    assert auditor.config["iot_probe_packs"] == ["ssdp", "coap", "wiz", "yeelight", "tuya"]
    assert auditor.config["iot_probe_budget_seconds"] == 20
    assert auditor.config["iot_probe_timeout_seconds"] == 3


def test_build_scope_expansion_evidence_normalizes_and_deduplicates():
    auditor = _make_auditor()
    leak_runtime = {
        "decisions": [
            {
                "candidate": "10.0.0.5",
                "source_host": "10.0.0.1",
                "source_field": "redirect_url",
                "eligible": True,
                "reason": "in_scope",
            },
            {
                "candidate": "router.local",
                "source_host": "10.0.0.1",
                "source_field": "headers",
                "eligible": False,
                "reason": "hostname_not_allowlisted",
            },
        ]
    }
    iot_runtime = {
        "evidence": [
            {
                "classification": "evidence",
                "source": "udp:1900",
                "signal": "responded",
                "decision": "promote_candidate",
                "reason": "corroborated",
                "host": "10.0.0.5",
            },
            {
                "classification": "evidence",
                "source": "udp:5683",
                "signal": "responded",
                "decision": "promote_candidate",
                "reason": "active_signal_without_prior",
                "host": "10.0.0.5",
            },
        ]
    }

    evidence = InteractiveNetworkAuditor._build_scope_expansion_evidence(
        auditor, leak_runtime, iot_runtime
    )

    assert len(evidence) == 4
    classes = {(item["feature"], item["classification"]) for item in evidence}
    assert ("leak_follow", "heuristic") in classes
    assert ("leak_follow", "hint") in classes
    assert ("iot_probe", "evidence") in classes
    assert ("iot_probe", "heuristic") in classes
