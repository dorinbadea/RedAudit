"""
Tests for reporter.py to push coverage to 90%+.
Targets uncovered lines: 154-155, 195, 283, 337-338, 350-357, 361-370, 382-395, etc.
"""

import os
import tempfile
import json
from unittest.mock import patch, MagicMock
from datetime import datetime
import pytest

from redaudit.core.reporter import (
    _build_config_snapshot,
    _summarize_net_discovery,
    _summarize_agentless,
    _summarize_smart_scan,
    _infer_vuln_source,
    _summarize_vulnerabilities,
    _detect_network_leaks,
    extract_leaked_networks,
    generate_text_report,
)


# -------------------------------------------------------------------------
# _summarize_smart_scan Tests (lines 139-172)
# -------------------------------------------------------------------------


def test_summarize_smart_scan_with_exception():
    """Test _summarize_smart_scan handles exception in score parsing."""
    hosts = [
        {
            "smart_scan": {
                "identity_score": "invalid",  # Will cause exception
                "trigger_deep": True,
                "deep_scan_executed": True,
                "signals": ["http"],
                "reasons": ["low_identity"],
            }
        }
    ]
    result = _summarize_smart_scan(hosts)
    assert result["hosts"] == 1
    assert result["deep_scan_triggered"] == 1
    assert result["deep_scan_executed"] == 1


def test_summarize_smart_scan_empty():
    """Test _summarize_smart_scan with empty hosts."""
    result = _summarize_smart_scan([])
    assert result["hosts"] == 0
    assert result["identity_score_avg"] == 0


def test_summarize_smart_scan_no_smart_field():
    """Test _summarize_smart_scan with hosts missing smart_scan."""
    hosts = [{"ip": "192.168.1.1", "ports": []}]
    result = _summarize_smart_scan(hosts)
    assert result["hosts"] == 0


# -------------------------------------------------------------------------
# _infer_vuln_source Tests (lines 175-187)
# -------------------------------------------------------------------------


def test_infer_vuln_source_explicit():
    """Test _infer_vuln_source with explicit source."""
    vuln = {"source": "nuclei"}
    assert _infer_vuln_source(vuln) == "nuclei"


def test_infer_vuln_source_from_original_severity():
    """Test _infer_vuln_source from original_severity tool."""
    vuln = {"original_severity": {"tool": "nikto"}}
    assert _infer_vuln_source(vuln) == "nikto"


def test_infer_vuln_source_nuclei_template():
    """Test _infer_vuln_source detects nuclei from template_id."""
    vuln = {"template_id": "cve-2021-44228"}
    assert _infer_vuln_source(vuln) == "nuclei"


def test_infer_vuln_source_nikto():
    """Test _infer_vuln_source detects nikto from findings."""
    vuln = {"nikto_findings": ["+ Test finding"]}
    assert _infer_vuln_source(vuln) == "nikto"


def test_infer_vuln_source_testssl():
    """Test _infer_vuln_source detects testssl."""
    vuln = {"testssl_analysis": {"summary": "TLS 1.0 detected"}}
    assert _infer_vuln_source(vuln) == "testssl"


def test_infer_vuln_source_whatweb():
    """Test _infer_vuln_source detects whatweb."""
    vuln = {"whatweb": "Apache[2.4.41]"}
    assert _infer_vuln_source(vuln) == "whatweb"


def test_infer_vuln_source_unknown():
    """Test _infer_vuln_source returns unknown."""
    vuln = {"severity": "high"}
    assert _infer_vuln_source(vuln) == "unknown"


# -------------------------------------------------------------------------
# _summarize_vulnerabilities Tests (lines 190-200)
# -------------------------------------------------------------------------


def test_summarize_vulnerabilities_empty_entry():
    """Test _summarize_vulnerabilities skips empty entries."""
    entries = [None, {"vulnerabilities": []}, {"host": "192.168.1.1", "vulnerabilities": []}]
    result = _summarize_vulnerabilities(entries)
    assert result["total"] == 0


def test_summarize_vulnerabilities_with_sources():
    """Test _summarize_vulnerabilities counts sources."""
    entries = [
        {
            "vulnerabilities": [
                {"source": "nikto"},
                {"source": "testssl"},
                {"source": "nikto"},
            ]
        }
    ]
    result = _summarize_vulnerabilities(entries)
    assert result["total"] == 3
    assert result["sources"]["nikto"] == 2
    assert result["sources"]["testssl"] == 1


# -------------------------------------------------------------------------
# _detect_network_leaks Tests (lines 321-397)
# -------------------------------------------------------------------------


def test_detect_network_leaks_invalid_target():
    """Test _detect_network_leaks handles invalid target network."""
    results = {"vulnerabilities": []}
    config = {"target_networks": ["invalid-network"]}
    leaks = _detect_network_leaks(results, config)
    assert leaks == []


def test_detect_network_leaks_from_curl_headers():
    """Test _detect_network_leaks finds IPs in curl headers."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"curl_headers": "Location: http://10.0.1.50/admin"}],
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert len(leaks) >= 1
    assert any("10.0.1.50" in leak for leak in leaks)


def test_detect_network_leaks_from_wget_headers():
    """Test _detect_network_leaks finds IPs in wget headers."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"wget_headers": "X-Backend: 172.16.0.100"}],
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert len(leaks) >= 1


def test_detect_network_leaks_from_redirect_url():
    """Test _detect_network_leaks finds IPs in redirect URLs."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"redirect_url": "http://192.168.10.1/login"}],
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert len(leaks) >= 1


def test_detect_network_leaks_from_nikto():
    """Test _detect_network_leaks finds IPs in nikto findings."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"nikto_findings": ["RFC-1918 IP 10.0.0.1 found in headers"]}],
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert len(leaks) >= 1


def test_detect_network_leaks_ignores_same_host():
    """Test _detect_network_leaks ignores IP same as host."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"curl_headers": "Server: 192.168.1.1"}],
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert leaks == []


def test_detect_network_leaks_ignores_public_ip():
    """Test _detect_network_leaks ignores public IPs."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"curl_headers": "X-Forwarded-For: 8.8.8.8"}],
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert leaks == []


def test_detect_network_leaks_invalid_ip_value_error():
    """Test _detect_network_leaks handles ValueError in IP parsing."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"curl_headers": "Server: 192.168.1.999"}],  # Invalid IP
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    # Should not raise, just ignore invalid IPs


def test_detect_network_leaks_non_string_content():
    """Test _detect_network_leaks handles non-string content."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"curl_headers": 12345}],  # Not a string
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    # Should not raise


def test_detect_network_leaks_empty_vulnerabilities_entry():
    """Test _detect_network_leaks handles empty vulnerability entries."""
    results = {"vulnerabilities": [None, {}]}
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert leaks == []


# -------------------------------------------------------------------------
# extract_leaked_networks Tests (lines 400-472)
# -------------------------------------------------------------------------


def test_extract_leaked_networks_invalid_target():
    """Test extract_leaked_networks handles invalid target."""
    results = {"vulnerabilities": []}
    config = {"target_networks": ["not-a-network"]}
    networks = extract_leaked_networks(results, config)
    assert networks == []


def test_extract_leaked_networks_from_hidden():
    """Test extract_leaked_networks extracts from hidden_networks."""
    results = {
        "vulnerabilities": [],
        "hidden_networks": ["Host 192.168.1.1 leaks IP 10.0.1.50 (Potential Network: 10.0.1.0/24)"],
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    networks = extract_leaked_networks(results, config)
    assert "10.0.1.0/24" in networks


def test_extract_leaked_networks_from_curl():
    """Test extract_leaked_networks extracts from curl headers."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"curl_headers": "Location: http://10.0.2.1/login"}],
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    networks = extract_leaked_networks(results, config)
    assert "10.0.2.0/24" in networks


def test_extract_leaked_networks_empty_vulnerabilities():
    """Test extract_leaked_networks handles None entries."""
    results = {"vulnerabilities": [None]}
    config = {"target_networks": ["192.168.1.0/24"]}
    networks = extract_leaked_networks(results, config)
    assert networks == []


# -------------------------------------------------------------------------
# generate_text_report Tests (lines 475-682)
# -------------------------------------------------------------------------


def test_generate_text_report_basic():
    """Test generate_text_report with minimal data."""
    results = {
        "summary": {"networks": 1, "hosts_found": 5, "hosts_scanned": 3, "vulns_found": 2},
        "hosts": [],
        "vulnerabilities": [],
        "config_snapshot": {},
    }
    report = generate_text_report(results)
    assert "NETWORK AUDIT REPORT" in report
    assert "Networks:      1" in report


def test_generate_text_report_partial():
    """Test generate_text_report with partial flag."""
    results = {
        "summary": {},
        "hosts": [],
        "vulnerabilities": [],
        "config_snapshot": {},
    }
    report = generate_text_report(results, partial=True)
    assert "PARTIAL/INTERRUPTED" in report


def test_generate_text_report_with_auditor():
    """Test generate_text_report includes auditor name."""
    results = {
        "summary": {},
        "hosts": [],
        "vulnerabilities": [],
        "config_snapshot": {"auditor_name": "Test Auditor"},
    }
    report = generate_text_report(results)
    assert "Auditor: Test Auditor" in report


def test_generate_text_report_with_cve_join_exception():
    """Test generate_text_report handles exception in CVE join."""
    results = {
        "summary": {},
        "hosts": [],
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [
                    {
                        "severity": "high",
                        "cve_ids": [None, 123],  # Invalid types for join
                    }
                ],
            }
        ],
        "config_snapshot": {},
    }
    report = generate_text_report(results)
    # Should not raise exception


# -------------------------------------------------------------------------
# _build_config_snapshot Tests
# -------------------------------------------------------------------------


def test_build_config_snapshot():
    """Test _build_config_snapshot creates clean snapshot."""
    config = {
        "target_networks": ["192.168.1.0/24"],
        "scan_mode": "completo",
        "threads": 10,
        "password": "secret",  # Should NOT be included
        "encryption_key": b"secret",  # Should NOT be included
    }
    snapshot = _build_config_snapshot(config)
    assert snapshot["targets"] == ["192.168.1.0/24"]
    assert snapshot["scan_mode"] == "completo"
    assert "password" not in snapshot
    assert "encryption_key" not in snapshot


# -------------------------------------------------------------------------
# _summarize_net_discovery Tests
# -------------------------------------------------------------------------


def test_summarize_net_discovery_empty():
    """Test _summarize_net_discovery with empty dict."""
    result = _summarize_net_discovery({})
    assert result["enabled"] is False


def test_summarize_net_discovery_none():
    """Test _summarize_net_discovery with None."""
    result = _summarize_net_discovery(None)
    assert result["enabled"] is False


def test_summarize_net_discovery_full():
    """Test _summarize_net_discovery with full data."""
    net_disc = {
        "enabled": True,
        "protocols_used": ["arp", "mdns"],
        "redteam_enabled": True,
        "hyperscan_duration": 5.0,
        "errors": ["error1", "error2"],
        "dhcp_servers": [{"ip": "192.168.1.1"}],
        "alive_hosts": ["192.168.1.1", "192.168.1.2"],
        "netbios_hosts": [],
        "arp_hosts": [{"ip": "192.168.1.1"}],
        "mdns_services": [],
        "upnp_devices": [],
        "candidate_vlans": [],
        "hyperscan_tcp_hosts": {"192.168.1.1": []},
        "potential_backdoors": [],
        "redteam": {
            "targets_considered": 5,
            "masscan": {"open_ports": [22, 80]},
            "snmp": {"hosts": []},
            "smb": {"hosts": [{"ip": "192.168.1.1"}]},
            "rpc": {"hosts": []},
            "ldap": {"hosts": []},
            "kerberos": {"hosts": []},
            "vlan_enum": {"vlan_ids": [10, 20]},
            "router_discovery": {"router_candidates": []},
            "ipv6_discovery": {"neighbors": []},
        },
    }
    result = _summarize_net_discovery(net_disc)
    assert result["enabled"] is True
    assert result["counts"]["dhcp_servers"] == 1
    assert result["counts"]["alive_hosts"] == 2
    assert result["redteam"]["targets_considered"] == 5
    assert result["redteam"]["smb_hosts"] == 1


# -------------------------------------------------------------------------
# _summarize_agentless Tests
# -------------------------------------------------------------------------


def test_summarize_agentless_empty_hosts():
    """Test _summarize_agentless with empty hosts."""
    result = _summarize_agentless([], {}, {"windows_verify_enabled": True})
    assert result["enabled"] is True
    assert result["targets"] == 0


def test_summarize_agentless_with_probes():
    """Test _summarize_agentless counts probes."""
    hosts = [
        {
            "agentless_probe": {"smb": True, "rdp": True, "ldap": False},
            "agentless_fingerprint": {"domain": "CORP.LOCAL"},
        },
        {
            "agentless_probe": {"ssh": True, "http": True},
            "agentless_fingerprint": {"dns_domain_name": "CORP.LOCAL"},
        },
    ]
    result = _summarize_agentless(
        hosts, {"targets": 2, "completed": 2}, {"windows_verify_enabled": True}
    )
    assert result["signals"]["smb"] == 1
    assert result["signals"]["rdp"] == 1
    assert result["signals"]["ssh"] == 1
    assert result["signals"]["http"] == 1
    assert "CORP.LOCAL" in result["domains"]
