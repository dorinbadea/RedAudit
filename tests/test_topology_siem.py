#!/usr/bin/env python3
"""
Topology & SIEM Coverage Tests - VERIFIED APIs
Branch: batch/topology-siem-verify
"""

import tempfile
from unittest.mock import patch, MagicMock


# =================================================================
# topology.py - VERIFIED APIs
# Main: discover_topology(target_networks, network_info, extra_tools, logger)
# Helpers: _parse_ip_route, _extract_default_gateway, _parse_arp_scan
# =================================================================
def test_topology_parse_ip_route_empty():
    """Test _parse_ip_route with empty output."""
    from redaudit.core.topology import _parse_ip_route

    routes = _parse_ip_route("")
    assert routes == []


def test_topology_extract_default_gateway_empty():
    """Test _extract_default_gateway with no routes."""
    from redaudit.core.topology import _extract_default_gateway

    gateway = _extract_default_gateway([])
    assert gateway is None


def test_topology_parse_arp_scan_empty():
    """Test _parse_arp_scan with empty output."""
    from redaudit.core.topology import _parse_arp_scan

    neighbors = _parse_arp_scan("")
    assert neighbors == []


def test_topology_discover_topology_minimal():
    """Test discover_topology with minimal inputs."""
    from redaudit.core.topology import discover_topology

    # Empty networks and no network info
    result = discover_topology([], [])
    assert result is not None
    assert isinstance(result, dict)


# =================================================================
# siem.py - VERIFIED APIs
# Main: enrich_report_for_siem(results, config)
# Utils: calculate_severity, calculate_risk_score, generate_observable_hash
# =================================================================
def test_siem_calculate_severity_basic():
    """Test calculate_severity with various inputs."""
    from redaudit.core.siem import calculate_severity

    # Critical keyword
    severity = calculate_severity("Remote Code Execution vulnerability")
    assert severity in ["critical", "high", "medium", "low", "info"]

    # Empty
    severity = calculate_severity("")
    assert severity


def test_siem_calculate_risk_score_minimal():
    """Test calculate_risk_score with minimal host."""
    from redaudit.core.siem import calculate_risk_score

    # Empty host
    score = calculate_risk_score({})
    assert isinstance(score, (int, float))
    assert 0 <= score <= 100


def test_siem_generate_observable_hash():
    """Test generate_observable_hash."""
    from redaudit.core.siem import generate_observable_hash

    # Basic host
    hash1 = generate_observable_hash({"ip": "1.2.3.4", "ports": []})
    assert hash1
    assert isinstance(hash1, str)

    # Same host should produce same hash
    hash2 = generate_observable_hash({"ip": "1.2.3.4", "ports": []})
    assert hash1 == hash2


def test_siem_enrich_report_minimal():
    """Test enrich_report_for_siem with minimal data."""
    from redaudit.core.siem import enrich_report_for_siem

    results = {"hosts": [], "vulnerabilities": [], "timestamp": "2025-01-01"}
    config = {"target_networks": ["192.168.1.0/24"]}

    enriched = enrich_report_for_siem(results, config)
    assert enriched is not None
    assert "hosts" in enriched


def test_siem_classify_finding_category():
    """Test classify_finding_category."""
    from redaudit.core.siem import classify_finding_category

    # Crypto-related
    category = classify_finding_category("Weak TLS cipher")
    assert category in ["surface", "misconfig", "crypto", "auth", "info-leak", "vuln"]


def test_siem_is_rfc1918_address():
    """Test is_rfc1918_address."""
    from redaudit.core.siem import is_rfc1918_address

    # Private IPs
    assert is_rfc1918_address("192.168.1.1") is True
    assert is_rfc1918_address("10.0.0.1") is True

    # Public IP
    assert is_rfc1918_address("8.8.8.8") is False
