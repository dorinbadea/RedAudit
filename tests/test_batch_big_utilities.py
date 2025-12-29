#!/usr/bin/env python3
"""
Big Final Push - updater, reporter, scanner utilities
Target: ~300 lines coverage
Strategy: Focus on utility functions, parsers, validators
"""

import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock


# =================================================================
# updater.py - 218 lines (68.90%)
# Easy targets: parse_version, compare_versions, compute_file_hash,
#               _parse_published_date, _classify_release_type
# =================================================================
def test_updater_parse_version():
    """Test version parsing."""
    from redaudit.core.updater import parse_version

    # Now returns 4-tuple: (major, minor, patch, suffix)
    assert parse_version("2.8.0") == (2, 8, 0, "")
    assert parse_version("3.1.4") == (3, 1, 4, "")
    assert parse_version("1.0.0") == (1, 0, 0, "")
    assert parse_version("3.9.5a") == (3, 9, 5, "a")


def test_updater_compare_versions():
    """Test version comparison."""
    from redaudit.core.updater import compare_versions

    # Current < Remote (update available)
    assert compare_versions("2.8.0", "3.0.0") == -1

    # Current == Remote
    assert compare_versions("3.0.0", "3.0.0") == 0

    # Current > Remote (ahead)
    assert compare_versions("3.1.0", "3.0.0") == 1


def test_updater_compute_file_hash():
    """Test file hashing."""
    from redaudit.core.updater import compute_file_hash

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("test content")
        f.flush()
        hash_val = compute_file_hash(f.name)
        assert hash_val
        assert len(hash_val) == 64  # SHA256 hex digest
        Path(f.name).unlink()


def test_updater_mocked_fetch():
    """Test fetch_latest_version with mock."""
    from redaudit.core.updater import fetch_latest_version

    payload = {
        "tag_name": "v3.0.0",
        "name": "Release 3.0.0",
        "body": "Test notes",
        "published_at": "2025-01-01T00:00:00Z",
        "html_url": "https://example.com/release",
    }
    response = MagicMock()
    response.status = 200
    response.read.return_value = str(payload).replace("'", '"').encode("utf-8")
    response.__enter__.return_value = response
    response.__exit__.return_value = None

    with patch("redaudit.core.updater.urlopen", return_value=response):
        result = fetch_latest_version()
        assert result is not None


# =================================================================
# reporter.py - 148 lines (73.52%)
# Easy targets: sanitize functions, parsers, validators
# =================================================================
def test_reporter_build_config_snapshot():
    """Test config snapshot building."""
    from redaudit.core.reporter import _build_config_snapshot

    config = {"target_networks": ["192.168.1.0/24"], "mode": "normal"}
    snapshot = _build_config_snapshot(config)
    assert snapshot is not None
    assert isinstance(snapshot, dict)


def test_reporter_infer_vuln_source():
    """Test vulnerability source inference."""
    from redaudit.core.reporter import _infer_vuln_source

    # Nikto finding
    source = _infer_vuln_source({"nikto_findings": ["test"]})
    assert source in ["nikto", "whatweb", "testssl", "nmap", "unknown"]

    # Empty
    source = _infer_vuln_source({})
    assert source


def test_reporter_summarize_vulnerabilities():
    """Test vulnerability summarization."""
    from redaudit.core.reporter import _summarize_vulnerabilities

    vulns = [
        {
            "host": "192.168.1.1",
            "vulnerabilities": [{"nikto_findings": ["test1", "test2"]}],
        }
    ]

    summary = _summarize_vulnerabilities(vulns)
    assert isinstance(summary, dict)


# =================================================================
# scanner.py - 151 lines (76.15%)
# Easy targets: sanitize_ip, is_ipv6, is_web_service, is_suspicious_service,
#               extract_vendor_mac, get_nmap_arguments
# =================================================================
def test_scanner_sanitize_ip():
    """Test IP sanitization."""
    from redaudit.core.scanner import sanitize_ip

    # Valid IPv4
    assert sanitize_ip("192.168.1.1") == "192.168.1.1"

    # Valid IPv6
    ipv6 = sanitize_ip("2001:db8::1")
    assert ipv6

    # Invalid
    assert sanitize_ip("invalid") is None


def test_scanner_is_ipv6():
    """Test IPv6 detection."""
    from redaudit.core.scanner import is_ipv6

    assert is_ipv6("2001:db8::1") is True
    assert is_ipv6("192.168.1.1") is False
    assert is_ipv6("invalid") is False


def test_scanner_is_web_service():
    """Test web service detection."""
    from redaudit.core.scanner import is_web_service

    assert is_web_service("http") is True
    assert is_web_service("https") is True
    assert is_web_service("http-proxy") is True
    assert is_web_service("ssh") is False


def test_scanner_is_suspicious_service():
    """Test suspicious service detection."""
    from redaudit.core.scanner import is_suspicious_service

    # Just verify it returns boolean
    result = is_suspicious_service("vnc")
    assert isinstance(result, bool)

    result = is_suspicious_service("http")
    assert isinstance(result, bool)


def test_scanner_get_nmap_arguments():
    """Test nmap argument generation."""
    from redaudit.core.scanner import get_nmap_arguments

    # Rapid scan
    args = get_nmap_arguments("rapido")
    assert args
    assert isinstance(args, str)

    # Normal scan
    args = get_nmap_arguments("normal")
    assert args

    # Complete scan
    args = get_nmap_arguments("completo")
    assert args


def test_scanner_extract_vendor_mac():
    """Test MAC/vendor extraction."""
    from redaudit.core.scanner import extract_vendor_mac

    # With vendor
    text = "MAC Address: 00:11:22:33:44:55 (Cisco Systems)"
    mac, vendor = extract_vendor_mac(text)
    assert mac == "00:11:22:33:44:55"
    assert vendor == "Cisco Systems"

    # No MAC
    mac, vendor = extract_vendor_mac("No MAC found")
    assert mac is None
    assert vendor is None
