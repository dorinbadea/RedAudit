"""
Tests for playbook_generator.py to push coverage to 90%+.
Targets uncovered lines: 97-123, 249-264, 294-331, 453-478.
"""

import os
import tempfile
from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.playbook_generator import (
    _coerce_port,
    _extract_port,
    classify_finding,
    generate_playbook,
    get_playbooks_for_results,
    render_playbook_markdown,
    save_playbooks,
)


# -------------------------------------------------------------------------
# _extract_port Tests (lines 90-125)
# -------------------------------------------------------------------------


def test_extract_port_from_port_field():
    """Test _extract_port with port field."""
    finding = {"port": 443}
    assert _extract_port(finding) == 443


def test_extract_port_from_url():
    """Test _extract_port extracting port from URL."""
    finding = {"url": "https://example.com:8443/admin"}
    result = _extract_port(finding)
    assert result == 8443


def test_extract_port_from_url_standard():
    """Test _extract_port with standard port in URL path."""
    finding = {"url": "http://example.com:80/"}
    result = _extract_port(finding)
    assert result == 80


def test_extract_port_from_descriptive_title():
    """Test _extract_port from descriptive_title text."""
    finding = {"descriptive_title": "Open port 22/tcp SSH service"}
    result = _extract_port(finding)
    assert result == 22


def test_extract_port_from_category_text():
    """Test _extract_port from category text."""
    finding = {"category": "Service on port 3389"}
    result = _extract_port(finding)
    assert result == 3389


def test_extract_port_from_nikto_findings():
    """Test _extract_port from nikto_findings list."""
    finding = {"nikto_findings": ["+ Server leaking info on port 8080"]}
    result = _extract_port(finding)
    assert result == 8080


def test_extract_port_from_parsed_observations():
    """Test _extract_port from parsed_observations list."""
    finding = {"parsed_observations": ["Port 445/tcp is open"]}
    result = _extract_port(finding)
    assert result == 445


def test_extract_port_no_port():
    """Test _extract_port returns None when no port found."""
    finding = {"descriptive_title": "Generic issue"}
    result = _extract_port(finding)
    assert result is None


# -------------------------------------------------------------------------
# generate_playbook Category Tests (lines 248-331)
# -------------------------------------------------------------------------


def test_generate_playbook_http_headers():
    """Test generate_playbook for http_headers category."""
    finding = {"descriptive_title": "Missing HSTS header", "severity": "medium"}
    playbook = generate_playbook(finding, "192.168.1.1", "http_headers")

    assert playbook["category"] == "http_headers"
    assert len(playbook["steps"]) >= 4
    assert any("HSTS" in step for step in playbook["steps"])
    assert len(playbook["commands"]) >= 4
    assert len(playbook["references"]) >= 1


def test_generate_playbook_cve_with_cves():
    """Test generate_playbook for cve_remediation with CVE IDs."""
    finding = {
        "descriptive_title": "CVE-2021-44228 Log4Shell",
        "severity": "critical",
        "cve_ids": ["CVE-2021-44228", "CVE-2021-45046"],
    }
    playbook = generate_playbook(finding, "10.0.0.1", "cve_remediation")

    assert playbook["category"] == "cve_remediation"
    assert "CVE-2021-44228" in playbook["steps"][0]
    assert any("nvd.nist.gov" in ref for ref in playbook["references"])


def test_generate_playbook_cve_without_cves():
    """Test generate_playbook for cve_remediation without CVE IDs."""
    finding = {"descriptive_title": "Potential vulnerability", "severity": "high"}
    playbook = generate_playbook(finding, "10.0.0.1", "cve_remediation")

    assert playbook["category"] == "cve_remediation"
    assert len(playbook["steps"]) >= 3
    assert "Identify affected software" in playbook["steps"][0]


def test_generate_playbook_web_hardening():
    """Test generate_playbook for web_hardening category."""
    finding = {"descriptive_title": "Directory listing enabled", "severity": "low"}
    playbook = generate_playbook(finding, "192.168.1.100", "web_hardening")

    assert playbook["category"] == "web_hardening"
    assert any("directory" in step.lower() for step in playbook["steps"])
    assert any("autoindex" in cmd.lower() for cmd in playbook["commands"])
    assert len(playbook["references"]) >= 1


def test_generate_playbook_port_hardening_with_port():
    """Test generate_playbook for port_hardening with port."""
    finding = {"descriptive_title": "Telnet service", "severity": "high", "port": 23}
    playbook = generate_playbook(finding, "192.168.1.50", "port_hardening")

    assert playbook["category"] == "port_hardening"
    assert playbook["port"] == 23
    assert any("23" in cmd for cmd in playbook["commands"])
    assert any("iptables" in cmd for cmd in playbook["commands"])


def test_generate_playbook_port_hardening_without_port():
    """Test generate_playbook for port_hardening without port."""
    finding = {"descriptive_title": "FTP open", "severity": "medium"}
    playbook = generate_playbook(finding, "192.168.1.50", "port_hardening")

    assert playbook["category"] == "port_hardening"
    assert playbook["port"] is None
    assert any("<port>" in cmd for cmd in playbook["commands"])


# -------------------------------------------------------------------------
# save_playbooks Error Handling Tests (lines 453-478)
# -------------------------------------------------------------------------


def test_save_playbooks_mkdir_error():
    """Test save_playbooks handles mkdir error."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"descriptive_title": "SSL weak cipher", "severity": "high"}],
            }
        ]
    }
    logger = MagicMock()

    with patch("os.makedirs", side_effect=PermissionError("Access denied")):
        count = save_playbooks(results, "/nonexistent/path", logger)
        assert count == 0
        logger.warning.assert_called()


def test_save_playbooks_write_error():
    """Test save_playbooks handles file write error."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"descriptive_title": "SSL weak cipher", "severity": "high"}],
            }
        ]
    }
    logger = MagicMock()

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("builtins.open", side_effect=IOError("Write failed")):
            count = save_playbooks(results, tmpdir, logger)
            assert count == 0


def test_save_playbooks_chmod_error():
    """Test save_playbooks handles chmod error gracefully."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"descriptive_title": "SSL weak cipher", "severity": "high"}],
            }
        ]
    }
    logger = MagicMock()

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("os.chmod", side_effect=OSError("chmod failed")):
            count = save_playbooks(results, tmpdir, logger)
            # Should still save files even if chmod fails
            assert count >= 1


def test_save_playbooks_empty_results():
    """Test save_playbooks with no vulnerabilities."""
    results = {"vulnerabilities": []}
    count = save_playbooks(results, "/tmp", None)
    assert count == 0


def test_save_playbooks_success():
    """Test save_playbooks successfully writes files."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [
                    {"descriptive_title": "Missing HSTS", "severity": "medium"},
                ],
            }
        ]
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        count = save_playbooks(results, tmpdir, None)
        assert count >= 1
        playbooks_dir = os.path.join(tmpdir, "playbooks")
        assert os.path.exists(playbooks_dir)


# -------------------------------------------------------------------------
# Additional Coverage Tests
# -------------------------------------------------------------------------


def test_classify_finding_http_headers():
    """Test classify_finding identifies http_headers category."""
    finding = {"descriptive_title": "Missing HSTS header"}
    result = classify_finding(finding)
    assert result == "http_headers"


def test_classify_finding_web_hardening():
    """Test classify_finding identifies web_hardening category."""
    finding = {"nikto_findings": ["OSVDB-3268: Directory listing found"]}
    result = classify_finding(finding)
    assert result == "web_hardening"


def test_classify_finding_port_hardening():
    """Test classify_finding identifies port_hardening category."""
    finding = {"descriptive_title": "Telnet service running"}
    result = classify_finding(finding)
    assert result == "port_hardening"


def test_coerce_port_string():
    """Test _coerce_port with string input."""
    assert _coerce_port("443") == 443


def test_coerce_port_invalid_string():
    """Test _coerce_port with non-numeric string."""
    assert _coerce_port("https") is None


def test_coerce_port_out_of_range():
    """Test _coerce_port with out of range value."""
    assert _coerce_port(70000) is None
    assert _coerce_port(0) is None


def test_render_playbook_markdown_complete():
    """Test render_playbook_markdown generates complete markdown."""
    playbook = {
        "title": "Test Playbook",
        "host": "192.168.1.1",
        "port": 443,
        "severity": "HIGH",
        "category": "tls_hardening",
        "generated_at": "2025-01-01 12:00",
        "steps": ["Step 1", "Step 2"],
        "commands": ["command1", "command2"],
        "references": ["https://example.com"],
    }
    markdown = render_playbook_markdown(playbook)

    assert "# Test Playbook" in markdown
    assert "**Host**: 192.168.1.1" in markdown
    assert "**Port**: 443" in markdown
    assert "Step 1" in markdown
    assert "```bash" in markdown
    assert "https://example.com" in markdown


def test_render_playbook_markdown_no_port():
    """Test render_playbook_markdown without port."""
    playbook = {
        "title": "Test",
        "host": "192.168.1.1",
        "port": None,
        "severity": "LOW",
        "category": "other",
        "generated_at": "2025-01-01",
        "steps": [],
        "commands": [],
        "references": [],
    }
    markdown = render_playbook_markdown(playbook)
    assert "**Port**:" not in markdown or "None" not in markdown


def test_get_playbooks_for_results_deduplication():
    """Test get_playbooks_for_results deduplicates by host+category."""
    results = {
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [
                    {"descriptive_title": "SSL weak cipher 1", "severity": "high"},
                    {"descriptive_title": "SSL TLS1.0 enabled", "severity": "medium"},
                ],
            }
        ]
    }
    playbooks = get_playbooks_for_results(results)
    # Should deduplicate - both are tls_hardening for same host
    tls_playbooks = [p for p in playbooks if p["category"] == "tls_hardening"]
    assert len(tls_playbooks) <= 1
