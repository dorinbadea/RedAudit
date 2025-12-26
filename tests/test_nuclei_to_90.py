"""
Tests for nuclei.py to push coverage to 90%+.
Targets uncovered lines: 43, 129, 149, 155-156, 163, 172-174, 202, etc.
"""

import json
import os
import tempfile
from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.nuclei import (
    is_nuclei_available,
    get_nuclei_version,
    _parse_nuclei_output,
    _normalize_nuclei_finding,
    _extract_cve_ids,
    get_http_targets_from_hosts,
)


# -------------------------------------------------------------------------
# is_nuclei_available Tests
# -------------------------------------------------------------------------


def test_is_nuclei_available_true():
    """Test is_nuclei_available when nuclei exists."""
    with patch("shutil.which", return_value="/usr/bin/nuclei"):
        assert is_nuclei_available() is True


def test_is_nuclei_available_false():
    """Test is_nuclei_available when nuclei not found."""
    with patch("shutil.which", return_value=None):
        assert is_nuclei_available() is False


# -------------------------------------------------------------------------
# get_nuclei_version Tests (lines 40-46)
# -------------------------------------------------------------------------


def test_get_nuclei_version_not_available():
    """Test get_nuclei_version when nuclei not available."""
    with patch("shutil.which", return_value=None):
        result = get_nuclei_version()
        assert result is None


def test_get_nuclei_version_version_in_output():
    """Test get_nuclei_version parses version from output."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Nuclei version 2.9.0\nsome other output"

    with (
        patch("shutil.which", return_value="/usr/bin/nuclei"),
        patch("subprocess.run", return_value=mock_result),
    ):
        result = get_nuclei_version()
        assert result is not None
        assert "version" in result.lower() or "2.9" in result


def test_get_nuclei_version_no_version_keyword():
    """Test get_nuclei_version when no 'version' in output."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "nuclei 2.9.0"  # No 'version' keyword

    with (
        patch("shutil.which", return_value="/usr/bin/nuclei"),
        patch("subprocess.run", return_value=mock_result),
    ):
        result = get_nuclei_version()
        assert result is not None


def test_get_nuclei_version_exception():
    """Test get_nuclei_version handles exception."""
    with (
        patch("shutil.which", return_value="/usr/bin/nuclei"),
        patch("subprocess.run", side_effect=Exception("Failed")),
    ):
        result = get_nuclei_version()
        assert result is None


# -------------------------------------------------------------------------
# _parse_nuclei_output Tests (lines 293-314)
# -------------------------------------------------------------------------


def test_parse_nuclei_output_valid():
    """Test _parse_nuclei_output parses valid JSONL."""
    finding = {
        "template-id": "test-template",
        "info": {
            "name": "Test Finding",
            "severity": "high",
            "description": "Test description",
        },
        "host": "http://192.168.1.1",
        "matched-at": "http://192.168.1.1/admin",
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(json.dumps(finding) + "\n")
        f.flush()

        findings = _parse_nuclei_output(f.name)
        assert len(findings) >= 1

        os.unlink(f.name)


def test_parse_nuclei_output_empty_lines():
    """Test _parse_nuclei_output skips empty lines."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("\n")
        f.write('{"template-id": "test", "info": {"name": "Test", "severity": "info"}}\n')
        f.write("  \n")
        f.flush()

        findings = _parse_nuclei_output(f.name)
        assert len(findings) == 1

        os.unlink(f.name)


def test_parse_nuclei_output_invalid_json():
    """Test _parse_nuclei_output handles invalid JSON lines."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not valid json\n")
        f.write('{"template-id": "test", "info": {"name": "Valid", "severity": "info"}}\n')
        f.flush()

        findings = _parse_nuclei_output(f.name)
        # Should still parse the valid line
        assert len(findings) >= 1

        os.unlink(f.name)


def test_parse_nuclei_output_file_not_found():
    """Test _parse_nuclei_output handles missing file."""
    logger = MagicMock()
    findings = _parse_nuclei_output("/nonexistent/file.json", logger)
    assert findings == []
    logger.warning.assert_called()


# -------------------------------------------------------------------------
# _normalize_nuclei_finding Tests (lines 317-360)
# -------------------------------------------------------------------------


def test_normalize_nuclei_finding_complete():
    """Test _normalize_nuclei_finding with complete finding."""
    raw = {
        "template-id": "cve-2021-44228",
        "info": {
            "name": "Log4Shell RCE",
            "severity": "critical",
            "description": "Remote code execution",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "tags": ["cve", "rce", "log4j"],
            "classification": {"cve-id": ["CVE-2021-44228"]},
        },
        "host": "http://192.168.1.1",
        "matched-at": "http://192.168.1.1/api",
        "matcher-name": "log4j",
        "curl-command": "curl http://192.168.1.1/api",
    }

    result = _normalize_nuclei_finding(raw)

    assert result["template_id"] == "cve-2021-44228"
    assert result["name"] == "Log4Shell RCE"
    assert result["severity"] == "critical"
    assert "CVE-2021-44228" in result["cve_ids"]


def test_normalize_nuclei_finding_minimal():
    """Test _normalize_nuclei_finding with minimal data."""
    raw = {
        "template-id": "simple-test",
        "info": {"name": "Simple Test"},
    }

    result = _normalize_nuclei_finding(raw)

    assert result["template_id"] == "simple-test"
    assert result["name"] == "Simple Test"
    # Default severity from nuclei is 'medium' when not specified
    assert result["severity"] == "medium"


def test_normalize_nuclei_finding_matchedAt_alternative():
    """Test _normalize_nuclei_finding with matchedAt (camelCase)."""
    raw = {
        "template-id": "test",
        "info": {"name": "Test"},
        "matchedAt": "http://192.168.1.1/test",
        "matcherName": "test-matcher",
    }

    result = _normalize_nuclei_finding(raw)

    assert result["matched_at"] == "http://192.168.1.1/test"
    assert result["matcher_name"] == "test-matcher"


# -------------------------------------------------------------------------
# _extract_cve_ids Tests (lines 363-383)
# -------------------------------------------------------------------------


def test_extract_cve_ids_from_classification_list():
    """Test _extract_cve_ids from classification list."""
    info = {
        "classification": {
            "cve-id": ["CVE-2021-44228", "CVE-2021-45046"],
        }
    }
    cves = _extract_cve_ids(info)
    assert "CVE-2021-44228" in cves
    assert "CVE-2021-45046" in cves


def test_extract_cve_ids_from_classification_string():
    """Test _extract_cve_ids from classification string."""
    info = {
        "classification": {
            "cve-id": "CVE-2021-44228",
        }
    }
    cves = _extract_cve_ids(info)
    assert "CVE-2021-44228" in cves


def test_extract_cve_ids_from_tags():
    """Test _extract_cve_ids from tags."""
    info = {
        "tags": ["rce", "CVE-2021-44228", "critical"],
    }
    cves = _extract_cve_ids(info)
    assert "CVE-2021-44228" in cves


def test_extract_cve_ids_deduplicates():
    """Test _extract_cve_ids deduplicates CVEs."""
    info = {
        "classification": {"cve-id": ["CVE-2021-44228"]},
        "tags": ["CVE-2021-44228"],
    }
    cves = _extract_cve_ids(info)
    assert cves.count("CVE-2021-44228") == 1


def test_extract_cve_ids_cveId_alternative():
    """Test _extract_cve_ids with cveId (camelCase)."""
    info = {
        "classification": {
            "cveId": ["CVE-2021-44228"],
        }
    }
    cves = _extract_cve_ids(info)
    assert "CVE-2021-44228" in cves


# -------------------------------------------------------------------------
# get_http_targets_from_hosts Tests (lines 386-428)
# -------------------------------------------------------------------------


def test_get_http_targets_from_hosts_basic():
    """Test get_http_targets_from_hosts extracts HTTP targets."""
    hosts = [
        {
            "ip": "192.168.1.1",
            "ports": [
                {"port": 80, "service": "http", "is_web_service": True},
                {"port": 443, "service": "https", "is_web_service": True},
            ],
        }
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert "http://192.168.1.1:80" in targets
    assert "https://192.168.1.1:443" in targets


def test_get_http_targets_from_hosts_https_ports():
    """Test get_http_targets_from_hosts identifies HTTPS ports."""
    hosts = [
        {
            "ip": "192.168.1.1",
            "ports": [
                {"port": 8443, "service": "http", "is_web_service": True},
                {"port": 9443, "service": "http", "is_web_service": True},
            ],
        }
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert "https://192.168.1.1:8443" in targets
    assert "https://192.168.1.1:9443" in targets


def test_get_http_targets_from_hosts_ssl_service():
    """Test get_http_targets_from_hosts uses HTTPS for SSL services."""
    hosts = [
        {
            "ip": "192.168.1.1",
            "ports": [
                {"port": 8080, "service": "ssl/http", "is_web_service": True},
            ],
        }
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert "https://192.168.1.1:8080" in targets


def test_get_http_targets_from_hosts_skips_non_web():
    """Test get_http_targets_from_hosts skips non-web services."""
    hosts = [
        {
            "ip": "192.168.1.1",
            "ports": [
                {"port": 22, "service": "ssh", "is_web_service": False},
                {"port": 80, "service": "http", "is_web_service": True},
            ],
        }
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert len(targets) == 1
    assert "http://192.168.1.1:80" in targets


def test_get_http_targets_from_hosts_no_ip():
    """Test get_http_targets_from_hosts skips hosts without IP."""
    hosts = [
        {
            "ports": [
                {"port": 80, "service": "http", "is_web_service": True},
            ],
        }
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert targets == []


def test_get_http_targets_from_hosts_no_port():
    """Test get_http_targets_from_hosts skips ports without port number."""
    hosts = [
        {
            "ip": "192.168.1.1",
            "ports": [
                {"service": "http", "is_web_service": True},
            ],
        }
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert targets == []


def test_get_http_targets_from_hosts_deduplicates():
    """Test get_http_targets_from_hosts deduplicates targets."""
    hosts = [
        {
            "ip": "192.168.1.1",
            "ports": [{"port": 80, "service": "http", "is_web_service": True}],
        },
        {
            "ip": "192.168.1.1",
            "ports": [{"port": 80, "service": "http", "is_web_service": True}],
        },
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert targets.count("http://192.168.1.1:80") == 1
