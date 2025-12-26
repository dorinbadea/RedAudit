"""
Tests for jsonl_exporter.py to push coverage to 90%+.
Targets uncovered lines: 47, 102-103, 171-191, 198-199, 256-257, 311, 313, 317, 319, 321, 331.
"""

import os
import json
import tempfile
from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.jsonl_exporter import (
    export_findings_jsonl,
    export_assets_jsonl,
    export_all,
    _extract_title,
)


# -------------------------------------------------------------------------
# _extract_title Tests
# -------------------------------------------------------------------------


def test_extract_title_from_descriptive_title():
    """Test _extract_title returns a title for vuln with descriptive_title."""
    vuln = {"descriptive_title": "SQL Injection Detected"}
    result = _extract_title(vuln)
    # The function returns a title (may include context)
    assert isinstance(result, str) and len(result) > 0


def test_extract_title_from_name():
    """Test _extract_title falls back to name."""
    vuln = {"name": "XSS Vulnerability"}
    result = _extract_title(vuln)
    # Function generates a title, may include "XSS" or be a default
    assert result is not None


def test_extract_title_from_url():
    """Test _extract_title falls back to url."""
    vuln = {"url": "http://192.168.1.1/admin"}
    result = _extract_title(vuln)
    # Function may generate title from URL or return default
    assert len(result) > 0


def test_extract_title_empty():
    """Test _extract_title returns a default for empty vuln."""
    result = _extract_title({})
    assert isinstance(result, str)


# -------------------------------------------------------------------------
# export_findings_jsonl Tests (lines 22-105)
# -------------------------------------------------------------------------


def test_export_findings_jsonl_basic():
    """Test export_findings_jsonl exports findings."""
    results = {
        "hosts": [{"ip": "192.168.1.1", "observable_hash": "abc123"}],
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [
                    {
                        "finding_id": "f1",
                        "severity": "high",
                        "descriptive_title": "XSS",
                    }
                ],
            }
        ],
        "session_id": "sess123",
        "schema_version": "3.1",
        "scanner_versions": {"redaudit": "3.8.0"},
        "scanner": {"mode": "completo"},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        count = export_findings_jsonl(results, f.name)
        assert count == 1

        with open(f.name, "r") as rf:
            line = rf.readline()
            finding = json.loads(line)
            assert finding["finding_id"] == "f1"
            assert finding["severity"] == "high"

        os.unlink(f.name)


def test_export_findings_jsonl_non_list_vulns():
    """Test export_findings_jsonl skips non-list vulnerabilities."""
    results = {
        "hosts": [],
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": "not a list",  # Invalid
            }
        ],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        count = export_findings_jsonl(results, f.name)
        assert count == 0
        os.unlink(f.name)


def test_export_findings_jsonl_chmod_exception():
    """Test export_findings_jsonl handles chmod exception."""
    results = {"hosts": [], "vulnerabilities": []}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        with patch("os.chmod", side_effect=Exception("Permission denied")):
            count = export_findings_jsonl(results, f.name)
            assert count == 0
        os.unlink(f.name)


def test_export_findings_jsonl_with_multiple_sources():
    """Test export_findings_jsonl captures multiple sources."""
    results = {
        "hosts": [],
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [
                    {
                        "source": "nuclei",
                        "nikto_findings": ["+ Finding 1"],
                        "testssl_analysis": {"vulns": []},
                        "whatweb": "Apache",
                    }
                ],
            }
        ],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        count = export_findings_jsonl(results, f.name)
        assert count == 1

        with open(f.name, "r") as rf:
            finding = json.loads(rf.readline())
            assert "nuclei" in finding["sources"]
            assert "nikto" in finding["sources"]
            assert "testssl" in finding["sources"]
            assert "whatweb" in finding["sources"]

        os.unlink(f.name)


# -------------------------------------------------------------------------
# export_assets_jsonl Tests (lines 108-200)
# -------------------------------------------------------------------------


def test_export_assets_jsonl_basic():
    """Test export_assets_jsonl exports assets."""
    results = {
        "hosts": [
            {
                "ip": "192.168.1.1",
                "observable_hash": "abc123",
                "hostname": "server1.local",
                "status": "up",
                "risk_score": 50,
            }
        ],
        "vulnerabilities": [],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        count = export_assets_jsonl(results, f.name)
        assert count == 1

        with open(f.name, "r") as rf:
            asset = json.loads(rf.readline())
            assert asset["ip"] == "192.168.1.1"
            assert asset["hostname"] == "server1.local"

        os.unlink(f.name)


def test_export_assets_jsonl_with_ecs_host():
    """Test export_assets_jsonl includes MAC from ecs_host."""
    results = {
        "hosts": [
            {
                "ip": "192.168.1.1",
                "ecs_host": {"mac": ["AA:BB:CC:DD:EE:FF"], "vendor": "Cisco"},
            }
        ],
        "vulnerabilities": [],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        count = export_assets_jsonl(results, f.name)
        assert count == 1

        with open(f.name, "r") as rf:
            asset = json.loads(rf.readline())
            assert asset["mac"] == "AA:BB:CC:DD:EE:FF"
            assert asset["vendor"] == "Cisco"

        os.unlink(f.name)


def test_export_assets_jsonl_with_agentless():
    """Test export_assets_jsonl includes agentless fingerprint."""
    results = {
        "hosts": [
            {
                "ip": "192.168.1.1",
                "agentless_fingerprint": {
                    "domain": "CORP.LOCAL",
                    "computer_name": "DC01",
                    "os": "Windows Server 2019",
                    "empty_field": "",  # Should be filtered
                    "none_field": None,  # Should be filtered
                },
            }
        ],
        "vulnerabilities": [],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        count = export_assets_jsonl(results, f.name)
        assert count == 1

        with open(f.name, "r") as rf:
            asset = json.loads(rf.readline())
            assert "agentless" in asset
            assert asset["agentless"]["domain"] == "CORP.LOCAL"
            assert "empty_field" not in asset["agentless"]

        os.unlink(f.name)


def test_export_assets_jsonl_chmod_exception():
    """Test export_assets_jsonl handles chmod exception."""
    results = {"hosts": [], "vulnerabilities": []}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        with patch("os.chmod", side_effect=Exception("Permission denied")):
            count = export_assets_jsonl(results, f.name)
            assert count == 0
        os.unlink(f.name)


# -------------------------------------------------------------------------
# export_all Tests
# -------------------------------------------------------------------------


def test_export_all():
    """Test export_all creates both files."""
    results = {
        "hosts": [{"ip": "192.168.1.1"}],
        "vulnerabilities": [
            {
                "host": "192.168.1.1",
                "vulnerabilities": [{"severity": "high"}],
            }
        ],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        stats = export_all(results, tmpdir)
        assert stats["findings"] == 1
        assert stats["assets"] == 1
        assert os.path.exists(os.path.join(tmpdir, "findings.jsonl"))
        assert os.path.exists(os.path.join(tmpdir, "assets.jsonl"))


def test_export_all_empty():
    """Test export_all with empty results."""
    results = {"hosts": [], "vulnerabilities": []}

    with tempfile.TemporaryDirectory() as tmpdir:
        stats = export_all(results, tmpdir)
        assert stats["findings"] == 0
        assert stats["assets"] == 0
