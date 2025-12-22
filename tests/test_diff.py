#!/usr/bin/env python3
"""
RedAudit - Tests for diff report helpers.
"""

import builtins
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from redaudit.core import diff


def _write_report(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_load_report_rejects_missing_and_invalid(tmp_path):
    assert diff.load_report(str(tmp_path / "missing.json")) is None

    bad_path = tmp_path / "bad.json"
    bad_path.write_text("not json", encoding="utf-8")
    assert diff.load_report(str(bad_path)) is None

    invalid = tmp_path / "invalid.json"
    _write_report(invalid, {"version": "x"})
    assert diff.load_report(str(invalid)) is None


def test_generate_diff_report_and_formatters(tmp_path):
    old_report = {
        "version": "3.6.0",
        "timestamp": "2025-01-01T00:00:00",
        "hosts": [
            {
                "ip": "10.0.0.1",
                "ports": [{"port": 80, "service": "http"}],
                "known_exploits": [],
            }
        ],
        "vulnerabilities": [{"host": "10.0.0.1", "vulnerabilities": [{"nikto_findings": ["x"]}]}],
    }
    new_report = {
        "version": "3.6.0",
        "timestamp": "2025-01-02T00:00:00",
        "hosts": [
            {
                "ip": "10.0.0.1",
                "hostname": "host1",
                "ports": [
                    {"port": 80, "service": "http"},
                    {"port": 443, "service": "https", "known_exploits": ["CVE-1"]},
                ],
            },
            {"ip": "10.0.0.2", "ports": []},
        ],
        "vulnerabilities": [
            {"host": "10.0.0.1", "vulnerabilities": [{"nikto_findings": ["y", "z"]}]}
        ],
    }

    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    _write_report(old_path, old_report)
    _write_report(new_path, new_report)

    diff_report = diff.generate_diff_report(str(old_path), str(new_path))
    assert diff_report is not None
    assert diff_report["summary"]["new_hosts_count"] == 1
    assert diff_report["summary"]["removed_hosts_count"] == 0
    assert diff_report["summary"]["changed_hosts_count"] == 1
    assert diff_report["summary"]["web_vuln_delta"] == 1

    text = diff.format_diff_text(diff_report)
    assert "RedAudit Differential Analysis Report" in text
    assert "NEW HOSTS" in text
    assert "WEB VULNERABILITY CHANGES" in text

    md = diff.format_diff_markdown(diff_report)
    assert "# RedAudit Differential Analysis Report" in md
    assert "## Web Vulnerability Changes" in md


def test_format_diff_html_fallbacks():
    diff_report = {
        "generated_at": "2025-01-01",
        "old_report": {"path": "old.json", "timestamp": "t1", "total_hosts": 1},
        "new_report": {"path": "new.json", "timestamp": "t2", "total_hosts": 1},
        "changes": {
            "new_hosts": [],
            "removed_hosts": [],
            "changed_hosts": [],
            "web_vuln_changes": [],
        },
        "summary": {
            "new_hosts_count": 0,
            "removed_hosts_count": 0,
            "changed_hosts_count": 0,
            "total_new_ports": 0,
            "total_closed_ports": 0,
            "total_new_vulnerabilities": 0,
            "web_vuln_delta": 0,
            "has_changes": False,
        },
    }

    real_import = builtins.__import__

    def _import(name, *args, **kwargs):
        if name == "jinja2":
            raise ImportError("no jinja2")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_import):
        html = diff.format_diff_html(diff_report)
    assert "RedAudit Differential Analysis Report" in html

    class _Template:
        def render(self, **_kwargs):
            raise ValueError("boom")

    class _Env:
        def get_template(self, _name):
            return _Template()

    class _Environment:
        def __init__(self, **_kwargs):
            pass

        def get_template(self, _name):
            return _Template()

    class _PackageLoader:
        def __init__(self, *_args, **_kwargs):
            pass

    def _select_autoescape(_types):
        return []

    fake_jinja2 = SimpleNamespace(
        Environment=_Environment,
        PackageLoader=_PackageLoader,
        select_autoescape=_select_autoescape,
    )

    with patch.dict("sys.modules", {"jinja2": fake_jinja2}):
        html = diff.format_diff_html(diff_report)
    assert "Error generating HTML diff" in html
