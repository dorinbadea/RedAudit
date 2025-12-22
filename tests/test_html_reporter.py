#!/usr/bin/env python3
"""
RedAudit - Tests for HTML report helpers.
"""

from pathlib import Path
from unittest.mock import patch

from redaudit.core import html_reporter


def test_extract_finding_title_variants():
    assert html_reporter._extract_finding_title({"descriptive_title": "Custom"}) == "Custom"
    assert (
        html_reporter._extract_finding_title({"nikto_findings": ["Interesting finding here"]})
        == "Interesting finding here"
    )
    assert (
        html_reporter._extract_finding_title(
            {"nikto_findings": ["Target IP: 10.0.0.1"], "url": "http://x"}
        )
        == "http://x"
    )


def test_prepare_report_data_populates_tables():
    results = {
        "timestamp": "2025-01-01",
        "hosts": [
            {
                "ip": "10.0.0.1",
                "hostname": "host1",
                "status": "up",
                "ports": [{"port": 80, "service": "http"}],
                "risk_score": 5,
                "deep_scan": {"mac_address": "aa", "vendor": "acme"},
                "os_detected": "linux",
                "asset_type": "server",
                "tags": ["web"],
                "agentless_fingerprint": {"computer_name": "HOST1"},
            }
        ],
        "vulnerabilities": [
            {
                "host": "10.0.0.1",
                "vulnerabilities": [
                    {
                        "severity": "high",
                        "category": "web",
                        "url": "http://10.0.0.1",
                        "port": 80,
                        "cve_ids": ["CVE-1"],
                        "descriptive_title": "Finding title",
                    }
                ],
            }
        ],
        "summary": {"total_hosts": 1},
        "pipeline": {"stage": "done"},
        "smart_scan_summary": {"total": 1},
        "config_snapshot": {"threads": 1},
    }
    config = {"target_networks": ["10.0.0.0/24"], "scan_mode": "normal"}

    data = html_reporter.prepare_report_data(results, config)
    assert data["host_count"] == 1
    assert data["finding_count"] == 1
    assert data["severity_counts"]["high"] == 1
    assert data["top_ports"] == [(80, 1)]
    assert data["host_table"][0]["agentless"] == "HOST1"
    assert data["finding_table"][0]["title"] == "Finding title"


def test_generate_and_save_html_report(tmp_path):
    results = {"hosts": [], "vulnerabilities": [], "summary": {}}
    config = {"target_networks": [], "scan_mode": "normal", "auditor_name": "x"}

    class _Template:
        def render(self, **kwargs):
            return f"<html>{kwargs['scan_mode']}</html>"

    class _Env:
        def get_template(self, _name):
            return _Template()

    with patch("redaudit.core.html_reporter.get_template_env", return_value=_Env()):
        html = html_reporter.generate_html_report(results, config, lang="en")
        assert html == "<html>normal</html>"

        out_dir = Path(tmp_path)
        path = html_reporter.save_html_report(
            results,
            config,
            str(out_dir),
            filename="report.html",
            lang="en",
        )
        assert path is not None
        assert Path(path).read_text(encoding="utf-8") == "<html>normal</html>"
