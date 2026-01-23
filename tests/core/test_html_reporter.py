#!/usr/bin/env python3
"""
RedAudit - Tests for HTML report helpers.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from redaudit.core import html_reporter


def test_extract_finding_title_variants():
    assert html_reporter._extract_finding_title({"descriptive_title": "Custom"}) == "Custom"
    assert (
        html_reporter._extract_finding_title({"nikto_findings": ["Interesting finding here"]})
        == "Interesting finding here"
    )
    # v4.6.20: When nikto has only metadata, fall back to structured title (not raw URL)
    assert (
        html_reporter._extract_finding_title(
            {"nikto_findings": ["Target IP: 10.0.0.1"], "url": "http://x"}
        )
        == "HTTP Service Finding on Port 0"
    )
    assert (
        html_reporter._extract_finding_title({"url": "https://example.com", "port": 443})
        == "HTTP Service Finding on Port 443"
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


def test_prepare_report_data_translates_titles_es():
    results = {
        "timestamp": "2025-01-01",
        "hosts": [{"ip": "10.0.0.1", "ports": [{"port": 80}]}],
        "vulnerabilities": [
            {
                "host": "10.0.0.1",
                "vulnerabilities": [
                    {"descriptive_title": "Missing X-Content-Type-Options Header", "port": 80},
                    {"descriptive_title": "Web Service Finding on Port 443", "port": 443},
                ],
            }
        ],
        "summary": {},
    }
    config = {"target_networks": ["10.0.0.0/24"], "scan_mode": "normal"}

    data = html_reporter.prepare_report_data(results, config, lang="es")
    titles = [finding["title"] for finding in data["finding_table"]]
    assert "Falta la cabecera X-Content-Type-Options" in titles
    assert "Hallazgo de servicio web en el puerto 443" in titles


def test_prepare_report_data_translates_auth_errors_es():
    results = {
        "hosts": [],
        "vulnerabilities": [],
        "summary": {},
        "auth_scan": {"errors": [{"ip": "1.2.3.4", "error": "All credentials failed"}]},
    }
    config = {"target_networks": [], "scan_mode": "normal"}

    data = html_reporter.prepare_report_data(results, config, lang="es")
    assert data["auth_scan"]["errors"] == ["1.2.3.4: Todas las credenciales fallaron"]


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


def test_get_reverse_dns_empty():
    assert html_reporter._get_reverse_dns({}) == ""
    assert html_reporter._get_reverse_dns({"dns": {"reverse": [None]}}) == ""
    assert html_reporter._get_reverse_dns({"dns": {"reverse": ["host.local."]}}) == "host.local"


def test_basename_filter_empty():
    env = html_reporter.get_template_env()
    basename_filter = env.filters["basename"]
    assert basename_filter("") == ""
    assert basename_filter(None) == ""
    assert basename_filter("/path/to/file.txt") == "file.txt"


def test_prepare_report_data_no_observations():
    results = {
        "vulnerabilities": [
            {
                "host": "1.2.3.4",
                "vulnerabilities": [
                    {
                        "severity": "high",
                        "parsed_observations": None,
                        "nikto_findings": None,
                    }
                ],
            }
        ]
    }
    data = html_reporter.prepare_report_data(results, {"target_networks": []})
    assert data["finding_table"][0]["observations"] == []


def test_extract_finding_title_evidence_parser_exception():
    vuln = {"parsed_observations": ["some observation"]}
    with patch(
        "redaudit.core.evidence_parser._derive_descriptive_title",
        side_effect=Exception("parse error"),
    ):
        title = html_reporter._extract_finding_title(vuln)
        assert "Service Finding" in title or "Finding" in title


def test_extract_finding_title_evidence_parser_none():
    vuln = {"parsed_observations": ["some observation"]}
    with patch("redaudit.core.evidence_parser._derive_descriptive_title", return_value=None):
        title = html_reporter._extract_finding_title(vuln)
        assert "Service Finding" in title or "Finding" in title


def test_translate_finding_title_fallback():
    assert html_reporter._translate_finding_title("Unknown Title", "es") == "Unknown Title"
    assert html_reporter._translate_finding_title("Unknown Title", "en") == "Unknown Title"


def test_prepare_report_data_with_reverse_dns():
    results = {"hosts": [{"ip": "1.2.3.4", "dns": {"reverse": ["myhost.local."]}}]}
    data = html_reporter.prepare_report_data(results, {})
    assert data["host_table"][0]["hostname"] == "myhost.local"


def test_get_template_env_import_error():
    with patch.dict("sys.modules", {"jinja2": None}):
        try:
            html_reporter.get_template_env()
            assert False, "Should have raised ImportError"
        except (ImportError, AttributeError):
            pass


def test_save_html_report_chmod_error():
    results = {
        "hosts": [],
        "vulnerabilities": [],
        "summary": {},
        "timestamp": "2025-01-01",
        "pipeline": {},
        "smart_scan_summary": {},
        "config_snapshot": {},
    }
    config = {"target_networks": ["192.168.1.0/24"], "scan_mode": "smart"}

    class _Template:
        def render(self, **kwargs):
            return "<html>test</html>"

    class _Env:
        def get_template(self, _name):
            return _Template()

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.html_reporter.get_template_env", return_value=_Env()):
            with patch("os.chmod", side_effect=PermissionError("Mock chmod error")):
                output_path = html_reporter.save_html_report(results, config, tmpdir)
                assert output_path is not None
                assert os.path.exists(output_path)


def test_save_html_report_generation_error():
    results = {"hosts": [], "vulnerabilities": []}
    config = {}

    with patch(
        "redaudit.core.html_reporter.generate_html_report", side_effect=RuntimeError("Mock error")
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = html_reporter.save_html_report(results, config, tmpdir)
            assert output_path is None
