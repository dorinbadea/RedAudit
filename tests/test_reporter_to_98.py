import os
import io
import json
import pytest
import tempfile
import shutil
from datetime import datetime
from unittest.mock import MagicMock, patch
from redaudit.core.reporter import (
    save_results,
    generate_text_report,
    _detect_network_leaks,
    extract_leaked_networks,
    show_config_summary,
    show_results_summary,
    generate_summary,
    _infer_vuln_source,
)


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp()
    yield d
    if os.path.exists(d):
        try:
            shutil.rmtree(d)
        except Exception:
            pass


# -------------------------------------------------------------------------
# Leak Detection
# -------------------------------------------------------------------------


def test_leak_detection_and_extraction():
    results = {
        "vulnerabilities": [
            {
                "host": "1.1.1.1",
                "vulnerabilities": [
                    {
                        "curl_headers": "Location: http://192.168.10.5/",
                        "nikto_findings": ["10.0.1.10 backend"],
                    },
                    {"redirect_url": "http://172.16.0.1/"},
                ],
            }
        ]
    }
    config = {"target_networks": ["1.1.0.0/16"]}

    leaks = _detect_network_leaks(results, config)
    assert any("192.168.10.5" in l for l in leaks)
    assert any("10.0.1.10" in l for l in leaks)

    net_cidrs = extract_leaked_networks(results, config)
    assert "192.168.10.0/24" in net_cidrs
    assert "10.0.1.0/24" in net_cidrs


def test_leak_detection_empty():
    assert _detect_network_leaks({}, {}) == []
    assert extract_leaked_networks({}, {}) == []


# -------------------------------------------------------------------------
# Text Report Generation
# -------------------------------------------------------------------------


def test_generate_text_report_detailed():
    results = {
        "config": {"target_networks": ["1.1.0.0/16"]},
        "summary": {
            "networks": 1,
            "hosts_found": 1,
            "hosts_scanned": 1,
            "vulns_found": 2,
            "duration": "1s",
        },
        "config_snapshot": {"auditor_name": "Antigravity"},
        "hosts": [
            {
                "ip": "1.1.1.1",
                "hostname": "host1",
                "status": "up",
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "version": "1.0",
                        "cve_count": 5,
                        "cve_max_severity": "HIGH",
                        "known_exploits": ["E1"],
                    }
                ],
                "deep_scan": {
                    "mac_address": "AA:BB",
                    "vendor": "V",
                    "commands": ["cmd1"],
                    "pcap_capture": {"pcap_file": "f.pcap"},
                },
                "agentless_fingerprint": {
                    "computer_name": "WIN1",
                    "os": "Windows",
                    "ssh_hostkeys": ["key1"],
                },
                "cve_summary": {"total": 5, "critical": 1, "high": 2},
                "dns": {"reverse": ["host1.local"], "whois_summary": "Test Whois"},
            }
        ],
        "vulnerabilities": [
            {
                "host": "1.1.1.1",
                "vulnerabilities": [
                    {
                        "source": "nuclei",
                        "severity": "high",
                        "severity_score": 9.0,
                        "template_id": "T1",
                        "cve_ids": ["CVE-1", "CVE-2"],
                        "matched_at": "http://x/p",
                    },
                    {
                        "url": "http://x",
                        "severity": "info",
                        "whatweb": "nginx",
                        "nikto_findings": ["F1"],
                        "testssl_analysis": {"summary": "OK", "vulnerabilities": ["SSLv3"]},
                        "potential_false_positives": ["FP1"],
                        "curl_headers": "Location: http://192.168.50.1/",
                    },
                ],
            }
        ],
        "pipeline": {
            "net_discovery": {"enabled": True, "counts": {"arp_hosts": 1}},
            "agentless_verify": {"targets": 1, "completed": 1},
            "smart_scan_summary": {"identity_score_avg": 5},
        },
    }
    report = generate_text_report(results)
    assert "POTENTIAL HIDDEN NETWORKS" in report
    assert "Auditor: Antigravity" in report
    assert "known_exploits" in report.lower() or "⚠️" in report


def test_infer_vuln_source():
    assert _infer_vuln_source({"source": "manual"}) == "manual"
    assert _infer_vuln_source({"original_severity": {"tool": "nikto"}}) == "nikto"
    assert _infer_vuln_source({"template_id": "nuclei-id"}) == "nuclei"
    assert _infer_vuln_source({}) == "unknown"


# -------------------------------------------------------------------------
# Save Results
# -------------------------------------------------------------------------


def test_save_results_with_encryption(temp_dir):
    results = {"summary": {}, "hosts": []}
    config = {"output_dir": temp_dir}

    with (
        patch("redaudit.core.reporter.encrypt_data", return_value=b"encrypted") as mock_enc,
        patch("os.chmod"),
    ):
        result = save_results(
            results, config, encryption_enabled=True, encryption_key=b"key", partial=True
        )
        assert result is True


def test_save_results_full_branches(temp_dir):
    results = {
        "summary": {},
        "hosts": [{"deep_scan": {"pcap_capture": {"pcap_file": "test.pcap"}}}],
        "vulnerabilities": [{"host": "1.1.1.1", "vulnerabilities": [{"name": "V"}]}],
    }
    config = {
        "output_dir": temp_dir,
        "save_txt_report": True,
        "encryption_salt": "c2FsdA==",
        "save_html_report": True,
        "webhook_url": "http://hook",
        "lang": "es",
    }

    with (
        patch("redaudit.core.jsonl_exporter.export_all", return_value={"findings": 1, "assets": 1}),
        patch("redaudit.core.html_reporter.save_html_report", return_value="/path/html"),
        patch("redaudit.core.playbook_generator.save_playbooks", return_value=1),
        patch("redaudit.utils.webhook.process_findings_for_alerts", return_value=1),
        patch("redaudit.core.reporter.maybe_chown_tree_to_invoking_user"),
        patch("redaudit.core.reporter.os.chmod"),
    ):

        result = save_results(
            results,
            config,
            print_fn=MagicMock(),
            t_fn=lambda x, *args: f"T({x})",
            logger=MagicMock(),
        )
        assert result is True


def test_save_results_exceptions(temp_dir):
    results = {"summary": {}, "hosts": []}
    config = {"output_dir": temp_dir}

    # Trigger export error
    with (
        patch("redaudit.core.jsonl_exporter.export_all", side_effect=ImportError("no")),
        patch("os.chmod"),
    ):
        save_results(results, config, logger=MagicMock())

    # Trigger html error
    config["save_html_report"] = True
    with (
        patch("redaudit.core.html_reporter.save_html_report", side_effect=Exception("fail")),
        patch("os.chmod"),
    ):
        save_results(results, config, logger=MagicMock(), print_fn=MagicMock())


# -------------------------------------------------------------------------
# Console Summary Views
# -------------------------------------------------------------------------


def test_show_summaries():
    config = {
        "target_networks": ["net"],
        "scan_mode": "normal",
        "threads": 1,
        "windows_verify_enabled": True,
        "windows_verify_max_targets": 10,
        "output_dir": "/tmp",
    }
    colors = {k: "" for k in ["HEADER", "OKBLUE", "OKGREEN", "WARNING", "FAIL", "ENDC", "CYAN"]}

    with patch("sys.stdout", new=io.StringIO()) as out:
        show_config_summary(config, lambda x, *args: x, colors)

        results = {
            "summary": {"hosts_found": 1, "hosts_scanned": 1, "vulns_found": 1, "duration": "1s"},
            "hosts": [{"deep_scan": {"pcap_capture": {"pcap_file": "f.pcap"}}}],
            "pipeline": {"net_discovery": {"enabled": True}},
        }
        show_results_summary(results, lambda x, *args: x, colors, "/tmp")
        content = out.getvalue()
        assert "net" in content


# -------------------------------------------------------------------------
# Summary Generation Edge Cases
# -------------------------------------------------------------------------


def test_generate_summary_comprehensive():
    results = {
        "hosts": [{"ip": "1.1.1.1", "device_type_hints": ["pc"]}],
        "vulnerabilities": [{"host": "1.1.1.1", "vulnerabilities": [{"source": "nmap"}]}],
        "topology": {"default_gateway": {"ip": "1.1.1.1"}},
    }
    config = {"target_networks": ["1.1.1.0/24"]}
    all_hosts = ["1.1.1.1"]
    scanned = results["hosts"]

    summary = generate_summary(results, config, all_hosts, scanned, datetime.now())
    assert summary["hosts_found"] == 1
    assert results["hosts"][0].get("is_default_gateway")


def test_manifest_edge_cases(temp_dir):
    from redaudit.core.reporter import _write_output_manifest

    # Test with non-string output_dir
    assert (
        _write_output_manifest(
            output_dir=None, results={}, config={}, encryption_enabled=False, partial=False
        )
        is None
    )

    # Test walk error or property error
    results = {"hosts": ["invalid"], "vulnerabilities": [None]}  # will trigger if host.get fails
    path = _write_output_manifest(
        output_dir=temp_dir, results=results, config={}, encryption_enabled=False, partial=False
    )
    assert os.path.exists(path)
