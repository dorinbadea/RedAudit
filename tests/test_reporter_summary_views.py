#!/usr/bin/env python3
"""
Coverage for reporter summary display helpers.
"""

from __future__ import annotations

from redaudit.core import reporter


def test_show_config_summary_includes_windows_verify(capsys):
    config = {
        "target_networks": ["10.0.0.0/24"],
        "scan_mode": "normal",
        "threads": 4,
        "scan_vulnerabilities": True,
        "cve_lookup_enabled": True,
        "output_dir": "/tmp/output",
        "windows_verify_enabled": True,
        "windows_verify_max_targets": 5,
    }
    colors = {"HEADER": "", "ENDC": ""}
    t_fn = lambda key, *_args: key

    reporter.show_config_summary(config, t_fn, colors)

    captured = capsys.readouterr().out
    assert "windows_verify" in captured
    assert "max 5" in captured


def test_show_results_summary_counts_pcaps(capsys):
    results = {
        "summary": {
            "networks": 1,
            "hosts_found": 2,
            "hosts_scanned": 2,
            "vulns_found": 0,
            "duration": "0:01:00",
        },
        "hosts": [
            {"deep_scan": {"pcap_capture": {"pcap_file": "capture1.pcap"}}},
            {"deep_scan": {"pcap_capture": {"pcap_file": None}}},
        ],
    }
    colors = {"HEADER": "", "ENDC": "", "OKGREEN": ""}
    t_fn = lambda key, *_args: key

    reporter.show_results_summary(results, t_fn, colors, "/tmp/output")

    captured = capsys.readouterr().out
    assert "pcaps" in captured
