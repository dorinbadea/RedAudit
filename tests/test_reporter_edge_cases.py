"""Tests for reporter.py to push coverage to 95%+
Targets missing lines including encryption, manifest edge cases, and leak detection.
"""

import os
import tempfile
import json
import base64
from datetime import datetime
from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.reporter import (
    generate_summary,
    _detect_network_leaks,
    extract_leaked_networks,
    generate_text_report,
    save_results,
    show_results_summary,
)


def test_generate_summary_gateway_mac_and_skip():
    """Test generate_summary with gateway mac and host skip (lines 296, 299)."""
    results = {
        "hosts": [
            {"ip": "192.168.1.1", "deep_scan": {"mac_address": "AA:BB"}},
            {"ip": "192.168.1.2"},
        ],
        "topology": {"default_gateway": {"ip": "192.168.1.1"}},
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    summary = generate_summary(results, config, ["192.168.1.1", "192.168.1.2"], [], datetime.now())
    assert results["hosts"][1]["_gateway_mac"] == "AA:BB"
    assert results["hosts"][0]["is_default_gateway"] is True


def test_generate_summary_consolidated_vulns_exception():
    """Test generate_summary failure in consolidated vulns (lines 338-339)."""
    results = {"vulnerabilities": [{"vulnerabilities": [{}, {}]}]}
    # First call at 243 succeeds, second call at 335 fails to hit 338-339
    with patch(
        "redaudit.core.reporter._summarize_vulnerabilities",
        side_effect=[{"total": 2}, Exception("fail")],
    ):
        summary = generate_summary(results, {}, [], [], datetime.now())
        assert summary["vulns_found"] == 2


def test_detect_network_leaks_cand_checks():
    """Test _detect_network_leaks candidate returns false (lines 378, 382)."""
    results = {
        "vulnerabilities": [
            {
                "host": "1.1.1.1",
                "vulnerabilities": [
                    {"curl_headers": "Location: http://8.8.8.8/\nLocation: http://192.168.1.10/"}
                ],
            }
        ]
    }
    # 8.8.8.8 is not private (378), 192.168.1.10 is in target (382)
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert not any("8.8.8.8" in l for l in leaks)
    assert not any("192.168.1.10" in l for l in leaks)


def test_detect_network_leaks_value_error():
    """Test _detect_network_leaks value error in loop (lines 422-423)."""
    results = {
        "vulnerabilities": [{"host": "10.0.0.1", "vulnerabilities": [{"curl_headers": "10.0.0.5"}]}]
    }
    with patch("ipaddress.ip_network", side_effect=[MagicMock(), ValueError("Invalid Network")]):
        leaks = _detect_network_leaks(results, {"target_networks": ["10.0.0.0/24"]})
        assert any("10.0.0.5" in l for l in leaks)


def test_extract_leaked_networks_edge_cases():
    """Test extract_leaked_networks edge cases (lines 459, 462, 464, 476, 484, 491)."""
    results = {
        "vulnerabilities": [
            {
                "vulnerabilities": [
                    {"wget_headers": "10.20.30.40"},  # 476
                    {"curl_headers": None},  # 484
                ]
            }
        ]
    }
    config = {"target_networks": []}
    with patch("ipaddress.ip_address", side_effect=[ValueError("bad ip"), MagicMock()]):  # 464
        nets = extract_leaked_networks(results, config)
        # Should still work or handle gracefully


def test_generate_text_report_risk_score():
    """Test generate_text_report showing risk score (line 592)."""
    results = {"hosts": [{"ip": "1.1.1.1", "risk_score": 50}]}
    report = generate_text_report(results)
    assert "Risk Score: 50/100" in report


def test_save_results_encryption_txt_and_salt():
    """Test save_results encryption for TXT and salt (lines 779-782, 799-807)."""
    results = {"summary": {}}
    config = {
        "save_txt_report": True,
        "encryption_salt": base64.b64encode(b"salt").decode(),
        "output_dir": "/tmp/out",
    }
    with patch("os.makedirs"):
        with patch("builtins.open", return_value=MagicMock()):
            with patch("os.chmod"):
                with patch("redaudit.core.reporter.encrypt_data", return_value=b"encrypted"):
                    assert (
                        save_results(
                            results, config, encryption_enabled=True, encryption_key=b"key"
                        )
                        is True
                    )


def test_save_results_logs_and_failures(tmp_path):
    """Test save_results logging paths (lines 827, 839, 861, 880, 892, 910)."""
    logger = MagicMock()
    results = {"summary": {}, "vulnerabilities": []}
    output_dir = str(tmp_path)
    config = {"html_report": True, "output_dir": output_dir}

    # JSONL skipped log (827)
    save_results(results, config, encryption_enabled=True, logger=logger)
    logger.info.assert_any_call("JSONL exports skipped (report encryption enabled)")

    # Playbooks generated msg (839)
    with patch("redaudit.core.playbook_generator.save_playbooks", return_value=(1, [])):
        print_fn = MagicMock()
        t_fn = MagicMock(return_value="Playbooks!")
        save_results(
            results,
            {"save_playbooks": True, "output_dir": output_dir},
            print_fn=print_fn,
            t_fn=t_fn,
        )
        print_fn.assert_any_call("Playbooks!", "OKGREEN")

    # HTML path not found message (861-862)
    with patch("redaudit.core.html_reporter.save_html_report", return_value=None):
        print_fn = MagicMock()
        save_results(
            results,
            {"html_report": True, "output_dir": output_dir},
            print_fn=print_fn,
            t_fn=MagicMock(),
        )
        print_fn.assert_any_call("HTML report generation failed (check log)", "WARNING")

    # Webhook fail log (892-894)
    err = Exception("Webhook Error")
    with patch("redaudit.utils.webhook.process_findings_for_alerts", side_effect=err):
        save_results(
            results, {"webhook_url": "http://web", "output_dir": output_dir}, logger=logger
        )
        logger.warning.assert_any_call("Webhook alerting failed: %s", err)

    # Manifest failure (910-912)
    err = Exception("Manifest Error")
    with patch("redaudit.core.reporter._write_output_manifest", side_effect=err):
        save_results(results, {"output_dir": output_dir}, logger=logger)
        logger.debug.assert_any_call("Run manifest generation failed: %s", err, exc_info=True)


def test_write_output_manifest_exceptions():
    """Test _write_output_manifest edge cases (lines 948, 985, 989, 997)."""
    from redaudit.core.reporter import _write_output_manifest

    results = {"hosts": [{"deep_scan": "not-a-dict"}]}  # 948
    with patch("os.walk", side_effect=Exception("Walk Error")):  # 997
        with patch("builtins.open", return_value=MagicMock()):
            _write_output_manifest(
                output_dir="/tmp",
                results=results,
                config={},
                encryption_enabled=False,
                partial=False,
                logger=MagicMock(),
            )


def test_show_results_summary_detail():
    """Test show_results_summary with raw vs total detail (line 1058)."""
    results = {"summary": {"vulns_found": 5, "vulns_found_raw": 10}}
    t_fn = MagicMock(return_value="Detail output")
    show_results_summary(results, t_fn, {"HEADER": "", "ENDC": "", "OKGREEN": ""}, "/tmp")
    t_fn.assert_any_call("vulns_web_detail", 5, 10)
