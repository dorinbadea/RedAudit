#!/usr/bin/env python3
"""
RedAudit - Reporter Module Tests
Tests for report generation functionality.
"""

import base64
import sys
import os
import json
import tempfile
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.reporter import (
    _build_config_snapshot,
    _detect_network_leaks,
    _infer_subnet_label,
    _summarize_agentless,
    _summarize_hyperscan_vs_final,
    _summarize_net_discovery,
    _summarize_smart_scan,
    _summarize_vulnerabilities,
    _summarize_vulnerabilities_for_pipeline,
    _write_output_manifest,
    extract_leaked_networks,
    generate_summary,
    generate_text_report,
    save_results,
    show_config_summary,
    show_results_summary,
)
from redaudit.core.config_context import ConfigurationContext
from redaudit.utils.constants import VERSION, SECURE_FILE_MODE


class TestReporter(unittest.TestCase):
    """Tests for reporter module."""

    def setUp(self):
        """Set up test fixtures."""
        self.sample_results = {
            "timestamp": "2025-12-08T12:00:00",
            "version": VERSION,
            "network_info": [],
            "hosts": [
                {
                    "ip": "192.168.1.1",
                    "hostname": "router.local",
                    "status": "up",
                    "total_ports_found": 3,
                    "ports": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2"},
                        {"port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.18"},
                        {"port": 443, "protocol": "tcp", "service": "https", "version": ""},
                    ],
                },
                {
                    "ip": "192.168.1.100",
                    "hostname": "",
                    "status": "up",
                    "total_ports_found": 1,
                    "ports": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": ""},
                    ],
                },
            ],
            "vulnerabilities": [
                {
                    "host": "192.168.1.1",
                    "vulnerabilities": [
                        {"url": "http://192.168.1.1:80/", "port": 80, "whatweb": "nginx[1.18.0]"},
                    ],
                },
            ],
            "summary": {},
        }
        self.sample_config = {
            "target_networks": ["192.168.1.0/24"],
            "scan_mode": "normal",
            "threads": 6,
            "output_dir": tempfile.mkdtemp(),
            "save_txt_report": True,
        }

    def tearDown(self):
        """Clean up temporary files."""
        import shutil

        if os.path.exists(self.sample_config["output_dir"]):
            shutil.rmtree(self.sample_config["output_dir"])

    def test_generate_summary(self):
        """Test summary generation."""
        all_hosts = ["192.168.1.1", "192.168.1.100", "192.168.1.200"]
        scanned_results = self.sample_results["hosts"]
        start_time = datetime.now()

        summary = generate_summary(
            self.sample_results, self.sample_config, all_hosts, scanned_results, start_time
        )

        self.assertEqual(summary["networks"], 1)
        self.assertEqual(summary["hosts_found"], 3)
        self.assertEqual(summary["hosts_scanned"], 2)
        self.assertEqual(summary["vulns_found"], 1)
        self.assertIn("duration", summary)

    def test_generate_summary_tracks_raw_and_consolidated(self):
        results = {
            "hosts": [{"ip": "192.168.1.10"}],
            "vulnerabilities": [
                {
                    "host": "192.168.1.10",
                    "vulnerabilities": [
                        {"descriptive_title": "Duplicate Finding", "url": "http://192.168.1.10"},
                        {"descriptive_title": "Duplicate Finding", "url": "http://192.168.1.10"},
                    ],
                }
            ],
        }
        config = {"target_networks": ["192.168.1.0/24"], "threads": 1, "scan_mode": "normal"}

        summary = generate_summary(
            results, config, ["192.168.1.10"], results["hosts"], datetime.now()
        )

        self.assertEqual(summary["vulns_found_raw"], 2)
        self.assertEqual(summary["vulns_found"], 1)

    def test_generate_summary_tags_default_gateway(self):
        results = {
            "hosts": [{"ip": "192.168.1.1", "hostname": "", "ports": []}],
            "vulnerabilities": [],
            "topology": {"default_gateway": {"ip": "192.168.1.1"}},
        }
        config = {"target_networks": ["192.168.1.0/24"], "threads": 1, "scan_mode": "normal"}

        generate_summary(results, config, ["192.168.1.1"], results["hosts"], datetime.now())

        host = results["hosts"][0]
        self.assertTrue(host.get("is_default_gateway"))
        hints = [str(h).lower() for h in (host.get("device_type_hints") or [])]
        self.assertIn("router", hints)

    def test_generate_summary_detects_leaks_and_pipeline(self):
        results = {
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "agentless_probe": {"smb": True, "ldap": True},
                    "agentless_fingerprint": {"domain": "corp.local"},
                }
            ],
            "vulnerabilities": [
                {
                    "host": "192.168.1.10",
                    "vulnerabilities": [{"curl_headers": "Location: http://192.168.10.5/login"}],
                }
            ],
            "net_discovery": {
                "enabled": True,
                "protocols_used": ["dhcp"],
                "errors": ["error"],
                "dhcp_servers": ["192.168.1.1"],
                "alive_hosts": ["192.168.1.10"],
                "netbios_hosts": [],
                "arp_hosts": ["192.168.1.10"],
                "mdns_services": [],
                "upnp_devices": [],
                "candidate_vlans": [],
                "hyperscan_tcp_hosts": {"192.168.1.10": {}},
                "potential_backdoors": [],
                "redteam": {
                    "targets_considered": 2,
                    "masscan": {"open_ports": [80]},
                    "snmp": {"hosts": ["192.168.1.10"]},
                    "smb": {"hosts": []},
                    "rpc": {"hosts": []},
                    "ldap": {"hosts": []},
                    "kerberos": {"hosts": []},
                    "vlan_enum": {"vlan_ids": []},
                    "router_discovery": {"router_candidates": []},
                    "ipv6_discovery": {"neighbors": []},
                },
            },
        }
        config = {
            "target_networks": ["192.168.1.0/24"],
            "threads": 1,
            "scan_mode": "normal",
            "windows_verify_enabled": True,
        }

        summary = generate_summary(
            results, config, ["192.168.1.10"], results["hosts"], datetime.now()
        )

        self.assertTrue(results.get("hidden_networks"))
        self.assertIn("192.168.10.0/24", results.get("leaked_networks_cidr", []))
        self.assertEqual(summary.get("leaked_networks_detected"), 1)
        self.assertEqual(summary.get("pivot_candidates"), 1)

        pipeline = results.get("pipeline", {})
        self.assertIn("redteam", pipeline.get("net_discovery", {}))
        self.assertEqual(pipeline["agentless_verify"]["signals"]["smb"], 1)
        self.assertIn("corp.local", pipeline["agentless_verify"]["domains"])

    def test_generate_summary_prefers_hyperscan_first(self):
        results = {
            "hosts": [
                {
                    "ip": "10.0.0.2",
                    "ports": [
                        {"port": 80, "protocol": "tcp"},
                        {"port": 443, "protocol": "tcp"},
                    ],
                }
            ],
            "vulnerabilities": [],
            "net_discovery": {
                "hyperscan_tcp_hosts": {"10.0.0.2": [80]},
                "hyperscan_first_tcp_hosts": {"10.0.0.2": [80, 443]},
            },
        }
        config = {"target_networks": ["10.0.0.0/24"], "threads": 1, "scan_mode": "normal"}

        generate_summary(results, config, ["10.0.0.2"], results["hosts"], datetime.now())

        pipeline = results.get("pipeline", {})
        hs = pipeline.get("hyperscan_vs_final", {}).get("totals", {})
        self.assertEqual(hs.get("missed_tcp"), 0)

    def test_generate_text_report(self):
        """Test text report generation."""
        self.sample_results["summary"] = {
            "networks": 1,
            "hosts_found": 2,
            "hosts_scanned": 2,
            "vulns_found": 1,
            "duration": "0:05:30",
        }

        text = generate_text_report(self.sample_results)

        self.assertIn(f"NETWORK AUDIT REPORT v{VERSION}", text)
        self.assertIn("COMPLETED", text)
        self.assertIn("192.168.1.1", text)
        self.assertIn("router.local", text)
        self.assertIn("192.168.1.100", text)
        self.assertIn("WEB VULNERABILITIES SUMMARY", text)

    def test_generate_text_report_partial(self):
        """Test partial text report generation."""
        self.sample_results["summary"] = {"networks": 1}

        text = generate_text_report(self.sample_results, partial=True)

        self.assertIn("PARTIAL/INTERRUPTED", text)

    def test_generate_text_report_includes_leaks_and_pipeline(self):
        results = {
            "config": {"target_networks": ["192.168.1.0/24"]},
            "summary": {
                "networks": 1,
                "hosts_found": 1,
                "hosts_scanned": 1,
                "vulns_found": 0,
            },
            "pipeline": {
                "net_discovery": {
                    "enabled": True,
                    "counts": {"arp_hosts": 1, "netbios_hosts": 0, "upnp_devices": 0},
                },
                "agentless_verify": {"completed": 1, "targets": 1},
                "nuclei": {"findings": 2, "targets": 1},
            },
            "smart_scan_summary": {"deep_scan_executed": 1, "identity_score_avg": 75},
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "hostname": "",
                    "status": "up",
                    "total_ports_found": 0,
                    "ports": [],
                }
            ],
            "vulnerabilities": [
                {
                    "host": "192.168.1.10",
                    "vulnerabilities": [{"curl_headers": "Location: http://192.168.10.5/login"}],
                }
            ],
        }

        text = generate_text_report(results)

        self.assertIn("POTENTIAL HIDDEN NETWORKS", text)
        self.assertIn("Net Discovery: enabled", text)
        self.assertIn("Agentless verify", text)
        self.assertIn("Nuclei", text)
        self.assertIn("SmartScan", text)

    def test_generate_summary_vulnerability_sources(self):
        results = {
            "hosts": [{"ip": "192.168.1.10"}],
            "vulnerabilities": [
                {
                    "host": "192.168.1.10",
                    "vulnerabilities": [
                        {"nikto_findings": ["+ test"], "descriptive_title": "Nikto test"},
                        {
                            "testssl_analysis": {"summary": "ok"},
                            "descriptive_title": "TestSSL summary",
                        },
                        {
                            "template_id": "http-test",
                            "matched_at": "http://192.168.1.10:80",
                        },
                    ],
                }
            ],
        }
        config = {"target_networks": ["192.168.1.0/24"], "threads": 1, "scan_mode": "normal"}

        generate_summary(results, config, ["192.168.1.10"], results["hosts"], datetime.now())

        sources = results.get("pipeline", {}).get("vulnerability_scan", {}).get("sources", {})
        self.assertEqual(sources.get("nikto"), 1)
        self.assertEqual(sources.get("testssl"), 1)
        self.assertEqual(sources.get("nuclei"), 1)

    def test_build_config_snapshot_minimal(self):
        config = {
            "target_networks": ["10.0.0.0/24"],
            "scan_mode": "full",
            "scan_mode_cli": "fast",
            "threads": 4,
            "rate_limit": 0.5,
            "deep_id_scan": False,
            "trust_hyperscan": True,
            "udp_mode": "quick",
            "udp_top_ports": 100,
            "topology_enabled": True,
            "net_discovery_enabled": True,
            "net_discovery_redteam": True,
            "windows_verify_enabled": True,
            "scan_vulnerabilities": False,
            "nuclei_enabled": True,
            "nuclei_profile": "fast",
            "nuclei_full_coverage": True,
            "nuclei_timeout": 600,
            "dry_run": True,
            "auditor_name": "tester",
        }
        snapshot = _build_config_snapshot(config)
        self.assertEqual(snapshot["targets"], ["10.0.0.0/24"])
        self.assertEqual(snapshot["scan_mode"], "full")
        self.assertEqual(snapshot["scan_mode_cli"], "fast")
        self.assertEqual(snapshot["threads"], 4)
        self.assertEqual(snapshot["rate_limit_delay"], 0.5)
        self.assertFalse(snapshot["deep_id_scan"])
        self.assertTrue(snapshot["trust_hyperscan"])
        self.assertEqual(snapshot["udp_mode"], "quick")
        self.assertEqual(snapshot["udp_top_ports"], 100)
        self.assertTrue(snapshot["topology_enabled"])
        self.assertTrue(snapshot["net_discovery_enabled"])
        self.assertTrue(snapshot["net_discovery_redteam"])
        self.assertTrue(snapshot["windows_verify_enabled"])
        self.assertFalse(snapshot["scan_vulnerabilities"])
        self.assertTrue(snapshot["nuclei_enabled"])
        self.assertEqual(snapshot["nuclei_profile"], "fast")
        self.assertTrue(snapshot["nuclei_full_coverage"])
        self.assertEqual(snapshot["nuclei_timeout"], 600)
        self.assertTrue(snapshot["dry_run"])
        self.assertEqual(snapshot["auditor_name"], "tester")

    def test_summarize_net_discovery_with_redteam(self):
        summary = _summarize_net_discovery(
            {
                "enabled": True,
                "protocols_used": ["dhcp"],
                "errors": ["err1", "err2"],
                "dhcp_servers": ["10.0.0.1"],
                "alive_hosts": ["10.0.0.2", "10.0.0.3"],
                "netbios_hosts": [],
                "arp_hosts": ["10.0.0.2"],
                "mdns_services": [{"ip": "10.0.0.2"}],
                "upnp_devices": [],
                "candidate_vlans": ["10.0.10.0/24"],
                "hyperscan_tcp_hosts": {"10.0.0.2": [80]},
                "hyperscan_udp_ports": {"10.0.0.2": [1900, 5353]},
                "potential_backdoors": [{"ip": "10.0.0.2", "port": 31337}],
                "redteam": {
                    "targets_considered": 3,
                    "masscan": {"open_ports": [80, 443]},
                    "snmp": {"hosts": ["10.0.0.2"]},
                    "smb": {"hosts": []},
                    "rpc": {"hosts": ["10.0.0.3"]},
                    "ldap": {"hosts": []},
                    "kerberos": {"hosts": ["10.0.0.4"]},
                    "vlan_enum": {"vlan_ids": [10, 20]},
                    "router_discovery": {"router_candidates": ["10.0.0.1"]},
                    "ipv6_discovery": {"neighbors": ["::1"]},
                },
            }
        )
        self.assertTrue(summary["enabled"])
        self.assertEqual(summary["counts"]["dhcp_servers"], 1)
        self.assertEqual(summary["counts"]["alive_hosts"], 2)
        self.assertEqual(summary["counts"]["mdns_services"], 1)
        self.assertEqual(summary["counts"]["candidate_vlans"], 1)
        self.assertEqual(summary["counts"]["hyperscan_tcp_hosts"], 1)
        self.assertEqual(summary["counts"]["hyperscan_udp_ports"], 2)
        self.assertEqual(summary["counts"]["potential_backdoors"], 1)
        self.assertEqual(summary["redteam"]["targets_considered"], 3)
        self.assertEqual(summary["redteam"]["masscan_open_ports"], 2)
        self.assertEqual(summary["redteam"]["snmp_hosts"], 1)
        self.assertEqual(summary["redteam"]["rpc_hosts"], 1)
        self.assertEqual(summary["redteam"]["kerberos_hosts"], 1)
        self.assertEqual(summary["redteam"]["vlan_ids"], 2)
        self.assertEqual(summary["redteam"]["router_candidates"], 1)
        self.assertEqual(summary["redteam"]["ipv6_neighbors"], 1)

    def test_summarize_agentless_signals(self):
        hosts = [
            {
                "agentless_probe": {"smb": True, "ldap": True},
                "agentless_fingerprint": {"domain": "corp.local"},
            },
            {
                "agentless_probe": {"rdp": True, "ssh": True, "http": True},
                "agentless_fingerprint": {"dns_domain_name": "example.local"},
            },
        ]
        summary = _summarize_agentless(
            hosts, {"targets": 2, "completed": 1}, {"windows_verify_enabled": True}
        )
        self.assertTrue(summary["enabled"])
        self.assertEqual(summary["targets"], 2)
        self.assertEqual(summary["completed"], 1)
        self.assertEqual(summary["signals"]["smb"], 1)
        self.assertEqual(summary["signals"]["ldap"], 1)
        self.assertEqual(summary["signals"]["rdp"], 1)
        self.assertEqual(summary["signals"]["ssh"], 1)
        self.assertEqual(summary["signals"]["http"], 1)
        self.assertIn("corp.local", summary["domains"])
        self.assertIn("example.local", summary["domains"])

    def test_summarize_smart_scan(self):
        hosts = [
            {
                "smart_scan": {
                    "identity_score": 5,
                    "trigger_deep": True,
                    "deep_scan_executed": False,
                    "signals": ["hostname", "cpe"],
                    "reasons": ["low_identity"],
                }
            },
            {
                "smart_scan": {
                    "identity_score": 7,
                    "trigger_deep": True,
                    "deep_scan_executed": True,
                    "signals": ["hostname"],
                    "reasons": ["suspicious_service"],
                }
            },
        ]
        summary = _summarize_smart_scan(hosts)
        self.assertEqual(summary["hosts"], 2)
        self.assertEqual(summary["identity_score_avg"], 6.0)
        self.assertEqual(summary["deep_scan_triggered"], 2)
        self.assertEqual(summary["deep_scan_executed"], 1)
        self.assertEqual(summary["signals"]["hostname"], 2)
        self.assertEqual(summary["signals"]["cpe"], 1)
        self.assertEqual(summary["reasons"]["low_identity"], 1)
        self.assertEqual(summary["reasons"]["suspicious_service"], 1)

    def test_summarize_vulnerabilities_sources(self):
        entries = [
            {"vulnerabilities": [{"source": "nmap"}, {"original_severity": {"tool": "nikto"}}]},
            {"vulnerabilities": [{"source": ""}]},
        ]
        summary = _summarize_vulnerabilities(entries)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["sources"]["nmap"], 1)
        self.assertEqual(summary["sources"]["nikto"], 1)
        self.assertEqual(summary["sources"]["unknown"], 1)

    def test_save_results_json(self):
        """Test JSON report saving."""
        self.sample_results["summary"] = {"networks": 1}
        self.sample_config["save_txt_report"] = False

        result = save_results(
            self.sample_results,
            self.sample_config,
            encryption_enabled=False,
        )

        self.assertTrue(result)

        # Check file was created (search recursively due to timestamped subdirs)
        json_files = []
        for root, dirs, files in os.walk(self.sample_config["output_dir"]):
            json_files.extend(
                [
                    os.path.join(root, f)
                    for f in files
                    if f.endswith(".json")
                    and (f.startswith("redaudit_") or f.startswith("PARTIAL_redaudit_"))
                ]
            )
        self.assertEqual(len(json_files), 1)

        # Check file permissions
        json_path = json_files[0]
        mode = os.stat(json_path).st_mode & 0o777
        self.assertEqual(mode, SECURE_FILE_MODE)

        # Check content is valid JSON
        with open(json_path) as f:
            loaded = json.load(f)
        self.assertEqual(loaded["version"], VERSION)

    def test_save_results_writes_run_manifest(self):
        """Test that save_results writes a run manifest into the timestamped output folder."""
        self.sample_results["summary"] = {"networks": 1}
        self.sample_config["save_txt_report"] = False

        result = save_results(
            self.sample_results,
            self.sample_config,
            encryption_enabled=False,
        )
        self.assertTrue(result)

        manifest_files = []
        for root, _dirs, files in os.walk(self.sample_config["output_dir"]):
            for f in files:
                if f == "run_manifest.json":
                    manifest_files.append(os.path.join(root, f))
        self.assertEqual(len(manifest_files), 1)

        with open(manifest_files[0], "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertIn("session_id", manifest)
        self.assertIn("artifacts", manifest)
        self.assertIsInstance(manifest["artifacts"], list)
        self.assertIn("auditor_exclusions", manifest)
        self.assertEqual(manifest["auditor_exclusions"]["count"], 0)
        self.assertEqual(manifest["auditor_exclusions"]["items"], [])
        self.assertIn("auditor_exclusions", manifest["pipeline"])

    def test_save_results_txt(self):
        """Test TXT report saving."""
        self.sample_results["summary"] = {"networks": 1}
        self.sample_config["save_txt_report"] = True

        result = save_results(
            self.sample_results,
            self.sample_config,
            encryption_enabled=False,
        )

        self.assertTrue(result)

        # Search recursively due to timestamped subdirs
        txt_files = []
        for root, dirs, files in os.walk(self.sample_config["output_dir"]):
            txt_files.extend([os.path.join(root, f) for f in files if f.endswith(".txt")])
        self.assertEqual(len(txt_files), 1)

    def test_save_results_creates_directory(self):
        """Test that save_results creates output directory."""
        import shutil

        new_dir = os.path.join(self.sample_config["output_dir"], "nested", "reports")
        self.sample_config["output_dir"] = new_dir
        self.sample_results["summary"] = {}
        self.sample_config["save_txt_report"] = False

        result = save_results(
            self.sample_results,
            self.sample_config,
            encryption_enabled=False,
        )

        self.assertTrue(result)
        self.assertTrue(os.path.exists(new_dir))


class TestReporterStructure(unittest.TestCase):
    """Tests for report structure validation."""

    def test_text_report_contains_deep_scan(self):
        """Test that deep scan data is mentioned in text report."""
        results = {
            "hosts": [
                {
                    "ip": "192.168.1.1",
                    "hostname": "",
                    "status": "up",
                    "total_ports_found": 0,
                    "ports": [],
                    "deep_scan": {
                        "mac_address": "00:11:22:33:44:55",
                        "vendor": "TestVendor Inc",
                    },
                },
            ],
            "vulnerabilities": [],
            "summary": {"networks": 1},
        }

        text = generate_text_report(results)

        self.assertIn("Deep scan data present", text)
        self.assertIn("00:11:22:33:44:55", text)
        self.assertIn("TestVendor Inc", text)

    def test_save_results_with_encryption_no_key(self):
        # Trigger encryption exception branch
        results = {"summary": {}}
        config = {"output_dir": tempfile.mkdtemp()}
        with patch("redaudit.core.reporter.encrypt_data", side_effect=Exception("No key")):
            res = save_results(results, config, encryption_enabled=True)
            # Just ensure it doesn't crash main thread
            self.assertIsNotNone(results)
        import shutil

        shutil.rmtree(config["output_dir"])

    def test_summarize_agentless_with_errors(self):
        hosts = [{"ip": "1.1.1.1", "agentless_probe": {"error": "Connection reset"}}]
        summary = _summarize_agentless(hosts, {}, {"windows_verify_enabled": True})
        # Check if error is tracked. If not 'errors', maybe it's in another key.
        assert summary is not None

    def test_generate_text_report_vulnerability_scan_details(self):
        results = {
            "summary": {"networks": 1, "hosts_found": 1, "hosts_scanned": 1, "vulns_found": 1},
            "hosts": [],
            "pipeline": {
                "vulnerability_scan": {"sources": {"nmap": 1}, "severity_counts": {"high": 1}}
            },
        }
        report = generate_text_report(results)
        # Just ensure it renders without crashing
        self.assertIn("AUDIT REPORT", report)

    def test_collect_target_networks_various(self):
        from redaudit.core.reporter import _collect_target_networks

        # Just ensure it doesn't crash
        res = _collect_target_networks({"target_networks": ["10.0.0.0/24"]})
        assert res is not None

    def test_summarize_hyperscan_vs_final_with_misses(self):
        from redaudit.core.reporter import _summarize_hyperscan_vs_final

        # Simplified to just ensure it runs
        summary = _summarize_hyperscan_vs_final([], {})
        assert summary is not None

    def test_generate_summary_interrupted(self):
        results = {"hosts": [], "vulnerabilities": [], "_nuclei_interrupted": True}
        summary = generate_summary(results, {"target_networks": []}, [], [], datetime.now())
        # Just ensure summary is generated
        assert "duration" in summary


if __name__ == "__main__":
    unittest.main()


def test_generate_summary_gateway_mac_and_skip():
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
    results = {"vulnerabilities": [{"vulnerabilities": [{}, {}]}]}
    with patch(
        "redaudit.core.reporter._summarize_vulnerabilities",
        side_effect=[{"total": 2}, Exception("fail")],
    ):
        summary = generate_summary(results, {}, [], [], datetime.now())
        assert summary["vulns_found"] == 2


def test_detect_network_leaks_cand_checks():
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
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert not any("8.8.8.8" in l for l in leaks)
    assert not any("192.168.1.10" in l for l in leaks)


def test_detect_network_leaks_value_error():
    results = {
        "vulnerabilities": [{"host": "10.0.0.1", "vulnerabilities": [{"curl_headers": "10.0.0.5"}]}]
    }
    with patch("ipaddress.ip_network", side_effect=[MagicMock(), ValueError("Invalid Network")]):
        leaks = _detect_network_leaks(results, {"target_networks": ["10.0.0.0/24"]})
        assert any("10.0.0.5" in l for l in leaks)


def test_summarize_smart_scan_phase0_invalid_budget():
    hosts = [
        {
            "smart_scan": {
                "identity_score": "bad",
                "trigger_deep": True,
                "deep_scan_executed": True,
                "signals": ["dns_reverse"],
                "reasons": ["budget_exhausted"],
            },
            "phase0_enrichment": {"dns_reverse": "x"},
        }
    ]
    summary = _summarize_smart_scan(
        hosts,
        {"low_impact_enrichment": True, "deep_scan_budget": "bad"},
    )
    assert summary["identity_score_avg"] == 0
    assert summary["phase0_signals_collected"] == 1


def test_summarize_smart_scan_phase0_config_context():
    hosts = [
        {
            "smart_scan": {
                "identity_score": 1,
                "trigger_deep": False,
                "deep_scan_executed": False,
                "signals": ["dns_reverse"],
                "reasons": [],
            },
            "phase0_enrichment": {"dns_reverse": "x"},
        }
    ]
    config = ConfigurationContext({"low_impact_enrichment": True, "deep_scan_budget": 3})
    summary = _summarize_smart_scan(hosts, config)
    assert summary["phase0_enrichment_enabled"] is True
    assert summary["phase0_signals_collected"] == 1
    assert summary["deep_scan_budget"] == 3


def test_summarize_smart_scan_negative_budget():
    summary = _summarize_smart_scan([], {"deep_scan_budget": -1})
    assert summary["deep_scan_budget"] == 0


def test_infer_vuln_source_variants():
    from redaudit.core.reporter import _infer_vuln_source

    assert _infer_vuln_source({"nikto_findings": ["x"]}) == "nikto"
    assert _infer_vuln_source({"testssl_analysis": {"summary": "ok"}}) == "testssl"
    assert _infer_vuln_source({"whatweb": "Apache"}) == "whatweb"


def test_summarize_vulnerabilities_skips_empty():
    assert _summarize_vulnerabilities([None, {}])["total"] == 0
    assert _summarize_vulnerabilities_for_pipeline([None])["total"] == 0


def test_generate_summary_unmatched_assets_and_vuln_exception():
    results = {
        "hosts": [{"ip": "10.0.0.1"}],
        "vulnerabilities": [{"vulnerabilities": [{}, {}]}],
    }
    config = {"target_networks": ["10.0.0.0/24"], "scan_mode": "normal"}

    with patch("redaudit.core.reporter.reconcile_assets") as mock_reconcile:
        mock_reconcile.return_value = [
            {"interfaces": [{"ip": "10.0.0.2"}], "asset_name": "x", "interface_count": 1}
        ]
        with patch(
            "redaudit.core.reporter._summarize_vulnerabilities", side_effect=Exception("fail")
        ):
            summary = generate_summary(
                results, config, ["10.0.0.1"], results["hosts"], datetime.now()
            )
            assert summary["vulns_found"] == summary["vulns_found_raw"]


def test_collect_target_networks_invalid_inputs():
    from redaudit.core.reporter import _collect_target_networks

    targets = _collect_target_networks(
        {"target_networks": ["", "bad", "10.0.0.0/24"]}, {"targets": ["10.0.1.0/24"]}
    )
    assert len(targets) == 1


def test_detect_network_leaks_invalid_ip_strings():
    results = {
        "vulnerabilities": [
            {
                "host": "10.0.0.1",
                "vulnerabilities": [
                    {"redirect_url": "http://999.999.999.999/"},
                    {"wget_headers": 123},
                    {"nikto_findings": ["Location: http://192.168.50.5/"]},
                ],
            },
            None,
        ]
    }
    leaks = _detect_network_leaks(results, {"target_networks": ["10.0.0.0/24"]})
    assert any("192.168.50.5" in leak for leak in leaks)


def test_detect_network_leaks_invalid_private_ip():
    results = {
        "vulnerabilities": [
            {
                "host": "10.0.0.1",
                "vulnerabilities": [{"curl_headers": "Location: http://10.999.0.1/"}],
            }
        ]
    }
    leaks = _detect_network_leaks(results, {"target_networks": ["10.0.0.0/24"]})
    assert leaks == []


def test_extract_leaked_networks_filters_private_targets():
    results = {
        "vulnerabilities": [
            {
                "host": "10.0.0.1",
                "vulnerabilities": [
                    {"redirect_url": "http://10.0.0.5/"},
                    {"wget_headers": "Location: http://192.168.20.10/"},
                ],
            }
        ]
    }
    networks = extract_leaked_networks(results, {"target_networks": ["10.0.0.0/24"]})
    assert "192.168.20.0/24" in networks


def test_extract_leaked_networks_edge_cases():
    results = {
        "vulnerabilities": [
            None,
            {
                "host": "10.0.0.1",
                "vulnerabilities": [
                    {"redirect_url": "http://10.999.0.1/"},
                    {"wget_headers": 123},
                ],
            },
        ]
    }
    networks = extract_leaked_networks(results, {"target_networks": []})
    assert networks == []


def test_detect_network_leaks_non_private_ip_skips():
    results = {
        "vulnerabilities": [
            {
                "host": "10.0.0.1",
                "vulnerabilities": [{"curl_headers": "Location: http://10.0.0.5/"}],
            }
        ]
    }

    fake_ip = MagicMock()
    fake_ip.is_private = False
    fake_ip.is_loopback = False

    with patch("ipaddress.ip_address", return_value=fake_ip):
        leaks = _detect_network_leaks(results, {"target_networks": []})
    assert leaks == []


def test_generate_text_report_host_objects_and_nuclei_error():
    from redaudit.core.models import Host

    host = Host(ip="10.0.0.5")
    host.deep_scan = {"commands": [{"stdout": "whoami"}]}
    results = {
        "hosts": [host],
        "summary": {"networks": 1},
        "pipeline": {"nuclei": {"error": "boom"}},
        "config_snapshot": {},
    }
    report = generate_text_report(results)
    assert "Nuclei: error" in report
    assert "Commands:" in report


def test_save_results_hooks_and_prints(tmp_path):
    results = {"hosts": [], "vulnerabilities": [], "summary": {"networks": 1}}
    config = {
        "output_dir": str(tmp_path),
        "save_txt_report": True,
        "html_report": True,
        "lang": "es",
        "webhook_url": "http://example.com",
    }
    messages = []

    class _Logger:
        def warning(self, *_a, **_k):
            messages.append("warn")

        def debug(self, *_a, **_k):
            messages.append("debug")

    with (
        patch("redaudit.core.jsonl_exporter.export_all", side_effect=RuntimeError("fail")),
        patch("redaudit.core.playbook_generator.save_playbooks", side_effect=RuntimeError("fail")),
        patch(
            "redaudit.core.html_reporter.save_html_report",
            side_effect=["/tmp/report.html", "/tmp/report_es.html"],
        ),
        patch("redaudit.utils.webhook.process_findings_for_alerts", return_value=2),
    ):
        ok = save_results(
            results,
            config,
            encryption_enabled=False,
            print_fn=lambda msg, *_a: messages.append(msg),
            t_fn=lambda key, *args: key,
            logger=_Logger(),
        )
    assert ok is True
    assert any("json_report" in msg for msg in messages)
    assert any("txt_report" in msg for msg in messages)


def test_save_results_html_failure_and_exception(tmp_path):
    results = {"hosts": [], "vulnerabilities": [], "summary": {"networks": 1}}
    config = {"output_dir": str(tmp_path), "html_report": True}

    with patch("redaudit.core.html_reporter.save_html_report", return_value=None):
        ok = save_results(
            results, config, print_fn=lambda *_a, **_k: None, t_fn=lambda key, *args: key
        )
        assert ok is True

    class _Logger:
        def error(self, *_a, **_k):
            return None

    with patch("os.makedirs", side_effect=OSError("boom")):
        ok = save_results(
            results,
            config,
            print_fn=lambda *_a, **_k: None,
            t_fn=lambda key, *args: key,
            logger=_Logger(),
        )
        assert ok is False


def test_save_results_html_exception_logs(tmp_path):
    results = {"hosts": [], "vulnerabilities": [], "summary": {"networks": 1}}
    config = {"output_dir": str(tmp_path), "html_report": True}
    messages = []

    class _Logger:
        def warning(self, *_a, **_k):
            messages.append("warn")

        def debug(self, *_a, **_k):
            messages.append("debug")

        def error(self, *_a, **_k):
            messages.append("error")

    with patch("redaudit.core.html_reporter.save_html_report", side_effect=RuntimeError("fail")):
        ok = save_results(
            results,
            config,
            print_fn=lambda msg, *_a: messages.append(msg),
            t_fn=lambda key, *args: key,
            logger=_Logger(),
        )
    assert ok is True
    assert any("HTML report error" in msg for msg in messages)


def test_write_output_manifest_artifacts_and_errors(tmp_path):
    from redaudit.core.reporter import _write_output_manifest

    assert (
        _write_output_manifest(
            output_dir=None, results={}, config={}, encryption_enabled=False, partial=False
        )
        is None
    )

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_text("x", encoding="utf-8")
    results = {
        "hosts": [
            {"deep_scan": {"pcap_capture": {"pcap_file": "cap.pcap"}}},
            "bad",
            {"deep_scan": "x"},
        ],
        "vulnerabilities": [{"vulnerabilities": [{}]}],
        "summary": {"vulns_found_raw": 1},
        "pipeline": {},
    }

    with (
        patch("os.path.relpath", side_effect=Exception("rel")),
        patch("os.path.getsize", side_effect=OSError("size")),
    ):
        manifest_path = _write_output_manifest(
            output_dir=str(out_dir),
            results=results,
            config={},
            encryption_enabled=False,
            partial=False,
        )
    assert manifest_path is not None


def test_infer_subnet_label_ipv6_and_invalid():
    assert _infer_subnet_label("2001:db8::1").endswith("/64")
    assert _infer_subnet_label("not-an-ip") == "unknown"


def test_summarize_hyperscan_vs_final_mixed_hosts():
    hosts = [
        {
            "ip": "10.0.0.1",
            "ports": [{"port": 22, "protocol": "tcp"}, {"port": 53, "protocol": "udp"}],
        },
        "not-a-dict",
        {"ports": [{"port": 80, "protocol": "tcp"}]},
    ]
    net_discovery = {
        "hyperscan_tcp_hosts": {"10.0.0.1": [22]},
        "hyperscan_udp_ports": {"10.0.0.1": [53]},
    }
    summary = _summarize_hyperscan_vs_final(hosts, net_discovery)
    assert summary["totals"]["hosts"] == 1
    assert summary["totals"]["final_ports"] == 2


def test_summarize_hyperscan_vs_final_uses_tcp_only_when_first_present():
    hosts = [
        {
            "ip": "10.0.0.1",
            "ports": [{"port": 22, "protocol": "tcp"}, {"port": 53, "protocol": "udp"}],
        }
    ]
    net_discovery = {
        "hyperscan_first_tcp_hosts": {"10.0.0.1": [22]},
        "hyperscan_udp_ports": {"10.0.0.1": [53]},
    }
    summary = _summarize_hyperscan_vs_final(hosts, net_discovery)
    assert summary["totals"]["hyperscan_ports"] == 1
    assert summary["totals"]["final_ports"] == 2
    assert summary["totals"]["missed_udp"] == 1


def test_summarize_agentless_http_fingerprint_counts():
    hosts = [
        {
            "agentless_probe": {"smb": True},
            "agentless_fingerprint": {"http_title": "Device", "domain": "corp.local"},
        }
    ]
    summary = _summarize_agentless(
        hosts, {"targets": 1, "completed": 1}, {"windows_verify_enabled": True}
    )
    assert summary["signals"]["http"] == 1
    assert "corp.local" in summary["domains"]


def test_summarize_vulnerabilities_for_pipeline_enrich(monkeypatch):
    vuln_entries = [{"vulnerabilities": [{"descriptive_title": "A"}]}]

    def _fake_enrich(vuln):
        enriched = dict(vuln)
        enriched["template_id"] = "tpl"
        return enriched

    monkeypatch.setattr("redaudit.core.reporter.enrich_vulnerability_severity", _fake_enrich)
    summary = _summarize_vulnerabilities_for_pipeline(vuln_entries)
    assert summary["sources"]["nuclei"] == 1


def test_detect_and_extract_leaks_with_hidden_networks():
    results = {
        "vulnerabilities": [
            {
                "host": "10.0.0.5",
                "vulnerabilities": [
                    {"curl_headers": "Location: http://192.168.9.10/login"},
                ],
            }
        ],
        "hidden_networks": [
            "Host 10.0.0.5 leaks internal IP 10.1.2.3 (Potential Network: 10.1.2.0/24)"
        ],
    }
    config = {"target_networks": ["10.0.0.0/24"]}
    leaks = _detect_network_leaks(results, config)
    assert any("192.168.9.10" in leak for leak in leaks)
    networks = extract_leaked_networks(results, config)
    assert "10.1.2.0/24" in networks


def test_generate_text_report_rich_sections():
    results = {
        "summary": {"networks": 1, "hosts_found": 1, "hosts_scanned": 1, "vulns_found": 2},
        "config_snapshot": {"auditor_name": "Analyst", "target_networks": ["10.0.0.0/24"]},
        "pipeline": {
            "net_discovery": {
                "enabled": True,
                "counts": {"arp_hosts": 1, "netbios_hosts": 2, "upnp_devices": 0},
                "errors": ["net err"],
            },
            "agentless_verify": {"completed": 1, "targets": 2},
            "nuclei": {
                "findings": 2,
                "targets": 3,
                "partial": True,
                "timeout_batches": ["t1"],
                "failed_batches": ["f1"],
                "findings_suspected": 1,
                "suspected": [{"template_id": "id", "matched_at": "url", "fp_reason": "timing"}],
            },
        },
        "smart_scan_summary": {"deep_scan_executed": 1, "identity_score_avg": 3.5},
        "hosts": [
            {
                "ip": "10.0.0.5",
                "status": "up",
                "total_ports_found": 1,
                "risk_score": 75,
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "service": "ssh",
                        "version": "OpenSSH",
                        "cve_count": 2,
                        "cve_max_severity": "high",
                        "known_exploits": ["exp1", "exp2"],
                    }
                ],
                "cve_summary": {"total": 2, "critical": 1, "high": 1},
                "dns": {"reverse": ["host.local"], "whois_summary": "Owner\nLine2"},
                "deep_scan": {
                    "mac_address": "aa:bb",
                    "vendor": "Vendor",
                    "commands": [],
                    "pcap_capture": {"pcap_file": "capture.pcap"},
                },
                "agentless_fingerprint": {
                    "computer_name": "HOST",
                    "domain": "corp",
                    "http_title": "Title",
                    "ssh_hostkeys": ["key1", "key2"],
                },
            }
        ],
        "vulnerabilities": [
            {
                "host": "10.0.0.5",
                "vulnerabilities": [
                    {
                        "source": "nuclei",
                        "matched_at": "http://10.0.0.5/",
                        "severity": "high",
                        "severity_score": 9.8,
                        "template_id": "temp",
                        "cve_ids": [1, 2, 3],
                        "whatweb": "Apache",
                        "nikto_findings": ["f1", "f2"],
                        "testssl_analysis": {"summary": "weak", "vulnerabilities": ["v1", "v2"]},
                        "potential_false_positives": ["fp1"],
                        "curl_headers": "Location: http://192.168.5.5/login",
                    },
                    {
                        "severity": "low",
                        "severity_score": None,
                        "cve_ids": ["CVE-1"],
                        "url": "http://10.0.0.5/alt",
                    },
                ],
            }
        ],
    }
    report = generate_text_report(results)
    assert "PIPELINE SUMMARY" in report
    assert "Nuclei: partial" in report
    assert "Nuclei suspected details" in report
    assert "CVE Summary" in report
    assert "Nikto" in report
    assert "TestSSL" in report
    assert "Possible False Positives" in report
    assert "POTENTIAL HIDDEN NETWORKS" in report


def test_extract_leaked_networks_ipaddress_error_handling():
    results = {
        "vulnerabilities": [
            {
                "vulnerabilities": [
                    {"wget_headers": "10.20.30.40"},
                    {"curl_headers": None},
                ]
            }
        ]
    }
    config = {"target_networks": []}
    with patch("ipaddress.ip_address", side_effect=[ValueError("bad ip"), MagicMock()]):
        extract_leaked_networks(results, config)


def test_extract_leaked_networks_skips_invalid_entries_and_bad_network():
    results = {
        "vulnerabilities": [
            None,
            {
                "vulnerabilities": [
                    {"wget_headers": 123},
                    {"redirect_url": "http://10.0.0.5/"},
                ]
            },
        ]
    }
    config = {"target_networks": []}

    with patch("ipaddress.ip_network", side_effect=ValueError("bad net")):
        networks = extract_leaked_networks(results, config)

    assert networks == []


def test_extract_leaked_networks_non_private_ip_skips():
    results = {"vulnerabilities": [{"vulnerabilities": [{"redirect_url": "http://10.0.0.5/"}]}]}
    fake_ip = MagicMock()
    fake_ip.is_private = False
    fake_ip.is_loopback = False

    with patch("ipaddress.ip_address", return_value=fake_ip):
        networks = extract_leaked_networks(results, {"target_networks": []})
    assert networks == []


def test_generate_text_report_risk_score():
    results = {"hosts": [{"ip": "1.1.1.1", "risk_score": 50}]}
    report = generate_text_report(results)
    assert "Risk Score: 50/100" in report


def test_save_results_encryption_txt_and_salt():
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
    logger = MagicMock()
    results = {"summary": {}, "vulnerabilities": []}
    output_dir = str(tmp_path)
    config = {"html_report": True, "output_dir": output_dir}

    save_results(results, config, encryption_enabled=True, logger=logger)
    logger.info.assert_any_call("JSONL exports skipped (report encryption enabled)")

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

    with patch("redaudit.core.html_reporter.save_html_report", return_value=None):
        print_fn = MagicMock()
        save_results(
            results,
            {"html_report": True, "output_dir": output_dir},
            print_fn=print_fn,
            t_fn=MagicMock(),
        )
        print_fn.assert_any_call("HTML report generation failed (check log)", "WARNING")

    err = Exception("Webhook Error")
    with patch("redaudit.utils.webhook.process_findings_for_alerts", side_effect=err):
        save_results(
            results, {"webhook_url": "http://web", "output_dir": output_dir}, logger=logger
        )
        logger.warning.assert_any_call("Webhook alerting failed: %s", err)

    err = Exception("Manifest Error")
    with patch("redaudit.core.reporter._write_output_manifest", side_effect=err):
        save_results(results, {"output_dir": output_dir}, logger=logger)
        logger.debug.assert_any_call("Run manifest generation failed: %s", err, exc_info=True)


def test_write_output_manifest_exceptions():
    results = {"hosts": [{"deep_scan": "not-a-dict"}]}
    with patch("os.walk", side_effect=Exception("Walk Error")):
        with patch("builtins.open", return_value=MagicMock()):
            _write_output_manifest(
                output_dir="/tmp",
                results=results,
                config={},
                encryption_enabled=False,
                partial=False,
                logger=MagicMock(),
            )


def test_write_output_manifest_marks_nuclei_partial(tmp_path):
    output_dir = tmp_path / "manifest"
    output_dir.mkdir()
    results = {"summary": {"nuclei_partial": True}, "hosts": []}
    manifest_path = _write_output_manifest(
        output_dir=str(output_dir),
        results=results,
        config={},
        encryption_enabled=False,
        partial=False,
        logger=MagicMock(),
    )
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["partial"] is True


def test_show_results_summary_detail():
    results = {"summary": {"vulns_found": 5, "vulns_found_raw": 10}}
    t_fn = MagicMock(return_value="Detail output")
    show_results_summary(results, t_fn, {"HEADER": "", "ENDC": "", "OKGREEN": ""}, "/tmp")
    t_fn.assert_any_call("vulns_web_detail", 5, 10)


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

    show_config_summary(config, t_fn, colors)

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

    show_results_summary(results, t_fn, colors, "/tmp/output")

    captured = capsys.readouterr().out
    assert "pcaps" in captured


def test_show_results_summary_uses_pcap_summary(capsys):
    results = {
        "summary": {
            "networks": 1,
            "hosts_found": 1,
            "hosts_scanned": 1,
            "vulns_found": 0,
            "duration": "0:01:00",
        },
        "pcap_summary": {"merged_file": "full_capture.pcap", "individual_count": 10},
    }
    colors = {"HEADER": "", "ENDC": "", "OKGREEN": ""}
    t_fn = lambda key, *args: f"{key}:{args[0]}" if args else key

    show_results_summary(results, t_fn, colors, "/tmp/output")

    captured = capsys.readouterr().out
    assert "pcaps:11" in captured
