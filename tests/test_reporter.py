#!/usr/bin/env python3
"""
RedAudit - Reporter Module Tests
Tests for report generation functionality.
"""

import sys
import os
import json
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.reporter import (
    _build_config_snapshot,
    _summarize_agentless,
    _summarize_net_discovery,
    _summarize_smart_scan,
    _summarize_vulnerabilities,
    generate_summary,
    generate_text_report,
    save_results,
)
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
                        {"nikto_findings": ["+ test"]},
                        {"testssl_analysis": {"summary": "ok"}},
                        {"template_id": "http-test"},
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
            "udp_mode": "quick",
            "udp_top_ports": 100,
            "topology_enabled": True,
            "net_discovery_enabled": True,
            "net_discovery_redteam": True,
            "windows_verify_enabled": True,
            "scan_vulnerabilities": False,
            "nuclei_enabled": True,
            "dry_run": True,
            "auditor_name": "tester",
        }
        snapshot = _build_config_snapshot(config)
        self.assertEqual(snapshot["targets"], ["10.0.0.0/24"])
        self.assertEqual(snapshot["scan_mode"], "full")
        self.assertEqual(snapshot["scan_mode_cli"], "fast")
        self.assertEqual(snapshot["threads"], 4)
        self.assertEqual(snapshot["rate_limit_delay"], 0.5)
        self.assertEqual(snapshot["udp_mode"], "quick")
        self.assertEqual(snapshot["udp_top_ports"], 100)
        self.assertTrue(snapshot["topology_enabled"])
        self.assertTrue(snapshot["net_discovery_enabled"])
        self.assertTrue(snapshot["net_discovery_redteam"])
        self.assertTrue(snapshot["windows_verify_enabled"])
        self.assertFalse(snapshot["scan_vulnerabilities"])
        self.assertTrue(snapshot["nuclei_enabled"])
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


if __name__ == "__main__":
    unittest.main()
