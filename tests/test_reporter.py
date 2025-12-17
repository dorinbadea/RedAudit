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
