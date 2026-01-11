#!/usr/bin/env python3
"""
Tests for Phase 4: Authenticated Scanning - Scanning Logic
"""

import unittest
from unittest.mock import MagicMock, patch, ANY
import sys
from dataclasses import dataclass, field
from typing import Dict, List

# Mock dependencies
sys.modules["nmap"] = MagicMock()

from redaudit.core.auditor_scan import AuditorScan
from redaudit.core.models import Host, Service
from redaudit.core.auth_ssh import SSHHostInfo, SSHConnectionError
from redaudit.core.credentials import Credential


# Minimal test class that mixes in AuditorScan
class TestAuditor(AuditorScan):
    __test__ = False

    def __init__(self, config=None):
        self.config = config or {}
        self.ui = MagicMock()
        self.logger = MagicMock()
        self.scanner = MagicMock()
        self.results = {}
        self.lock = MagicMock()

    def _coerce_text(self, value):
        return str(value)

    def _set_ui_detail(self, text):
        pass


class TestPhase4Scanning(unittest.TestCase):

    def setUp(self):
        self.auditor = TestAuditor()
        self.auditor.ui.t.side_effect = lambda x, *args: x  # Mock translation

    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_scan_host_ports_auth_trigger(self, MockSSHScanner):
        """Test that SSHScanner is triggered when creds + port 22 present."""

        # Setup Config
        self.auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "root",
            "auth_ssh_key": "/tmp/key",
            "auth_ssh_trust_keys": True,
            "timeout": 5,
            "scan_mode": "normal",
        }

        # Setup Host and Nmap result
        host_ip = "192.168.1.10"

        # Mock scanner.get_or_create_host -> Host
        host_obj = Host(ip=host_ip)
        self.auditor.scanner.get_or_create_host.return_value = host_obj

        # Mock nmap
        mock_nm_data = MagicMock()
        mock_nm_data.all_protocols.return_value = ["tcp"]
        # Setup a service on port 22
        mock_service = {
            "name": "ssh",
            "state": "open",
            "product": "OpenSSH",
            "version": "8.0",
            "extrainfo": "",
            "cpe": "",
        }
        mock_nm_data.__getitem__.side_effect = lambda x: {22: mock_service} if x == "tcp" else {}

        # We need to mock AuditorScan.run_nmap_command (Wait, it calls run_nmap_command imported?)
        # auditor_scan calls `self.scanner.run_nmap_scan` inside scan_host_ports?
        # Let's check auditor_scan.py source.
        # Line ~1034: `self.scanner.run_nmap_scan(...)`
        # But wait, `scan_host_ports` calls `run_nmap_command`? No.

        # Mock nmap object (PortScanner-like)
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [host_ip]
        mock_nm.__getitem__.return_value = mock_nm_data

        mock_nm.__getitem__.return_value = mock_nm_data

        # run_nmap_scan returns (nm, error) - 2 values
        self.auditor.scanner.run_nmap_scan.return_value = (mock_nm, None)

        # Mock SSHScanner instance
        mock_ssh_instance = MockSSHScanner.return_value
        mock_ssh_instance.connect.return_value = True
        mock_ssh_instance.gather_host_info.return_value = SSHHostInfo(
            os_name="Linux", os_version="5.4", hostname="testbox"
        )

        # Execute
        result_host = self.auditor.scan_host_ports(host_ip)

        # Assertions
        # 1. SSHScanner initialized with correct args
        MockSSHScanner.assert_called_once()
        args, kwargs = MockSSHScanner.call_args
        self.assertEqual(args[0].username, "root")
        self.assertEqual(kwargs["trust_unknown_keys"], True)

        # 2. Connect called
        mock_ssh_instance.connect.assert_called_with(host_ip, port=22)

        # 3. Host object updated
        self.assertIn("auth_scan", result_host.__dict__)  # Dataclass usually has fields
        # Wait, auth_scan is a field in Host model (added in v4.1)
        # Check content
        self.assertEqual(result_host.auth_scan.get("hostname"), "testbox")
        self.assertEqual(result_host.os_detected, "Linux 5.4")  # Merged OS

    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_scan_host_ports_auth_no_creds(self, MockSSHScanner):
        """Test that SSHScanner is NOT triggered without creds."""
        self.auditor.config = {"scan_mode": "normal"}  # No auth config

        host_ip = "192.168.1.11"
        host_obj = Host(ip=host_ip)
        self.auditor.scanner.get_or_create_host.return_value = host_obj

        mock_nm_data = MagicMock()
        mock_nm_data.all_protocols.return_value = ["tcp"]
        # Port 22 open but no creds
        mock_service = {"name": "ssh", "state": "open"}
        mock_nm_data.__getitem__.side_effect = lambda x: {22: mock_service} if x == "tcp" else {}

        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [host_ip]
        mock_nm.__getitem__.return_value = mock_nm_data

        mock_nm.all_hosts.return_value = [host_ip]
        mock_nm.__getitem__.return_value = mock_nm_data

        self.auditor.scanner.run_nmap_scan.return_value = (mock_nm, None)

        # Execute
        self.auditor.scan_host_ports(host_ip)

        # Assert
        MockSSHScanner.assert_not_called()

    @patch("redaudit.core.auth_smb.SMBScanner")
    def test_scan_host_ports_smb_trigger(self, MockSMBScanner):
        """Test that SMBScanner is triggered when creds + port 445 present."""

        # Setup Config
        self.auditor.config = {
            "auth_enabled": True,
            "auth_smb_user": "admin",
            "auth_smb_pass": "pass123",
            "timeout": 5,
            "scan_mode": "normal",
        }

        host_ip = "192.168.1.15"
        host_obj = Host(ip=host_ip)
        self.auditor.scanner.get_or_create_host.return_value = host_obj

        # Mock nmap with port 445
        mock_nm_data = MagicMock()
        mock_nm_data.all_protocols.return_value = ["tcp"]
        mock_service = {
            "name": "microsoft-ds",
            "state": "open",
            "product": "Windows 10",
            "version": "",
        }
        mock_nm_data.__getitem__.side_effect = lambda x: {445: mock_service} if x == "tcp" else {}

        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [host_ip]
        mock_nm.__getitem__.return_value = mock_nm_data

        self.auditor.scanner.run_nmap_scan.return_value = (mock_nm, None)

        # Mock SMBScanner instance
        mock_smb_instance = MockSMBScanner.return_value
        mock_smb_instance.connect.return_value = True

        # Mock info return. Need an object with attributes.
        @dataclass
        class MockSMBInfo:
            os_name: str = "Windows Server 2022"
            os_version: str = "10.0"
            domain: str = "CORP"
            shares: List[Dict] = field(default_factory=list)
            hostname: str = "FILE01"

        mock_smb_instance.gather_host_info.return_value = MockSMBInfo(
            shares=[{"name": "C$", "type": "0"}]
        )

        # Execute
        result_host = self.auditor.scan_host_ports(host_ip)

        # Assertions
        # 1. SMBScanner initialized
        MockSMBScanner.assert_called_once()
        args, _ = MockSMBScanner.call_args
        self.assertEqual(args[0].username, "admin")
        self.assertEqual(args[0].password, "pass123")

        # 2. Connect called
        mock_smb_instance.connect.assert_called_with(host_ip, 445)

        # 3. Host object updated
        # Check auth_scan content (merged asdict of MockSMBInfo)
        self.assertIn("domain", result_host.auth_scan)
        self.assertEqual(result_host.auth_scan["domain"], "CORP")
        self.assertEqual(result_host.os_detected, "Windows Server 2022 10.0")

    @patch("redaudit.core.auth_snmp.SNMPScanner")
    def test_scan_host_ports_snmp_trigger(self, MockSNMPScanner):
        """Test that SNMPScanner is triggered when creds + port 161 present."""

        # Setup Config
        self.auditor.config = {
            "auth_enabled": True,
            "auth_snmp_user": "snmpuser",
            "auth_snmp_pass": "auth123",  # or auth proto/pass
            "timeout": 5,
            "scan_mode": "normal",
        }

        host_ip = "192.168.1.20"
        host_obj = Host(ip=host_ip)
        self.auditor.scanner.get_or_create_host.return_value = host_obj

        # Mock nmap with port 161 (UDP)
        mock_nm_data = MagicMock()
        mock_nm_data.all_protocols.return_value = ["udp"]
        mock_service = {"name": "snmp", "state": "open", "product": "Net-SNMP", "version": ""}
        mock_nm_data.__getitem__.side_effect = lambda x: {161: mock_service} if x == "udp" else {}

        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [host_ip]
        mock_nm.__getitem__.return_value = mock_nm_data

        self.auditor.scanner.run_nmap_scan.return_value = (mock_nm, None)

        # Mock SNMPScanner instance
        mock_snmp_instance = MockSNMPScanner.return_value

        @dataclass
        class MockSNMPInfo:
            sys_descr: str = "Cisco IOS"
            sys_name: str = "Router1"
            sys_uptime: str = "100"
            sys_contact: str = "admin"
            sys_location: str = "lab"
            error: str = None

        mock_snmp_instance.get_system_info.return_value = MockSNMPInfo()

        # Execute
        result_host = self.auditor.scan_host_ports(host_ip)

        # Assertions
        # 1. Scanner initialized
        MockSNMPScanner.assert_called_once()
        args, _ = MockSNMPScanner.call_args
        self.assertEqual(args[0].username, "snmpuser")

        # 2. get_system_info called
        mock_snmp_instance.get_system_info.assert_called_with(host_ip)

        # 3. Host object updated (auth_scan merged)
        self.assertIn("sys_descr", result_host.auth_scan)
        self.assertEqual(result_host.auth_scan["sys_descr"], "Cisco IOS")
        self.assertIn("Cisco IOS", result_host.os_detected)

    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_scan_host_ports_lynis_trigger(self, MockSSHScanner, MockLynisScanner):
        """Test that Lynis is triggered when enabled + Linux + SSH success."""

        # Config
        self.auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "root",
            "auth_ssh_key": "/tmp/key",
            "auth_ssh_trust_keys": True,
            "lynis_enabled": True,
            "timeout": 5,
            "scan_mode": "normal",
        }

        host_ip = "192.168.1.30"
        host_obj = Host(ip=host_ip)
        self.auditor.scanner.get_or_create_host.return_value = host_obj

        # Nmap finding SSH
        mock_nm_data = MagicMock()
        mock_nm_data.all_protocols.return_value = ["tcp"]
        mock_service = {"name": "ssh", "state": "open"}
        mock_nm_data.__getitem__.side_effect = lambda x: {22: mock_service} if x == "tcp" else {}

        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [host_ip]
        mock_nm.__getitem__.return_value = mock_nm_data

        self.auditor.scanner.run_nmap_scan.return_value = (mock_nm, None)

        # SSH success returning Linux OS
        mock_ssh = MockSSHScanner.return_value
        mock_ssh.connect.return_value = True
        mock_ssh.gather_host_info.return_value = SSHHostInfo(
            os_name="Ubuntu Linux", os_version="20.04"
        )

        # Lynis success
        mock_lynis = MockLynisScanner.return_value
        from redaudit.core.auth_lynis import LynisResult

        mock_lynis.run_audit.return_value = LynisResult(hardening_index=75)

        # Execute
        res = self.auditor.scan_host_ports(host_ip)

        # Assert
        MockLynisScanner.assert_called()
        mock_lynis.run_audit.assert_called_with(use_portable=True)
        self.assertEqual(res.auth_scan["lynis_hardening_index"], 75)


if __name__ == "__main__":
    unittest.main()
