#!/usr/bin/env python3
"""
Unit tests for SNMP v3 Scanner (auth_snmp.py)
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock pysnmp to ensure auth_snmp imports these names even if library missing
mock_pysnmp = MagicMock()
sys.modules["pysnmp"] = mock_pysnmp
sys.modules["pysnmp.hlapi"] = mock_pysnmp
# Ensure access to getCmd/nextCmd via module attribute for patch to work
mock_pysnmp.getCmd = MagicMock()
mock_pysnmp.nextCmd = MagicMock()
mock_pysnmp.SnmpEngine = MagicMock()
mock_pysnmp.UsmUserData = MagicMock()
mock_pysnmp.UdpTransportTarget = MagicMock()
mock_pysnmp.ContextData = MagicMock()
mock_pysnmp.ObjectType = MagicMock()
mock_pysnmp.ObjectIdentity = MagicMock()
mock_pysnmp.usmHMACSHAAuthProtocol = MagicMock()
mock_pysnmp.usmAesCfb128Protocol = MagicMock()

from redaudit.core.auth_snmp import SNMPScanner  # noqa: E402
from redaudit.core.credentials import Credential  # noqa: E402


@patch("redaudit.core.auth_snmp.PYSNMP_AVAILABLE", True)
class TestSNMPScanner(unittest.TestCase):

    def setUp(self):
        self.credential = Credential(
            username="snmpuser",
            # We assume these fields are present on credential object
            # or dynamically assigned in real flow.
            # In test, we assign them.
            password="authpass",  # Generic generic password used as fallback/primary
        )
        self.credential.snmp_auth_proto = "SHA"
        self.credential.snmp_priv_proto = "AES"
        self.credential.snmp_priv_pass = "privpass"

    def test_init_raises_if_missing_dependency(self):
        with patch("redaudit.core.auth_snmp.PYSNMP_AVAILABLE", False):
            with self.assertRaises(ImportError):
                SNMPScanner(self.credential)

    @patch("redaudit.core.auth_snmp.getCmd")
    def test_get_system_info_success(self, mock_getCmd):
        """Test successful retrieval of system info."""
        scanner = SNMPScanner(self.credential)

        # Mock getCmd return = (errorIndication, errorStatus, errorIndex, varBinds)
        # varBinds is list of (oid, value)

        # We queried 5 OIDs
        var_binds = [
            (None, "Linux System"),  # sysDescr
            (None, "host1"),  # sysName
            (None, "1000"),  # sysUpTime
            (None, "admin@corp"),  # sysContact
            (None, "DC1"),  # sysLocation
        ]

        # return iterator
        mock_getCmd.return_value = iter([(None, 0, 0, var_binds)])

        info = scanner.get_system_info("192.168.1.1")

        self.assertEqual(info.sys_descr, "Linux System")
        self.assertEqual(info.sys_name, "host1")
        self.assertEqual(info.sys_uptime, "1000")
        self.assertIsNone(info.error)

    @patch("redaudit.core.auth_snmp.getCmd")
    def test_get_system_info_error(self, mock_getCmd):
        """Test error handling."""
        scanner = SNMPScanner(self.credential)

        # Simulate timeout
        mock_getCmd.return_value = iter([("Request Timed Out", 0, 0, [])])

        info = scanner.get_system_info("192.168.1.1")
        self.assertEqual(info.error, "Request Timed Out")

    @patch("redaudit.core.auth_snmp.nextCmd")
    @patch("redaudit.core.auth_snmp.getCmd")
    def test_get_topology_info_success(self, mock_getCmd, mock_nextCmd):
        """Test successful retrieval of topology info."""
        scanner = SNMPScanner(self.credential)

        # Mock getCmd for system info (called first)
        var_binds_sys = [
            (None, "Linux System"),
            (None, "host1"),
            (None, "1000"),
            (None, "admin@corp"),
            (None, "DC1"),
        ]
        mock_getCmd.return_value = iter([(None, 0, 0, var_binds_sys)])

        # Mock nextCmd for walks. It's called 3 times: Interfaces, Routes, ARP.
        # 1. Interfaces
        # We need more control over MAC address parsing test, so let's mock carefully
        iface_val_3 = MagicMock()
        del iface_val_3.asNumbers  # Force it to use prettyPrint path
        iface_val_3.prettyPrint.return_value = "0x001122334455"
        iface_row_complex = [
            (None, "1"),
            (None, "eth0"),
            (None, "6"),
            (None, iface_val_3),
            (None, "1"),
        ]
        iter_iface = iter([(None, 0, 0, iface_row_complex)])  # 2. Routes
        # dest, if_index, next_hop, type, mask
        route_row = [
            (None, "192.168.1.0"),
            (None, "1"),
            (None, "0.0.0.0"),
            (None, "3"),
            (None, "255.255.255.0"),
        ]
        iter_routes = iter([(None, 0, 0, route_row)])
        # 3. ARP
        # if_index, mac, ip, type
        arp_val_1 = MagicMock()
        del arp_val_1.asNumbers
        arp_val_1.prettyPrint.return_value = "0xaa00000000ff"
        arp_row = [(None, "1"), (None, arp_val_1), (None, "192.168.1.50"), (None, "3")]
        iter_arp = iter([(None, 0, 0, arp_row)])
        mock_nextCmd.side_effect = [iter_iface, iter_routes, iter_arp]

        info = scanner.get_topology_info("192.168.1.1")

        self.assertEqual(info.sys_name, "host1")
        self.assertEqual(len(info.interfaces), 1)
        self.assertEqual(info.interfaces[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(len(info.routes), 1)
        self.assertEqual(info.routes[0]["dest"], "192.168.1.0")
        self.assertEqual(len(info.arp_table), 1)
        self.assertEqual(info.arp_table[0]["mac"], "aa:00:00:00:00:ff")

    @patch("redaudit.core.auth_snmp.getCmd")
    def test_get_topology_info_sys_error(self, mock_getCmd):
        scanner = SNMPScanner(self.credential)
        mock_getCmd.return_value = iter([("Timeout", 0, 0, [])])
        info = scanner.get_topology_info("192.168.1.1")
        self.assertEqual(info.error, "Timeout")

    @patch("redaudit.core.auth_snmp.nextCmd")
    def test_walk_oid_handles_exception(self, mock_nextCmd):
        scanner = SNMPScanner(self.credential)
        mock_nextCmd.side_effect = Exception("Boom")
        results = scanner._walk_oid(MagicMock(), "1.2.3")
        self.assertEqual(results, [])

    @patch("redaudit.core.auth_snmp.nextCmd")
    def test_walk_interfaces_mac_parsing(self, mock_nextCmd):
        scanner = SNMPScanner(self.credential)

        # Test asNumbers path
        mac_val = MagicMock()
        # Mock asNumbers to return a list of integers
        mac_val.asNumbers.return_value = [0xAA, 0xBB, 0xCC]
        # Also ensure hasattr(mac_val, "asNumbers") is True (default for MagicMock)

        row = [(None, "1"), (None, "eth0"), (None, "6"), (None, mac_val), (None, "1")]
        mock_nextCmd.return_value = iter([(None, 0, 0, row)])

        res = scanner._walk_interfaces(MagicMock())
        self.assertEqual(res[0]["mac"], "aa:bb:cc")


if __name__ == "__main__":
    unittest.main()
