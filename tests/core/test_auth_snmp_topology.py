import unittest
from unittest.mock import MagicMock, patch
import sys

# Mock pysnmp before importing auth_snmp
sys.modules["pysnmp"] = MagicMock()
sys.modules["pysnmp.hlapi"] = MagicMock()

from redaudit.core.auth_snmp import SNMPScanner, SNMPHostInfo
from redaudit.core.credentials import Credential


class TestSNMPTopology(unittest.TestCase):
    def setUp(self):
        self.cred = Credential(username="testuser", password="testpass")
        # We need to ensure PYSNMP_AVAILABLE is True for tests
        with patch("redaudit.core.auth_snmp.PYSNMP_AVAILABLE", True):
            self.scanner = SNMPScanner(self.cred)

    @patch("redaudit.core.auth_snmp.nextCmd")
    @patch("redaudit.core.auth_snmp.getCmd")
    def test_get_topology_info(self, mock_get, mock_next):
        # Mock system info (getCmd)
        mock_get.return_value = iter(
            [
                (
                    None,
                    None,
                    0,
                    [
                        (None, "TestRouter"),  # sysDescr
                        (None, "Router1"),  # sysName
                        (None, "1000"),  # sysUpTime
                        (None, "Admin"),  # sysContact
                        (None, "Lab"),  # sysLocation
                    ],
                )
            ]
        )

        # Mock Topology Walks (nextCmd)
        # We have 3 walks: Interfaces, Routes, ARP

        # 1. Interfaces response
        iface_varbinds = [
            (None, "1"),
            (None, "eth0"),
            (None, "6"),
            (None, b"\x00\x11\x22"),
            (None, "1"),
        ]
        # Make varbinds have appropriate mocked methods/attributes if code uses them
        # Logic uses str(v[1]) mostly, but for mac it checks asNumbers etc.
        # We'll just assume they return clean strings for simplicity in this mock test
        # or we mock the object behavior deeper if needed.

        # 2. Routes response
        # dest, ifIndex, nextHop, type, mask
        route_varbinds = [
            (None, "10.10.10.0"),
            (None, "2"),
            (None, "192.168.1.1"),
            (None, "3"),
            (None, "255.255.255.0"),
        ]

        # 3. ARP response
        # ifIndex, mac, ip, type
        arp_varbinds = [(None, "2"), (None, b"\xaa\xbb\xcc"), (None, "10.10.10.5"), (None, "3")]

        # Setup side_effect for nextCmd to return correct iterator for each call
        # _walk_interfaces calls nextCmd first
        # _walk_routes calls nextCmd second
        # _walk_arp calls nextCmd third

        # We need to construct the iterators properly.
        # nextCmd returns generator yielding (err, err, err, varBinds)

        iter_iface = iter([(None, None, 0, iface_varbinds)])
        iter_routes = iter([(None, None, 0, route_varbinds)])
        iter_arp = iter([(None, None, 0, arp_varbinds)])

        mock_next.side_effect = [iter_iface, iter_routes, iter_arp]

        # Run
        info = self.scanner.get_topology_info("192.168.1.1")

        # Verify
        self.assertIsInstance(info, SNMPHostInfo)
        self.assertEqual(info.sys_name, "Router1")

        # Check routes
        self.assertTrue(len(info.routes) > 0)
        route = info.routes[0]
        self.assertEqual(route["dest"], "10.10.10.0")
        self.assertEqual(route["mask"], "255.255.255.0")

        # Check arp
        self.assertTrue(len(info.arp_table) > 0)
        self.assertEqual(info.arp_table[0]["ip"], "10.10.10.5")


if __name__ == "__main__":
    unittest.main()
