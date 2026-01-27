#!/usr/bin/env python3
"""
Unit tests for SNMP v3 Scanner (auth_snmp.py)
"""

import sys
import unittest
import importlib
import builtins
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
mock_pysnmp.usmHMACMD5AuthProtocol = MagicMock()
mock_pysnmp.usmHMACSHA224AuthProtocol = MagicMock()
mock_pysnmp.usmHMACSHA256AuthProtocol = MagicMock()
mock_pysnmp.usmHMACSHA384AuthProtocol = MagicMock()
mock_pysnmp.usmHMACSHA512AuthProtocol = MagicMock()
mock_pysnmp.usmAesCfb192Protocol = MagicMock()
mock_pysnmp.usmAesCfb256Protocol = MagicMock()
mock_pysnmp.usmDESPrivProtocol = MagicMock()
mock_pysnmp.usm3DESEDEPrivProtocol = MagicMock()

from redaudit.core import auth_snmp  # noqa: E402
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

    @patch("redaudit.core.auth_snmp.UsmUserData")
    def test_protocol_mapping_uses_snmp_fields(self, mock_user_data):
        cred = Credential(username="snmpuser")
        cred.snmp_auth_pass = "authpass"
        cred.snmp_auth_proto = "SHA256"
        cred.snmp_priv_pass = "privpass"
        cred.snmp_priv_proto = "AES256"

        scanner = SNMPScanner(cred)

        self.assertEqual(scanner.auth_key, "authpass")
        self.assertEqual(scanner.auth_proto, auth_snmp.hlapi.usmHMACSHA256AuthProtocol)
        self.assertEqual(scanner.priv_proto, auth_snmp.hlapi.usmAesCfb256Protocol)
        mock_user_data.assert_called_with(
            "snmpuser",
            "authpass",
            scanner.auth_proto,
            "privpass",
            scanner.priv_proto,
        )

    def test_protocol_map_fallbacks(self):
        scanner = SNMPScanner(self.credential)
        custom_obj = object()

        self.assertIs(scanner.auth_protocol_map(custom_obj), custom_obj)
        self.assertIs(scanner.priv_protocol_map(custom_obj), custom_obj)
        self.assertEqual(scanner.auth_protocol_map("bogus"), mock_pysnmp.usmHMACSHAAuthProtocol)
        self.assertEqual(scanner.priv_protocol_map("bogus"), mock_pysnmp.usmAesCfb128Protocol)

    def test_protocol_map_defaults_and_normalize(self):
        scanner = SNMPScanner(self.credential)
        self.assertEqual(scanner._normalize_proto_name(object()), "")
        self.assertEqual(scanner.auth_protocol_map(None), auth_snmp.usmHMACSHAAuthProtocol)
        self.assertEqual(scanner.priv_protocol_map(None), auth_snmp.usmAesCfb128Protocol)

    def test_protocol_map_known_but_unsupported_warns(self):
        scanner = SNMPScanner(self.credential)
        with patch.object(auth_snmp, "logger") as mock_logger:
            with patch.object(auth_snmp.hlapi, "usmHMACSHA224AuthProtocol", None):
                self.assertEqual(
                    scanner.auth_protocol_map("sha-224"),
                    auth_snmp.usmHMACSHAAuthProtocol,
                )
                self.assertTrue(mock_logger.warning.called)

        with patch.object(auth_snmp, "logger") as mock_logger:
            with patch.object(auth_snmp.hlapi, "usmAesCfb192Protocol", None):
                self.assertEqual(
                    scanner.priv_protocol_map("aes_192"),
                    auth_snmp.usmAesCfb128Protocol,
                )
                self.assertTrue(mock_logger.warning.called)

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


def test_auth_snmp_import_error_fallback():
    import redaudit.core.auth_snmp as auth_module

    module_path = auth_module.__file__
    spec = importlib.util.spec_from_file_location("auth_snmp_no_pysnmp", module_path)
    loaded = importlib.util.module_from_spec(spec)
    orig_import = builtins.__import__

    def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("pysnmp"):
            raise ImportError("no pysnmp")
        return orig_import(name, globals, locals, fromlist, level)

    with patch("builtins.__import__", side_effect=_fake_import):
        spec.loader.exec_module(loaded)

    assert loaded.PYSNMP_AVAILABLE is False
    assert hasattr(loaded, "UsmUserData")


@patch("redaudit.core.auth_snmp.getCmd")
def test_get_system_info_error_status(mock_getCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))

    class _Status:
        def prettyPrint(self):
            return "Bad"

    var_binds = [("oid", "value")]
    mock_getCmd.return_value = iter([(None, _Status(), 1, var_binds)])
    info = scanner.get_system_info("127.0.0.1")
    assert "Bad" in info.error


@patch("redaudit.core.auth_snmp.getCmd")
def test_get_system_info_exception(mock_getCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))
    mock_getCmd.side_effect = RuntimeError("boom")
    info = scanner.get_system_info("127.0.0.1")
    assert "boom" in info.error


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_oid_collects_rows_and_breaks_on_error(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))
    row = [(None, "1"), (None, "2")]
    mock_nextCmd.return_value = iter(
        [
            (None, 0, 0, row),
            ("error", 0, 0, row),
        ]
    )
    results = scanner._walk_oid(MagicMock(), "1.2.3")
    assert results == [["1", "2"]]


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_interfaces_breaks_on_error_indication(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))
    mock_nextCmd.return_value = iter([("error", 0, 0, [])])
    assert scanner._walk_interfaces(MagicMock()) == []


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_interfaces_prettyprint_short_value(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))

    class _Val:
        def prettyPrint(self):
            return "abcd"

    row = [(None, "1"), (None, "eth0"), (None, "6"), (None, _Val()), (None, "1")]
    mock_nextCmd.return_value = iter([(None, 0, 0, row)])
    res = scanner._walk_interfaces(MagicMock())
    assert res[0]["mac"] == "abcd"


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_interfaces_prettyprint_exception(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))

    class _Val:
        def prettyPrint(self):
            raise RuntimeError("bad")

    row = [(None, "1"), (None, "eth0"), (None, "6"), (None, _Val()), (None, "1")]
    mock_nextCmd.return_value = iter([(None, 0, 0, row)])
    res = scanner._walk_interfaces(MagicMock())
    assert "bad" not in res[0]["mac"]


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_interfaces_exception_returns_empty(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))
    mock_nextCmd.side_effect = RuntimeError("boom")
    assert scanner._walk_interfaces(MagicMock()) == []


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_routes_error_and_exception(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))
    route_row = [(None, "dest"), (None, "1"), (None, "0.0.0.0"), (None, "3"), (None, "mask")]
    mock_nextCmd.return_value = iter([("error", 0, 0, route_row), (None, 0, 0, route_row)])
    res = scanner._walk_routes(MagicMock())
    assert len(res) == 1

    mock_nextCmd.side_effect = Exception("boom")
    assert scanner._walk_routes(MagicMock()) == []


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_arp_as_numbers_and_error(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))

    mac_val = MagicMock()
    mac_val.asNumbers.return_value = [0xAA, 0xBB, 0xCC, 0xDD]
    arp_row = [(None, "1"), (None, mac_val), (None, "10.0.0.1"), (None, "3")]
    mock_nextCmd.return_value = iter([("error", 0, 0, arp_row), (None, 0, 0, arp_row)])
    res = scanner._walk_arp(MagicMock())
    assert res[0]["mac"] == "aa:bb:cc:dd"


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_arp_prettyprint_exception_and_walk_failure(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))

    class _Val:
        def prettyPrint(self):
            raise RuntimeError("bad")

    val = _Val()
    arp_row = [(None, "1"), (None, val), (None, "10.0.0.1"), (None, "3")]
    mock_nextCmd.return_value = iter([(None, 0, 0, arp_row)])
    res = scanner._walk_arp(MagicMock())
    assert res[0]["mac"] == str(val)

    mock_nextCmd.side_effect = RuntimeError("boom")
    assert scanner._walk_arp(MagicMock()) == []


@patch("redaudit.core.auth_snmp.nextCmd")
def test_walk_arp_prettyprint_short_value(mock_nextCmd):
    scanner = SNMPScanner(Credential(username="user", password="pass"))

    class _Val:
        def prettyPrint(self):
            return "0x1234"

    arp_row = [(None, "1"), (None, _Val()), (None, "10.0.0.1"), (None, "3")]
    mock_nextCmd.return_value = iter([(None, 0, 0, arp_row)])
    res = scanner._walk_arp(MagicMock())
    assert res[0]["mac"] == "1234"


if __name__ == "__main__":
    unittest.main()
