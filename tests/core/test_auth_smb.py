import builtins
import importlib.util
import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock Impacket modules before importing SMBScanner
sys.modules["impacket"] = MagicMock()
sys.modules["impacket.smbconnection"] = MagicMock()
sys.modules["impacket.smb"] = MagicMock()
sys.modules["impacket.dcerpc"] = MagicMock()
sys.modules["impacket.dcerpc.v5"] = MagicMock()

from redaudit.core.auth_smb import SMBScanner, SMBConnectionError
from redaudit.core.credentials import Credential


@patch("redaudit.core.auth_smb.IMPACKET_AVAILABLE", True)
class TestSMBScanner(unittest.TestCase):
    def setUp(self):
        self.credential = Credential(username="Admin", password="Password123", domain="WORKGROUP")

    def test_init_raises_if_missing_dependency(self):
        # We need to simulate IMPACKET_AVAILABLE = False
        with patch("redaudit.core.auth_smb.IMPACKET_AVAILABLE", False):
            with self.assertRaises(ImportError):
                SMBScanner(self.credential)

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_connect_success(self, MockSMBConnection):
        # Setup mock instance
        mock_conn = MockSMBConnection.return_value

        scanner = SMBScanner(self.credential)
        result = scanner.connect("192.168.1.50")

        self.assertTrue(result)
        MockSMBConnection.assert_called_with(
            "192.168.1.50", "192.168.1.50", sess_port=445, timeout=15
        )
        mock_conn.login.assert_called_with("Admin", "Password123", domain="WORKGROUP")

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_connect_failure(self, MockSMBConnection):
        mock_conn = MockSMBConnection.return_value
        mock_conn.login.side_effect = Exception("Logon failure")

        scanner = SMBScanner(self.credential)
        with self.assertRaises(SMBConnectionError):
            scanner.connect("192.168.1.50")

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_gather_host_info(self, MockSMBConnection):
        mock_conn = MockSMBConnection.return_value
        mock_conn.getServerOS.return_value = "Windows Server 2019"
        mock_conn.getServerOSMajor.return_value = "10"
        mock_conn.getServerOSMinor.return_value = "0"
        mock_conn.getServerDomain.return_value = "CONTOSO"
        mock_conn.getServerName.return_value = "DC01"

        # Mock shares
        # Impacket listShares returns list of dict-like or objects you access with keys
        # The code implementation expects dictionary usage with 'shi1_netname'
        mock_share1 = {
            "shi1_netname": b"ADMIN$\x00",
            "shi1_remark": b"Remote Admin\x00",
            "shi1_type": 2147483648,
        }
        mock_share2 = {
            "shi1_netname": b"C$\x00",
            "shi1_remark": b"Default Share\x00",
            "shi1_type": 0,
        }
        mock_conn.listShares.return_value = [mock_share1, mock_share2]

        scanner = SMBScanner(self.credential)
        scanner.conn = mock_conn  # Simulate connected
        scanner.target_ip = "192.168.1.50"

        info = scanner.gather_host_info()

        self.assertEqual(info.os_name, "Windows Server 2019")
        self.assertEqual(info.os_version, "10.0")
        self.assertEqual(info.domain, "CONTOSO")
        self.assertEqual(len(info.shares), 2)
        self.assertEqual(info.shares[0]["name"], "ADMIN$")

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_gather_host_info_exception(self, MockSMBConnection):
        mock_conn = MockSMBConnection.return_value
        mock_conn.getServerOS.side_effect = Exception("OS Info Error")

        scanner = SMBScanner(self.credential)
        scanner.conn = mock_conn

        info = scanner.gather_host_info()
        self.assertIn("OS Info Error", info.error)

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_gather_host_info_shares_exception(self, MockSMBConnection):
        mock_conn = MockSMBConnection.return_value
        mock_conn.getServerOS.return_value = "Windows"
        mock_conn.listShares.side_effect = Exception("Share List Error")

        scanner = SMBScanner(self.credential)
        scanner.conn = mock_conn

        info = scanner.gather_host_info()
        # Shares should be empty, no global error if trapped
        self.assertEqual(len(info.shares), 0)
        # Check logs? Or just ensure no crash.
        # But global error shouldn't be set if only shares failed?
        # The code traps shares exception locally.
        self.assertIsNone(info.error)

    def test_close(self):
        scanner = SMBScanner(self.credential)
        mock_conn = MagicMock()
        scanner.conn = mock_conn
        scanner.close()
        mock_conn.logoff.assert_called_once()

    def test_close_exception(self):
        scanner = SMBScanner(self.credential)
        mock_conn = MagicMock()
        mock_conn.logoff.side_effect = Exception("Logoff Error")
        scanner.conn = mock_conn
        scanner.close()
        # Should succeed silently
        mock_conn.logoff.assert_called_once()

    def test_gather_host_info_not_connected(self):
        scanner = SMBScanner(self.credential)
        # No conn
        with self.assertRaises(SMBConnectionError):
            scanner.gather_host_info()

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_gather_host_info_str_shares(self, MockSMBConnection):
        mock_conn = MockSMBConnection.return_value
        mock_conn.getServerOS.return_value = "Windows"
        mock_conn.getServerOSMajor.return_value = "10"
        mock_conn.getServerOSMinor.return_value = "0"
        mock_conn.getServerDomain.return_value = "WORKGROUP"
        mock_conn.getServerName.return_value = "PC"

        # Test string values instead of bytes
        mock_share = {"shi1_netname": "MyShare", "shi1_remark": "My Remark", "shi1_type": 0}
        mock_conn.listShares.return_value = [mock_share]

        scanner = SMBScanner(self.credential)
        scanner.conn = mock_conn
        info = scanner.gather_host_info()

        self.assertEqual(len(info.shares), 1)
        self.assertEqual(info.shares[0]["name"], "MyShare")
        self.assertEqual(info.shares[0]["remark"], "My Remark")


def test_auth_smb_import_error_fallback():
    import redaudit.core.auth_smb as auth_module

    module_path = auth_module.__file__
    spec = importlib.util.spec_from_file_location("auth_smb_no_impacket", module_path)
    loaded = importlib.util.module_from_spec(spec)
    orig_import = builtins.__import__

    def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("impacket"):
            raise ImportError("no impacket")
        return orig_import(name, globals, locals, fromlist, level)

    with patch("builtins.__import__", side_effect=_fake_import):
        spec.loader.exec_module(loaded)

    assert loaded.IMPACKET_AVAILABLE is False
    assert loaded.SMBConnection is object
