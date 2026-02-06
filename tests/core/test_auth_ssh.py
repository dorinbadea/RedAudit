"""
Unit tests for redaudit.core.auth_ssh module.

These tests use mocking to avoid requiring actual SSH connections.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock

from redaudit.core.credentials import Credential
from redaudit.core.auth_ssh import (
    SSHScanner,
    SSHHostInfo,
    SSHConnectionError,
    SSHCommandError,
)


class TestSSHHostInfo(unittest.TestCase):
    """Tests for the SSHHostInfo dataclass."""

    def test_default_values(self):
        """Test that SSHHostInfo has appropriate defaults."""
        info = SSHHostInfo()
        self.assertEqual(info.os_name, "")
        self.assertEqual(info.packages, [])
        self.assertEqual(info.services, [])
        self.assertEqual(info.users, [])


class TestSSHScanner(unittest.TestCase):
    """Tests for the SSHScanner class."""

    def setUp(self):
        """Set up test fixtures."""
        self.credential = Credential(
            username="testuser",
            password="testpass",
        )
        self.key_credential = Credential(
            username="keyuser",
            private_key="/path/to/key",
        )

    @patch("redaudit.core.auth_ssh.SSHScanner.__init__")
    def _create_mock_scanner(self, mock_init, credential=None):
        """Helper to create a mock scanner without paramiko import."""
        mock_init.return_value = None
        scanner = SSHScanner.__new__(SSHScanner)
        scanner.credential = credential or self.credential
        scanner.timeout = 30
        scanner.trust_unknown_keys = False
        scanner._connected = False
        scanner._client = None
        scanner._paramiko = MagicMock()
        return scanner

    def test_init_without_paramiko_raises_import_error(self):
        """Test that missing paramiko raises ImportError."""
        with patch.dict("sys.modules", {"paramiko": None}):
            with patch("builtins.__import__", side_effect=ImportError("No module")):
                with self.assertRaises(ImportError) as ctx:
                    SSHScanner(self.credential)
                self.assertIn("paramiko", str(ctx.exception))

    def test_init_with_paramiko_sets_module(self):
        fake_paramiko = MagicMock()
        with patch.dict(sys.modules, {"paramiko": fake_paramiko}):
            scanner = SSHScanner(self.credential)
        assert scanner._paramiko is fake_paramiko

    def test_connect_with_password(self):
        """Test SSH connection with password authentication."""
        scanner = self._create_mock_scanner(credential=self.credential)
        scanner._client = MagicMock()

        result = scanner.connect("192.168.1.1", 22)

        # Verify connection was made
        self.assertTrue(result)

    def test_connect_with_key(self):
        """Test SSH connection with key authentication."""
        scanner = self._create_mock_scanner(credential=self.key_credential)
        scanner._client = MagicMock()

        # Mock key loading
        mock_key = MagicMock()
        scanner._paramiko.RSAKey.from_private_key_file.return_value = mock_key

        # Need to set up proper connect behavior
        scanner._connected = False

        # Mock the _load_private_key method
        scanner._load_private_key = MagicMock(return_value=mock_key)

        result = scanner.connect("192.168.1.1", 22)

        self.assertTrue(result)

    def test_connect_trust_unknown_keys_sets_policy(self):
        scanner = self._create_mock_scanner(credential=self.credential)
        scanner.trust_unknown_keys = True
        scanner._paramiko.MissingHostKeyPolicy = object

        result = scanner.connect("192.168.1.1", 22)

        self.assertTrue(result)
        scanner._client.set_missing_host_key_policy.assert_called()

    def test_connect_no_auth_raises_error(self):
        """Test that connection without auth method raises error."""
        empty_cred = Credential(username="user")
        scanner = self._create_mock_scanner(credential=empty_cred)
        scanner._paramiko.AuthenticationException = type("AuthExc", (Exception,), {})
        scanner._paramiko.SSHException = type("SSHExc", (Exception,), {})
        scanner._client = MagicMock()

        with self.assertRaises(SSHConnectionError) as ctx:
            scanner.connect("192.168.1.1", 22)
        self.assertIn("No authentication method", str(ctx.exception))

    def test_connect_authentication_exception(self):
        scanner = self._create_mock_scanner(credential=self.credential)
        scanner._paramiko.AuthenticationException = type("AuthExc", (Exception,), {})
        scanner._paramiko.SSHException = type("SSHExc", (Exception,), {})
        scanner._paramiko.SSHClient.return_value.connect.side_effect = (
            scanner._paramiko.AuthenticationException("bad auth")
        )

        with self.assertRaises(SSHConnectionError) as ctx:
            scanner.connect("192.168.1.1", 22)
        self.assertIn("Authentication failed", str(ctx.exception))

    def test_connect_ssh_exception(self):
        scanner = self._create_mock_scanner(credential=self.credential)
        scanner._paramiko.AuthenticationException = type("AuthExc", (Exception,), {})
        scanner._paramiko.SSHException = type("SSHExc", (Exception,), {})
        scanner._paramiko.SSHClient.return_value.connect.side_effect = (
            scanner._paramiko.SSHException("ssh error")
        )

        with self.assertRaises(SSHConnectionError) as ctx:
            scanner.connect("192.168.1.1", 22)
        self.assertIn("SSH error", str(ctx.exception))

    def test_connect_generic_exception(self):
        scanner = self._create_mock_scanner(credential=self.credential)
        scanner._paramiko.AuthenticationException = type("AuthExc", (Exception,), {})
        scanner._paramiko.SSHException = type("SSHExc", (Exception,), {})
        scanner._paramiko.SSHClient.return_value.connect.side_effect = RuntimeError("boom")

        with self.assertRaises(SSHConnectionError) as ctx:
            scanner.connect("192.168.1.1", 22)
        self.assertIn("Connection failed", str(ctx.exception))

    def test_close_handles_exception(self):
        scanner = self._create_mock_scanner()
        scanner._connected = True
        scanner._client = MagicMock()
        scanner._client.close.side_effect = RuntimeError("boom")
        scanner.close()
        self.assertFalse(scanner._connected)
        self.assertIsNone(scanner._client)

    def test_run_command_not_connected_raises_error(self):
        """Test that running command when not connected raises error."""
        scanner = self._create_mock_scanner()
        scanner._connected = False

        with self.assertRaises(SSHCommandError) as ctx:
            scanner.run_command("ls")
        self.assertIn("Not connected", str(ctx.exception))

    def test_run_command_returns_output(self):
        """Test successful command execution."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        # Mock exec_command
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"command output\n"
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        scanner._client = MagicMock()
        scanner._client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        stdout, stderr, code = scanner.run_command("echo test")

        self.assertEqual(stdout, "command output\n")
        self.assertEqual(stderr, "")
        self.assertEqual(code, 0)

    def test_run_command_exception(self):
        scanner = self._create_mock_scanner()
        scanner._connected = True
        scanner._client = MagicMock()
        scanner._client.exec_command.side_effect = RuntimeError("fail")

        with self.assertRaises(SSHCommandError):
            scanner.run_command("ls")

    def test_get_os_info_parses_os_release(self):
        """Test OS info parsing from /etc/os-release."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        os_release_content = 'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu'

        def mock_run_command(cmd, timeout=None):
            if "/etc/os-release" in cmd:
                return os_release_content, "", 0
            elif "uname -r" in cmd:
                return "5.15.0-generic\n", "", 0
            elif "uname -m" in cmd:
                return "x86_64\n", "", 0
            elif "hostname" in cmd:
                return "testhost\n", "", 0
            return "", "", 1

        scanner.run_command = mock_run_command

        info = scanner.get_os_info()

        self.assertEqual(info["name"], "Ubuntu")
        self.assertEqual(info["version_id"], "22.04")
        self.assertEqual(info["kernel"], "5.15.0-generic")
        self.assertEqual(info["architecture"], "x86_64")
        self.assertEqual(info["hostname"], "testhost")

    def test_get_installed_packages_dpkg(self):
        """Test package parsing for dpkg-based systems."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        dpkg_output = "bash|5.1-6ubuntu1\ncoreutils|8.32-4.1ubuntu1\n"

        def mock_run_command(cmd, timeout=None):
            if "dpkg-query" in cmd:
                return dpkg_output, "", 0
            return "", "", 1

        scanner.run_command = mock_run_command

        packages = scanner.get_installed_packages()

        self.assertEqual(len(packages), 2)
        self.assertEqual(packages[0]["name"], "bash")
        self.assertEqual(packages[0]["version"], "5.1-6ubuntu1")
        self.assertEqual(packages[0]["manager"], "dpkg")

    def test_get_installed_packages_rpm(self):
        """Test package parsing for rpm-based systems."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        rpm_output = "bash|5.1.8-4.el9\ncoreutils|8.32-34.el9\n"

        def mock_run_command(cmd, timeout=None):
            if "dpkg-query" in cmd:
                return "", "", 1
            if "rpm -qa" in cmd:
                return rpm_output, "", 0
            return "", "", 1

        scanner.run_command = mock_run_command

        packages = scanner.get_installed_packages()

        self.assertEqual(len(packages), 2)
        self.assertEqual(packages[0]["name"], "bash")
        self.assertEqual(packages[0]["manager"], "rpm")

    def test_get_running_services_systemd(self):
        """Test service parsing for systemd."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        systemctl_output = "sshd.service loaded active running OpenSSH\nnginx.service loaded active running NGINX\n"

        def mock_run_command(cmd, timeout=None):
            if "systemctl" in cmd:
                return systemctl_output, "", 0
            return "", "", 1

        scanner.run_command = mock_run_command

        services = scanner.get_running_services()

        self.assertEqual(len(services), 2)
        self.assertEqual(services[0]["name"], "sshd")
        self.assertEqual(services[0]["manager"], "systemd")

    def test_get_users_parses_passwd(self):
        """Test user parsing from /etc/passwd."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        passwd_content = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"

        def mock_run_command(cmd, timeout=None):
            if "/etc/passwd" in cmd:
                return passwd_content, "", 0
            return "", "", 1

        scanner.run_command = mock_run_command

        users = scanner.get_users()

        self.assertEqual(len(users), 2)
        self.assertEqual(users[0]["username"], "root")
        self.assertEqual(users[0]["uid"], 0)
        self.assertEqual(users[0]["shell"], "/bin/bash")

    def test_get_firewall_rules_iptables(self):
        """Test firewall parsing for iptables."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        iptables_output = "Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n"

        def mock_run_command(cmd, timeout=None):
            if "iptables" in cmd:
                return iptables_output, "", 0
            return "", "", 1

        scanner.run_command = mock_run_command

        rules = scanner.get_firewall_rules()

        self.assertIn("iptables", rules)
        self.assertIn("Chain INPUT", rules)

    def test_close_connection(self):
        """Test closing SSH connection."""
        scanner = self._create_mock_scanner()
        mock_client = MagicMock()
        scanner._connected = True
        scanner._client = mock_client

        scanner.close()

        mock_client.close.assert_called_once()
        self.assertFalse(scanner._connected)

    def test_context_manager(self):
        """Test context manager protocol."""
        scanner = self._create_mock_scanner()
        mock_client = MagicMock()
        scanner._client = mock_client
        scanner._connected = True

        with scanner:
            pass

        mock_client.close.assert_called()

    def test_gather_host_info(self):
        """Test gathering comprehensive host info."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        # Mock all info methods
        scanner.get_os_info = MagicMock(
            return_value={
                "name": "Ubuntu",
                "version_id": "22.04",
                "kernel": "5.15.0",
                "hostname": "testhost",
                "architecture": "x86_64",
            }
        )
        scanner.get_installed_packages = MagicMock(
            return_value=[{"name": "bash", "version": "5.1", "manager": "dpkg"}]
        )
        scanner.get_running_services = MagicMock(
            return_value=[{"name": "sshd", "status": "running", "manager": "systemd"}]
        )
        scanner.get_users = MagicMock(
            return_value=[
                {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"}
            ]
        )
        scanner.get_firewall_rules = MagicMock(return_value="# iptables\nChain INPUT")

        info = scanner.gather_host_info()

        self.assertIsInstance(info, SSHHostInfo)
        self.assertEqual(info.os_name, "Ubuntu")
        self.assertEqual(info.os_version, "22.04")
        self.assertEqual(len(info.packages), 1)
        self.assertEqual(len(info.services), 1)
        self.assertEqual(len(info.users), 1)

    def test_get_installed_packages_apk(self):
        """Test package parsing for apk (Alpine)."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        apk_output = "musl-1.2.2-r7 x86_64 {musl}\n"

        def mock_run_command(cmd, timeout=None):
            if "dpkg" in cmd:
                return "", "", 1
            if "rpm" in cmd:
                return "", "", 1
            if "apk" in cmd:
                return apk_output, "", 0
            return "", "", 1

        scanner.run_command = mock_run_command

        packages = scanner.get_installed_packages()

        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["name"], "musl-1.2.2-r7")
        self.assertEqual(packages[0]["manager"], "apk")

    def test_get_installed_packages_none(self):
        """Test when no package manager is detected."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        scanner.run_command = MagicMock(return_value=("", "", 1))
        packages = scanner.get_installed_packages()
        self.assertEqual(len(packages), 0)

    def test_get_running_services_sysv(self):
        """Test service parsing for SysV init."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        service_output = " [ + ]  cron\n [ - ]  procps\n"

        def mock_run_command(cmd, timeout=None):
            if "systemctl" in cmd:
                return "", "", 1
            if "service" in cmd:
                return service_output, "", 0
            return "", "", 1

        scanner.run_command = mock_run_command
        services = scanner.get_running_services()

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["name"], "cron")
        self.assertEqual(services[0]["manager"], "sysv")

    def test_firewall_detection_variants(self):
        """Test detection of various firewalls."""
        scanner = self._create_mock_scanner()
        scanner._connected = True

        # nftables
        def mock_nft(cmd, timeout=None):
            if "iptables" in cmd:
                return "", "", 1
            if "nft" in cmd:
                return "table ip filter", "", 0
            return "", "", 1

        scanner.run_command = mock_nft
        self.assertIn("nftables", scanner.get_firewall_rules())

        # firewalld
        def mock_firewalld(cmd, timeout=None):
            if "iptables" in cmd:
                return "", "", 1
            if "nft" in cmd:
                return "", "", 1
            if "firewall-cmd" in cmd:
                return "public (active)", "", 0
            return "", "", 1

        scanner.run_command = mock_firewalld
        self.assertIn("firewalld", scanner.get_firewall_rules())

        # ufw
        def mock_ufw(cmd, timeout=None):
            if "iptables" in cmd:
                return "", "", 1
            if "nft" in cmd:
                return "", "", 1
            if "firewall-cmd" in cmd:
                return "", "", 1
            if "ufw" in cmd:
                return "Status: active", "", 0
            return "", "", 1

        scanner.run_command = mock_ufw
        self.assertIn("ufw", scanner.get_firewall_rules())

        # None
        scanner.run_command = MagicMock(return_value=("", "", 1))
        self.assertIn("No firewall detected", scanner.get_firewall_rules())

    def test_load_private_key_iteration(self):
        """Test that _load_private_key tries all key types."""
        scanner = self._create_mock_scanner(credential=self.key_credential)

        # Define a real exception class for mocking
        class MockSSHException(Exception):
            pass

        scanner._paramiko.SSHException = MockSSHException

        # Mock SSHException for the first few types
        scanner._paramiko.RSAKey.from_private_key_file.side_effect = MockSSHException
        scanner._paramiko.Ed25519Key.from_private_key_file.side_effect = MockSSHException
        scanner._paramiko.ECDSAKey.from_private_key_file.side_effect = MockSSHException

        # Succeed on the last one
        mock_key = MagicMock()
        scanner._paramiko.DSSKey.from_private_key_file.side_effect = None
        scanner._paramiko.DSSKey.from_private_key_file.return_value = mock_key
        key = scanner._load_private_key()
        self.assertEqual(key, mock_key)

    def test_load_private_key_failure(self):
        """Test failure when no key type matches."""
        scanner = self._create_mock_scanner(credential=self.key_credential)

        # All fail
        scanner._paramiko.SSHException = Exception
        scanner._paramiko.RSAKey.from_private_key_file.side_effect = Exception
        scanner._paramiko.Ed25519Key.from_private_key_file.side_effect = Exception
        scanner._paramiko.ECDSAKey.from_private_key_file.side_effect = Exception
        scanner._paramiko.DSSKey.from_private_key_file.side_effect = Exception

        with self.assertRaises(SSHConnectionError):
            scanner._load_private_key()


if __name__ == "__main__":
    unittest.main()
