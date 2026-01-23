#!/usr/bin/env python3
"""
Tests for _run_authenticated_scans orchestrator method in auditor.py.

This tests the Phase 4 integration that triggers SSH/Lynis scans
when auth_enabled=True in config.
"""

from unittest.mock import MagicMock, patch, PropertyMock
import pytest

from redaudit.core.auditor import InteractiveNetworkAuditor


class MockUI:
    """Minimal UI mock for testing."""

    def __init__(self):
        self.colors = {"CYAN": "", "ENDC": "", "GREEN": "", "RED": "", "YELLOW": ""}

    def t(self, key, *args):
        return f"{key}: {args}" if args else key

    def print_status(self, *args, **kwargs):
        pass


class MockLogger:
    """Minimal logger mock."""

    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


@pytest.fixture
def auditor(tmp_path):
    """Create a minimal auditor instance for testing."""
    auditor = InteractiveNetworkAuditor.__new__(InteractiveNetworkAuditor)
    auditor.config = {}
    auditor.results = {"hosts": [], "vulnerabilities": []}
    auditor.ui = MockUI()
    auditor.logger = MockLogger()
    auditor.interrupted = False
    auditor.output_dir = str(tmp_path)
    return auditor


class TestRunAuthenticatedScans:
    """Tests for _run_authenticated_scans method."""

    def test_skips_when_no_ssh_user(self, auditor):
        """When auth_ssh_user is not configured, method returns early."""
        auditor.config = {"auth_enabled": True}  # No ssh_user

        # Should not raise, should return silently
        auditor._run_authenticated_scans([])

        # No auth_scan key added to results
        assert "auth_scan" not in auditor.results

    def test_skips_when_no_ssh_hosts(self, auditor):
        """When no hosts have port 22 open, logs message and returns."""
        auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "root",
        }

        # Host without SSH port
        host = {"ip": "192.168.1.1", "ports": [{"port": 80, "state": "open"}]}

        auditor._run_authenticated_scans([host])

        # No auth_scan added since no SSH hosts
        assert "auth_scan" not in auditor.results

    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_ssh_nonstandard_port_detected(self, MockSSHScanner, auditor):
        """SSH service on non-22 port should be detected and used."""
        auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "root",
            "auth_ssh_pass": "secret",
        }

        host = {
            "ip": "192.168.1.20",
            "ports": [{"port": 2222, "service": "ssh", "state": "open"}],
        }

        mock_ssh = MockSSHScanner.return_value
        mock_ssh.connect.return_value = True
        mock_info = MagicMock()
        mock_info.os_name = "Ubuntu"
        mock_info.os_version = "22.04"
        mock_info.kernel = "5.15.0"
        mock_info.hostname = "testserver"
        mock_info.packages = []
        mock_info.services = []
        mock_info.users = []
        mock_ssh.gather_host_info.return_value = mock_info

        auditor._run_authenticated_scans([host])

        mock_ssh.connect.assert_called_with("192.168.1.20", port=2222)

    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_ssh_connection_success(self, MockSSHScanner, MockLynisScanner, auditor):
        """When SSH connection succeeds, host info is gathered."""
        auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "root",
            "auth_ssh_pass": "secret",
        }

        # Host with SSH port
        host = {"ip": "192.168.1.10", "ports": [{"port": 22, "state": "open"}]}

        # Mock SSH scanner
        mock_ssh = MockSSHScanner.return_value
        mock_ssh.connect.return_value = True

        # Mock host info
        mock_info = MagicMock()
        mock_info.os_name = "Ubuntu"
        mock_info.os_version = "22.04"
        mock_info.kernel = "5.15.0"
        mock_info.hostname = "testserver"
        mock_info.packages = ["pkg1", "pkg2"]
        mock_info.services = ["ssh", "nginx"]
        mock_info.users = ["root", "ubuntu"]
        mock_ssh.gather_host_info.return_value = mock_info

        # Mock Lynis (optional, may fail)
        MockLynisScanner.return_value.run_audit.return_value = None

        auditor._run_authenticated_scans([host])

        # Assertions
        assert "auth_scan" in auditor.results
        assert auditor.results["auth_scan"]["ssh_success"] == 1
        assert auditor.results["auth_scan"]["completed"] == 1

        # Host should have auth_ssh data
        assert "auth_ssh" in host
        assert host["auth_ssh"]["os_name"] == "Ubuntu"

    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_ssh_connection_failure(self, MockSSHScanner, auditor):
        """When SSH connection fails, error is recorded."""
        from redaudit.core.auth_ssh import SSHConnectionError

        auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "root",
        }

        host = {"ip": "192.168.1.10", "ports": [{"port": 22, "state": "open"}]}

        # Mock SSH scanner to raise connection error
        mock_ssh = MockSSHScanner.return_value
        mock_ssh.connect.side_effect = SSHConnectionError("Connection refused")

        auditor._run_authenticated_scans([host])

        # Assertions
        assert "auth_scan" in auditor.results
        assert auditor.results["auth_scan"]["ssh_success"] == 0
        assert len(auditor.results["auth_scan"]["errors"]) == 1
        assert "192.168.1.10" in auditor.results["auth_scan"]["errors"][0]["ip"]

    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_lynis_scan_success(self, MockSSHScanner, MockLynisScanner, auditor):
        """When Lynis scan succeeds, results are stored."""
        auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "root",
        }

        host = {"ip": "192.168.1.10", "ports": [{"port": 22, "state": "open"}]}

        # Mock SSH success
        mock_ssh = MockSSHScanner.return_value
        mock_ssh.connect.return_value = True
        mock_info = MagicMock()
        mock_info.os_name = "Ubuntu"
        mock_info.os_version = "22.04"
        mock_info.kernel = "5.15.0"
        mock_info.hostname = "testserver"
        mock_info.packages = []
        mock_info.services = []
        mock_info.users = []
        mock_ssh.gather_host_info.return_value = mock_info

        # Mock Lynis success
        mock_lynis_result = MagicMock()
        mock_lynis_result.hardening_index = 72
        mock_lynis_result.warnings = ["warn1"]
        mock_lynis_result.suggestions = ["sug1", "sug2"]
        mock_lynis_result.tests_performed = 150
        MockLynisScanner.return_value.run_audit.return_value = mock_lynis_result

        auditor._run_authenticated_scans([host])

        # Assertions
        assert auditor.results["auth_scan"]["lynis_success"] == 1
        assert "auth_lynis" in host
        assert host["auth_lynis"]["hardening_index"] == 72
        assert host["auth_lynis"]["warnings_count"] == 1
        assert host["auth_lynis"]["suggestions_count"] == 2

    def test_respects_interrupted_flag(self, auditor):
        """When interrupted=True, method exits early."""
        auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "root",
        }
        auditor.interrupted = True

        host = {"ip": "192.168.1.10", "ports": [{"port": 22, "state": "open"}]}

        with patch("redaudit.core.auth_ssh.SSHScanner") as MockSSH:
            auditor._run_authenticated_scans([host])
            # SSH should not be called because we're interrupted
            MockSSH.assert_not_called()

    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_uses_ssh_key_when_provided(self, MockSSHScanner, auditor):
        """When SSH key is provided, it's used for authentication."""
        auditor.config = {
            "auth_enabled": True,
            "auth_ssh_user": "deploy",
            "auth_ssh_key": "/home/user/.ssh/id_rsa",
            "auth_ssh_key_pass": "keypass",
        }

        host = {"ip": "192.168.1.10", "ports": [{"port": 22, "state": "open"}]}

        mock_ssh = MockSSHScanner.return_value
        mock_ssh.connect.return_value = True
        mock_info = MagicMock()
        mock_info.os_name = "Debian"
        mock_info.os_version = "11"
        mock_info.kernel = "5.10"
        mock_info.hostname = "web01"
        mock_info.packages = []
        mock_info.services = []
        mock_info.users = []
        mock_ssh.gather_host_info.return_value = mock_info

        auditor._run_authenticated_scans([host])

        # Verify Credential was created with key
        call_args = MockSSHScanner.call_args
        credential = call_args[0][0]  # First positional arg
        assert credential.username == "deploy"
        assert credential.private_key == "/home/user/.ssh/id_rsa"
        assert credential.private_key_passphrase == "keypass"
