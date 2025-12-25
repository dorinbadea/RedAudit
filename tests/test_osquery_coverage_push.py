"""
Tests for osquery.py edge cases and missing coverage lines.
Target: Push osquery.py from 76% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess


class TestIsOsqueryAvailable:
    """Tests for is_osquery_available function."""

    def test_is_osquery_available_success(self):
        """Test osqueryi is available."""
        from redaudit.core.osquery import is_osquery_available

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = is_osquery_available()

        assert result is True

    def test_is_osquery_available_not_found(self):
        """Test osqueryi not found (line 63-64)."""
        from redaudit.core.osquery import is_osquery_available

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("osqueryi not found")
            result = is_osquery_available()

        assert result is False

    def test_is_osquery_available_timeout(self):
        """Test osqueryi times out (line 63-64)."""
        from redaudit.core.osquery import is_osquery_available

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="osqueryi", timeout=5)
            result = is_osquery_available()

        assert result is False


class TestRunLocalQuery:
    """Tests for run_local_query function (lines 67-99)."""

    def test_run_local_query_success(self):
        """Test successful local query execution."""
        from redaudit.core.osquery import run_local_query

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[{"port": 22, "protocol": "tcp"}]',
            )
            result = run_local_query("SELECT * FROM listening_ports;")

        assert result is not None
        assert len(result) == 1
        assert result[0]["port"] == 22

    def test_run_local_query_failure(self):
        """Test failed query execution (lines 86-88)."""
        from redaudit.core.osquery import run_local_query

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stderr="Error: table not found",
            )
            result = run_local_query("SELECT * FROM nonexistent;")

        assert result is None

    def test_run_local_query_timeout(self):
        """Test query timeout (lines 94-96)."""
        from redaudit.core.osquery import run_local_query

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="osqueryi", timeout=30)
            result = run_local_query("SELECT * FROM listening_ports;")

        assert result is None

    def test_run_local_query_exception(self):
        """Test generic exception (lines 97-99)."""
        from redaudit.core.osquery import run_local_query

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="invalid json",
            )
            result = run_local_query("SELECT * FROM listening_ports;")

        assert result is None  # JSON parse error


class TestRunRemoteQuery:
    """Tests for run_remote_query function (lines 102-151)."""

    def test_run_remote_query_success(self):
        """Test successful remote query."""
        from redaudit.core.osquery import run_remote_query

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[{"user": "root"}]',
            )
            result = run_remote_query(
                host="192.168.1.100",
                query="SELECT * FROM logged_in_users;",
            )

        assert result is not None
        assert result[0]["user"] == "root"

    def test_run_remote_query_with_ssh_key(self):
        """Test query with SSH key (line 124-125)."""
        from redaudit.core.osquery import run_remote_query

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="[]",
            )
            result = run_remote_query(
                host="192.168.1.100",
                query="SELECT * FROM services;",
                ssh_key="/path/to/key",
            )

        # Verify SSH key was passed
        call_args = mock_run.call_args[0][0]
        assert "-i" in call_args
        assert "/path/to/key" in call_args
        assert result is not None

    def test_run_remote_query_failure(self):
        """Test failed remote query (lines 138-140)."""
        from redaudit.core.osquery import run_remote_query

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stderr="SSH connection refused",
            )
            result = run_remote_query(
                host="192.168.1.100",
                query="SELECT * FROM services;",
            )

        assert result is None

    def test_run_remote_query_timeout(self):
        """Test SSH/query timeout (lines 146-148)."""
        from redaudit.core.osquery import run_remote_query

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="ssh", timeout=60)
            result = run_remote_query(
                host="192.168.1.100",
                query="SELECT * FROM services;",
            )

        assert result is None

    def test_run_remote_query_exception(self):
        """Test generic exception (lines 149-151)."""
        from redaudit.core.osquery import run_remote_query

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("SSH binary not found")
            result = run_remote_query(
                host="192.168.1.100",
                query="SELECT * FROM services;",
            )

        assert result is None


class TestVerifyHost:
    """Tests for verify_host function (lines 154-215)."""

    def test_verify_host_default_queries(self):
        """Test with default queries (line 179-180)."""
        from redaudit.core.osquery import verify_host, VERIFICATION_QUERIES

        with patch("redaudit.core.osquery.run_remote_query") as mock_query:
            mock_query.return_value = [{"data": "test"}]
            result = verify_host(host="192.168.1.100")

        # Should use all default queries
        assert len(result["queries"]) == len(VERIFICATION_QUERIES)

    def test_verify_host_unknown_query(self):
        """Test with unknown query name (lines 183-185)."""
        from redaudit.core.osquery import verify_host

        result = verify_host(
            host="192.168.1.100",
            queries=["unknown_query"],
        )

        assert "Unknown query: unknown_query" in result["errors"]

    def test_verify_host_query_success(self):
        """Test successful query execution (lines 197-202)."""
        from redaudit.core.osquery import verify_host

        with patch("redaudit.core.osquery.run_remote_query") as mock_query:
            mock_query.return_value = [{"port": 22}, {"port": 80}]
            result = verify_host(
                host="192.168.1.100",
                queries=["listening_ports"],
            )

        assert result["verified"] is True
        assert result["queries"]["listening_ports"]["success"] is True
        assert result["queries"]["listening_ports"]["rows"] == 2

    def test_verify_host_query_failure(self):
        """Test failed query (lines 203-207)."""
        from redaudit.core.osquery import verify_host

        with patch("redaudit.core.osquery.run_remote_query") as mock_query:
            mock_query.return_value = None  # Query failed
            result = verify_host(
                host="192.168.1.100",
                queries=["listening_ports"],
            )

        assert result["verified"] is False
        assert result["queries"]["listening_ports"]["success"] is False

    def test_verify_host_mixed_results(self):
        """Test verification status with mixed results (lines 209-214)."""
        from redaudit.core.osquery import verify_host

        with patch("redaudit.core.osquery.run_remote_query") as mock_query:
            # First query succeeds, second fails
            mock_query.side_effect = [[{"data": "test"}], None]
            result = verify_host(
                host="192.168.1.100",
                queries=["listening_ports", "firewall_rules"],
            )

        assert result["verified"] is True  # At least one succeeded
        assert result["success_count"] == 1
        assert result["total_count"] == 2


class TestGenerateVerificationReport:
    """Tests for generate_verification_report function (lines 218-256)."""

    def test_generate_report_single_host(self):
        """Test report generation for single host."""
        from redaudit.core.osquery import generate_verification_report

        with patch("redaudit.core.osquery.verify_host") as mock_verify:
            mock_verify.return_value = {
                "host": "192.168.1.100",
                "verified": True,
                "queries": {},
                "errors": [],
            }
            result = generate_verification_report(hosts=["192.168.1.100"])

        assert result["verified_hosts"] == 1
        assert result["failed_hosts"] == 0
        assert len(result["hosts"]) == 1

    def test_generate_report_multiple_hosts(self):
        """Test report with mixed success/failure (lines 251-254)."""
        from redaudit.core.osquery import generate_verification_report

        with patch("redaudit.core.osquery.verify_host") as mock_verify:
            mock_verify.side_effect = [
                {"host": "192.168.1.100", "verified": True, "queries": {}, "errors": []},
                {"host": "192.168.1.101", "verified": False, "queries": {}, "errors": []},
            ]
            result = generate_verification_report(hosts=["192.168.1.100", "192.168.1.101"])

        assert result["verified_hosts"] == 1
        assert result["failed_hosts"] == 1
        assert len(result["hosts"]) == 2

    def test_generate_report_with_custom_queries(self):
        """Test report with custom queries."""
        from redaudit.core.osquery import generate_verification_report

        with patch("redaudit.core.osquery.verify_host") as mock_verify:
            mock_verify.return_value = {
                "host": "192.168.1.100",
                "verified": True,
                "queries": {},
                "errors": [],
            }
            result = generate_verification_report(
                hosts=["192.168.1.100"],
                queries=["listening_ports"],
            )

        mock_verify.assert_called_with(
            host="192.168.1.100",
            queries=["listening_ports"],
            ssh_user="root",
            ssh_key=None,
        )
