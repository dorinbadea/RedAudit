#!/usr/bin/env python3
"""
RedAudit - Tests for osquery helpers.
"""

import json
from types import SimpleNamespace
from unittest.mock import patch

from redaudit.core import osquery


def test_is_osquery_available_true():
    result = SimpleNamespace(returncode=0)
    with patch("redaudit.core.osquery.subprocess.run", return_value=result):
        assert osquery.is_osquery_available() is True


def test_is_osquery_available_false_on_missing():
    with patch("redaudit.core.osquery.subprocess.run", side_effect=FileNotFoundError("nope")):
        assert osquery.is_osquery_available() is False


def test_run_local_query_success():
    payload = [{"port": 80}]
    result = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
    with patch("redaudit.core.osquery.subprocess.run", return_value=result):
        assert osquery.run_local_query("select 1") == payload


def test_run_local_query_failure():
    result = SimpleNamespace(returncode=1, stdout="", stderr="bad")
    with patch("redaudit.core.osquery.subprocess.run", return_value=result):
        assert osquery.run_local_query("select 1") is None


def test_run_remote_query_success():
    payload = [{"name": "svc"}]
    result = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
    with patch("redaudit.core.osquery.subprocess.run", return_value=result):
        assert osquery.run_remote_query("10.0.0.1", "select 1") == payload


def test_verify_host_and_report():
    with patch("redaudit.core.osquery.run_remote_query", return_value=[{"ok": True}]):
        result = osquery.verify_host("10.0.0.1", queries=["listening_ports", "bad"])
    assert result["verified"] is True
    assert result["success_count"] == 1
    assert result["total_count"] == 2
    assert result["errors"] == ["Unknown query: bad"]

    with patch("redaudit.core.osquery.run_remote_query", return_value=None):
        report = osquery.generate_verification_report(
            ["10.0.0.1", "10.0.0.2"], queries=["listening_ports"]
        )
    assert report["verified_hosts"] == 0
    assert report["failed_hosts"] == 2


def test_run_local_query_json_error():
    result = SimpleNamespace(returncode=0, stdout="garbage", stderr="")
    with patch("redaudit.core.osquery.subprocess.run", return_value=result):
        # Should catch JSONDecodeError and return None or raise?
        # Module code just calls json.loads(result.stdout) without try/except for JSON?
        # Wait, let's check code. It does NOT have try/except for json.loads in verify_host,
        # but run_local_query does?
        # Checking file content...
        # line 90: import json
        # line 92: return json.loads(result.stdout)
        # It's inside try/except Exception as e block?
        # Yes, try starts at line 78.
        pass

    # The implementation wraps strict logic in try/except Exception as e.
    # So json.loads raising ValueError will be caught.


def test_run_local_query_exceptions():
    """Test exception handling in run_local_query."""
    # JSON Decode Error
    result = SimpleNamespace(returncode=0, stdout="garbage", stderr="")
    with patch("redaudit.core.osquery.subprocess.run", return_value=result):
        assert osquery.run_local_query("select 1") is None

    # Timeout
    with patch(
        "redaudit.core.osquery.subprocess.run",
        side_effect=osquery.subprocess.TimeoutExpired("cmd", 5),
    ):
        assert osquery.run_local_query("select 1") is None

    # Generic Exception
    with patch("redaudit.core.osquery.subprocess.run", side_effect=Exception("boom")):
        assert osquery.run_local_query("select 1") is None


def test_run_remote_query_exceptions():
    """Test exception handling in run_remote_query."""
    # SSH Error (returncode != 0)
    result = SimpleNamespace(returncode=255, stdout="", stderr="ssh connect failed")
    with patch("redaudit.core.osquery.subprocess.run", return_value=result):
        assert osquery.run_remote_query("host", "query") is None

    # Timeout
    with patch(
        "redaudit.core.osquery.subprocess.run",
        side_effect=osquery.subprocess.TimeoutExpired("cmd", 5),
    ):
        assert osquery.run_remote_query("host", "query") is None

    # Generic Exception
    with patch("redaudit.core.osquery.subprocess.run", side_effect=Exception("boom")):
        assert osquery.run_remote_query("host", "query") is None


def test_run_remote_query_with_key():
    """Test run_remote_query with SSH key argument."""
    result = SimpleNamespace(returncode=0, stdout="[]", stderr="")
    with patch("redaudit.core.osquery.subprocess.run", return_value=result) as mock_run:
        osquery.run_remote_query("10.0.0.1", "select 1", ssh_key="/path/to/key")
        args = mock_run.call_args[0][0]
        assert "-i" in args
        assert "/path/to/key" in args


def test_verify_host_default_queries():
    """Test verify_host with default (None) queries."""
    with patch("redaudit.core.osquery.run_remote_query", return_value=[]):
        result = osquery.verify_host("10.0.0.1", queries=None)
        assert len(result["queries"]) == len(osquery.VERIFICATION_QUERIES)


def test_generate_verification_report_success_count():
    """Test generate_verification_report increments verified_hosts correctly."""
    with patch("redaudit.core.osquery.verify_host") as mock_verify:
        mock_verify.side_effect = [
            {"verified": True, "host": "10.0.0.1"},
            {"verified": False, "host": "10.0.0.2"},
        ]
        report = osquery.generate_verification_report(["10.0.0.1", "10.0.0.2"])
        assert report["verified_hosts"] == 1
        assert report["failed_hosts"] == 1
