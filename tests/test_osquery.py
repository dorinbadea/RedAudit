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
