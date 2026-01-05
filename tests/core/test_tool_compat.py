#!/usr/bin/env python3
"""
RedAudit - Tests for external tool compatibility checks.
"""

import shutil

from redaudit.core import tool_compat


def test_parse_major():
    assert tool_compat._parse_major("7.98") == 7
    assert tool_compat._parse_major("v3.1.0") == 3
    assert tool_compat._parse_major("unknown") is None


def test_extract_version():
    output = "Nmap version 7.98 ( https://nmap.org )"
    assert tool_compat._extract_version(output, r"Nmap version ([\d.]+)") == "7.98"

    output = "Nuclei Engine Version: v3.0.2"
    assert tool_compat._extract_version(output, r"v?(\d+\.\d+(?:\.\d+)?)") == "3.0.2"


def test_check_tool_compatibility_warns(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _tool: "/usr/bin/tool")

    def _fake_run(tool, _args, dry_run=None):
        if tool == "nmap":
            return "Nmap version 9.0"
        if tool == "nuclei":
            return "Nuclei Engine Version: v3.1.0"
        return ""

    monkeypatch.setattr(tool_compat, "_run_version_cmd", _fake_run)

    issues = tool_compat.check_tool_compatibility(("nmap", "nuclei"))
    by_tool = {issue.tool: issue for issue in issues}

    assert by_tool["nmap"].reason == "unsupported_major"
    assert by_tool["nmap"].expected == "7.x/8.x"
    assert "nuclei" not in by_tool


def test_check_tool_compatibility_unknown_version(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _tool: "/usr/bin/tool")
    monkeypatch.setattr(tool_compat, "_run_version_cmd", lambda *_args, **_kwargs: "???")

    issues = tool_compat.check_tool_compatibility(("nmap",))
    assert issues[0].reason == "unknown_version"
