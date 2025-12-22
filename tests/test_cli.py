#!/usr/bin/env python3
"""
RedAudit - Tests for CLI helpers.
"""

import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from redaudit import cli


class _DummyApp:
    def __init__(self):
        self.lang = "en"
        self.config = {}
        self.rate_limit_delay = 0.0
        self.extra_tools = {}
        self._statuses = []

    def check_dependencies(self):
        return True

    def show_legal_warning(self):
        return True

    def print_status(self, message, _level="INFO"):
        self._statuses.append(message)

    def t(self, key, *args):
        if args:
            return f"{key}:{','.join(str(a) for a in args)}"
        return key

    def setup_encryption(self, non_interactive=True, password=None):
        self.config["encrypt"] = True
        self.config["encrypt_password"] = password


def _base_args(**overrides):
    data = {
        "diff": None,
        "lang": None,
        "yes": True,
        "target": "10.0.0.0/24",
        "mode": "normal",
        "threads": 5,
        "rate_limit": 0.0,
        "output": None,
        "dry_run": False,
        "no_prevent_sleep": False,
        "max_hosts": None,
        "no_vuln_scan": False,
        "no_txt_report": False,
        "html_report": False,
        "webhook": None,
        "no_deep_scan": False,
        "prescan": False,
        "prescan_ports": "1-1024",
        "prescan_timeout": 0.5,
        "udp_mode": "quick",
        "udp_ports": 100,
        "topology": False,
        "topology_only": False,
        "ipv6": False,
        "cve_lookup": False,
        "nvd_key": None,
        "allow_non_root": True,
        "stealth": False,
        "no_color": False,
        "skip_update_check": True,
        "defaults": "ask",
        "net_discovery": None,
        "redteam": False,
        "net_discovery_interface": None,
        "redteam_max_targets": 50,
        "snmp_community": "public",
        "dns_zone": None,
        "kerberos_realm": None,
        "kerberos_userlist": None,
        "redteam_active_l2": False,
        "nuclei": False,
        "agentless_verify_max_targets": 20,
        "windows_verify": False,
        "encrypt": False,
        "encrypt_password": None,
        "save_defaults": False,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_configure_from_args_rejects_bad_target():
    app = _DummyApp()
    args = _base_args(target="bad")
    assert cli.configure_from_args(app, args) is False


def test_configure_from_args_rejects_udp_ports():
    app = _DummyApp()
    args = _base_args(udp_ports=10)
    assert cli.configure_from_args(app, args) is False


def test_configure_from_args_sets_stealth_and_encryption():
    app = _DummyApp()
    args = _base_args(stealth=True, encrypt=True, encrypt_password="pw")
    assert cli.configure_from_args(app, args) is True
    assert app.config["stealth_mode"] is True
    assert app.config["threads"] == 1
    assert app.rate_limit_delay >= 5.0
    assert app.config["nmap_timing"] == "T1"
    assert app.config["encrypt"] is True


def test_configure_from_args_requires_target_non_interactive():
    app = _DummyApp()
    args = _base_args(target=None)
    assert cli.configure_from_args(app, args) is False
    assert "target_required_non_interactive" in app._statuses[-1]


def test_configure_from_args_net_discovery_all_and_windows_verify():
    app = _DummyApp()
    args = _base_args(net_discovery="all", windows_verify=True, agentless_verify_max_targets=10)
    assert cli.configure_from_args(app, args) is True
    assert app.config["net_discovery_enabled"] is True
    assert app.config["net_discovery_protocols"] is None
    assert app.config["windows_verify_enabled"] is True
    assert app.config["windows_verify_max_targets"] == 10


def test_configure_from_args_rejects_agentless_verify_max_targets():
    app = _DummyApp()
    args = _base_args(agentless_verify_max_targets=0)
    assert cli.configure_from_args(app, args) is False


def test_configure_from_args_save_defaults_error(monkeypatch):
    app = _DummyApp()
    args = _base_args(save_defaults=True)

    def _raise(**_kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr("redaudit.utils.config.update_persistent_defaults", _raise)
    assert cli.configure_from_args(app, args) is True
    assert "defaults_save_error" in app._statuses[-1]


def test_main_diff_mode_generates_reports(tmp_path, monkeypatch):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text('{"version": "x", "hosts": []}', encoding="utf-8")
    new_path.write_text('{"version": "x", "hosts": []}', encoding="utf-8")

    diff_report = {
        "generated_at": "2025-01-01",
        "old_report": {"path": "old.json", "timestamp": "t1", "total_hosts": 0},
        "new_report": {"path": "new.json", "timestamp": "t2", "total_hosts": 0},
        "changes": {
            "new_hosts": [],
            "removed_hosts": [],
            "changed_hosts": [],
            "web_vuln_changes": [],
        },
        "summary": {
            "new_hosts_count": 0,
            "removed_hosts_count": 0,
            "changed_hosts_count": 0,
            "total_new_ports": 0,
            "total_closed_ports": 0,
            "total_new_vulnerabilities": 0,
            "web_vuln_delta": 0,
            "has_changes": False,
        },
    }

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))

    with patch.object(sys, "argv", ["redaudit", "--diff", str(old_path), str(new_path)]):
        with patch("redaudit.core.diff.generate_diff_report", return_value=diff_report):
            with patch("redaudit.core.diff.format_diff_text", return_value="text"):
                with patch("redaudit.core.diff.format_diff_markdown", return_value="md"):
                    with patch("redaudit.core.diff.format_diff_html", return_value="<html></html>"):
                        with pytest.raises(SystemExit) as exc:
                            cli.main()
    assert exc.value.code == 0


def test_main_requires_root_for_scan(monkeypatch):
    monkeypatch.setattr(cli, "parse_arguments", lambda: _base_args(allow_non_root=False))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
