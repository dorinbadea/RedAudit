#!/usr/bin/env python3
"""
RedAudit - Tests for CLI helpers.
"""

import builtins
import os
import runpy
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from redaudit import cli
from redaudit.utils.constants import (
    MAX_CIDR_LENGTH,
    DEFAULT_UDP_MODE,
    UDP_TOP_PORTS,
    suggest_threads,
)


class _DummyApp:
    def __init__(self):
        self.lang = "en"
        self.config = {}
        self.rate_limit_delay = 0.0
        self.extra_tools = {}
        self._statuses = []
        self.logger = MagicMock()

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


class _DummyAuditor:
    choices = []

    def __init__(self):
        self.COLORS = {
            "CYAN": "",
            "ENDC": "",
            "WARNING": "",
            "FAIL": "",
            "OKGREEN": "",
        }
        self.logger = None

    def t(self, key, *_args):
        return key

    def clear_screen(self):
        return None

    def print_banner(self):
        return None

    def check_dependencies(self):
        return True

    def show_legal_warning(self):
        return True

    def ask_yes_no(self, *_args, **_kwargs):
        return False

    def show_main_menu(self):
        return self.choices.pop(0)

    def interactive_setup(self):
        return False

    def run_complete_scan(self):
        return True

    def print_status(self, *_args, **_kwargs):
        return None


def _patch_auditor(monkeypatch, choices):
    _DummyAuditor.choices = list(choices)
    monkeypatch.setattr("redaudit.core.auditor.InteractiveNetworkAuditor", _DummyAuditor)
    monkeypatch.setattr("redaudit.core.updater.interactive_update_check", lambda **_k: False)


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
        "proxy": None,
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
        "nuclei_profile": "balanced",
        "nuclei_max_runtime": 0,
        "nuclei_resume": None,
        "nuclei_resume_latest": False,
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


def test_parse_arguments_handles_persisted_error(monkeypatch):
    def _raise():
        raise RuntimeError("boom")

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", _raise)
    with patch.object(sys, "argv", ["redaudit"]):
        args = cli.parse_arguments()
    # When persisted defaults error, fallback is suggest_threads() (auto-detected)
    assert args.threads == suggest_threads()


def test_parse_arguments_help_lang_es(monkeypatch):
    with patch.object(sys, "argv", ["redaudit", "--lang", "es"]):
        args = cli.parse_arguments()
    assert args.lang == "es"


def test_parse_arguments_help_lang_equals(monkeypatch):
    with patch.object(sys, "argv", ["redaudit", "--lang=es"]):
        args = cli.parse_arguments()
    assert args.lang == "es"


def test_configure_from_args_sets_lang():
    app = _DummyApp()
    args = _base_args(lang="es")
    assert cli.configure_from_args(app, args) is True
    assert app.lang == "es"


def test_configure_from_args_dependency_failure():
    app = _DummyApp()
    args = _base_args()
    app.check_dependencies = lambda: False
    assert cli.configure_from_args(app, args) is False


def test_configure_from_args_legal_warning_rejects():
    app = _DummyApp()
    args = _base_args(yes=False)
    app.show_legal_warning = lambda: False
    assert cli.configure_from_args(app, args) is False


def test_configure_from_args_target_too_long():
    app = _DummyApp()
    args = _base_args(target="a" * (MAX_CIDR_LENGTH + 1))
    assert cli.configure_from_args(app, args) is False
    assert any("invalid_target_too_long" in status for status in app._statuses)
    # With v4.9 flow, we fall through to "target_required_non_interactive" if list is empty
    assert app._statuses[-1] == "target_required_non_interactive"


def test_configure_from_args_expands_output(monkeypatch):
    app = _DummyApp()
    args = _base_args(output="~/Reports")
    monkeypatch.setattr(cli, "expand_user_path", lambda _: "/tmp/reports")
    assert cli.configure_from_args(app, args) is True
    assert app.config["output_dir"] == "/tmp/reports"


def test_configure_from_args_sets_dry_run_env(monkeypatch):
    app = _DummyApp()
    args = _base_args(dry_run=True)
    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    assert cli.configure_from_args(app, args) is True
    assert os.environ["REDAUDIT_DRY_RUN"] == "1"
    os.environ.pop("REDAUDIT_DRY_RUN", None)


def test_configure_from_args_scan_routed_import_error(monkeypatch):
    app = _DummyApp()
    args = _base_args(scan_routed=True)
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "redaudit.core.net_discovery":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    assert cli.configure_from_args(app, args) is True


def test_configure_from_args_invalid_deep_scan_budget_and_threshold():
    app = _DummyApp()
    args = _base_args(deep_scan_budget=-1, identity_threshold=200)
    assert cli.configure_from_args(app, args) is True
    assert app.config["deep_scan_budget"] >= 0
    assert app.config["identity_threshold"] <= 100


def test_configure_from_args_invalid_nuclei_settings():
    app = _DummyApp()
    args = _base_args(nuclei_timeout=10, nuclei_profile="bad")
    assert cli.configure_from_args(app, args) is True
    assert app.config["nuclei_timeout"] == 300
    assert app.config["nuclei_profile"] == "balanced"


def test_configure_from_args_sets_nuclei_max_runtime():
    app = _DummyApp()
    args = _base_args(nuclei_max_runtime=45)
    assert cli.configure_from_args(app, args) is True
    assert app.config["nuclei_max_runtime"] == 45


def test_configure_from_args_invalid_dead_host_retries():
    app = _DummyApp()
    args = _base_args(dead_host_retries=-1)
    assert cli.configure_from_args(app, args) is True
    assert app.config["dead_host_retries"] >= 0


def test_configure_from_args_credentials_file_loaded(monkeypatch):
    app = _DummyApp()
    args = _base_args(credentials_file="~/creds.json")

    class _Cred:
        def __init__(self, user, password):
            self.user = user
            self.password = password

    class _Mgr:
        def __init__(self):
            self.credentials = [_Cred("u1", "p1"), _Cred("u2", "p2")]

        def load_from_file(self, _path):
            return None

    monkeypatch.setattr(cli, "expand_user_path", lambda p: p)
    monkeypatch.setattr("redaudit.core.credentials_manager.CredentialsManager", _Mgr)

    assert cli.configure_from_args(app, args) is True
    assert len(app.config["auth_credentials"]) == 2


def test_configure_from_args_credentials_file_missing(monkeypatch):
    app = _DummyApp()
    args = _base_args(credentials_file="~/missing.json")

    class _Mgr:
        def __init__(self):
            self.credentials = []

        def load_from_file(self, _path):
            raise FileNotFoundError("missing")

    monkeypatch.setattr(cli, "expand_user_path", lambda p: p)
    monkeypatch.setattr("redaudit.core.credentials_manager.CredentialsManager", _Mgr)

    assert cli.configure_from_args(app, args) is False


def test_configure_from_args_credentials_file_error(monkeypatch):
    app = _DummyApp()
    args = _base_args(credentials_file="~/broken.json")

    class _Mgr:
        def __init__(self):
            self.credentials = []

        def load_from_file(self, _path):
            raise RuntimeError("boom")

    monkeypatch.setattr(cli, "expand_user_path", lambda p: p)
    monkeypatch.setattr("redaudit.core.credentials_manager.CredentialsManager", _Mgr)

    assert cli.configure_from_args(app, args) is False


def test_main_generate_credentials_template(monkeypatch):
    monkeypatch.setattr(
        cli, "parse_arguments", lambda: _base_args(generate_credentials_template=True)
    )
    monkeypatch.setattr(
        "redaudit.core.credentials_manager.CredentialsManager.generate_template", lambda _p: None
    )
    with pytest.raises(SystemExit):
        cli.main()


def test_main_resume_uses_budget_override(monkeypatch):
    captured = {}

    class _ResumeAuditor(_DummyAuditor):
        def __init__(self):
            super().__init__()
            self.lang = "en"

        def resume_nuclei_from_path(self, resume_path, **kwargs):
            captured["path"] = resume_path
            captured["override"] = kwargs.get("override_max_runtime_minutes")
            return True

    args = _base_args(target=None, nuclei_resume="/tmp/scan", nuclei_max_runtime=15)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr("redaudit.core.auditor.InteractiveNetworkAuditor", _ResumeAuditor)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        sys,
        "argv",
        ["redaudit", "--nuclei-resume", "/tmp/scan", "--nuclei-max-runtime", "15"],
    )

    with pytest.raises(SystemExit) as excinfo:
        cli.main()

    assert excinfo.value.code == 0
    assert captured["override"] == 15


def test_main_proxy_success(monkeypatch):
    class _Proxy:
        def __init__(self, _url):
            pass

        def is_valid(self):
            return True

        def test_connection(self):
            return True, "ok"

    args = _base_args(proxy="socks5://localhost:9050", target=None)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    _patch_auditor(monkeypatch, choices=[0])
    monkeypatch.setattr("redaudit.core.proxy.ProxyManager", _Proxy)
    monkeypatch.setattr("redaudit.core.proxy.is_proxychains_available", lambda: True)
    with pytest.raises(SystemExit):
        cli.main()


def test_main_interactive_start_scan_success(monkeypatch):
    class _ScanAuditor(_DummyAuditor):
        def show_main_menu(self):
            return 1

        def interactive_setup(self):
            return True

        def run_complete_scan(self):
            return False

    args = _base_args(target=None)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr("redaudit.core.auditor.InteractiveNetworkAuditor", _ScanAuditor)
    monkeypatch.setattr("redaudit.core.updater.interactive_update_check", lambda **_k: False)
    with pytest.raises(SystemExit):
        cli.main()


def test_main_interactive_start_scan_keyboard_interrupt(monkeypatch):
    class _ScanAuditor(_DummyAuditor):
        def show_main_menu(self):
            return 1

        def interactive_setup(self):
            raise KeyboardInterrupt()

    args = _base_args(target=None)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr("redaudit.core.auditor.InteractiveNetworkAuditor", _ScanAuditor)
    monkeypatch.setattr("redaudit.core.updater.interactive_update_check", lambda **_k: False)
    with pytest.raises(SystemExit):
        cli.main()


def test_main_interactive_diff_keyboard_interrupt(monkeypatch):
    class _DiffAuditor(_DummyAuditor):
        def show_main_menu(self):
            return self.choices.pop(0)

    _DiffAuditor.choices = [3, 0]
    args = _base_args(target=None)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr("redaudit.core.auditor.InteractiveNetworkAuditor", _DiffAuditor)
    monkeypatch.setattr("redaudit.core.updater.interactive_update_check", lambda **_k: False)
    monkeypatch.setattr(
        builtins, "input", lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    with pytest.raises(SystemExit):
        cli.main()


def test_configure_from_args_sets_max_hosts_all():
    app = _DummyApp()
    args = _base_args(max_hosts=None)
    assert cli.configure_from_args(app, args) is True
    assert app.config["max_hosts_value"] == "all"


def test_configure_from_args_sets_nuclei_profile():
    app = _DummyApp()
    args = _base_args(nuclei_profile="fast")
    assert cli.configure_from_args(app, args) is True
    assert app.config["nuclei_profile"] == "fast"


def test_configure_from_args_filters_net_discovery_protocols():
    app = _DummyApp()
    args = _base_args(net_discovery="dhcp,foo,mdns")
    assert cli.configure_from_args(app, args) is True
    assert app.config["net_discovery_protocols"] == ["dhcp", "mdns"]


def test_configure_from_args_save_defaults_success(monkeypatch):
    app = _DummyApp()
    args = _base_args(save_defaults=True)
    called = {}

    def _capture(**kwargs):
        called.update(kwargs)

    monkeypatch.setattr("redaudit.utils.config.update_persistent_defaults", _capture)
    assert cli.configure_from_args(app, args) is True
    assert "defaults_saved" in app._statuses[-1]
    assert called["threads"] == app.config.get("threads")


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


def test_main_diff_mode_fails_on_empty_diff(monkeypatch):
    args = _base_args(diff=("old", "new"))
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr("redaudit.core.diff.generate_diff_report", lambda *_args: None)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1


def test_main_requires_root_for_scan(monkeypatch):
    monkeypatch.setattr(cli, "parse_arguments", lambda: _base_args(allow_non_root=False))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1


def test_main_proxy_invalid_exits(monkeypatch):
    args = _base_args(proxy="socks5://example.com:1080", target=None)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)

    class _Proxy:
        def __init__(self, *_args, **_kwargs):
            pass

        def is_valid(self):
            return False

    monkeypatch.setattr("redaudit.core.proxy.ProxyManager", _Proxy)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1


def test_main_proxy_missing_proxychains(monkeypatch):
    args = _base_args(proxy="socks5://example.com:1080", target=None)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)

    class _Proxy:
        def __init__(self, *_args, **_kwargs):
            pass

        def is_valid(self):
            return True

        def test_connection(self):
            return True, "ok"

    monkeypatch.setattr("redaudit.core.proxy.ProxyManager", _Proxy)
    monkeypatch.setattr("redaudit.core.proxy.is_proxychains_available", lambda: False)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1


def test_main_defaults_ignore_resets_cli_values(monkeypatch):
    args = _base_args(defaults="ignore", threads=9, rate_limit=3.0, udp_mode="full", udp_ports=200)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    with patch.object(sys, "argv", ["redaudit"]):

        def _configure(app, cfg):
            # --defaults=ignore resets threads to suggest_threads() (auto-detected)
            assert cfg.threads == suggest_threads()
            assert cfg.rate_limit == 0.0
            assert cfg.udp_mode == DEFAULT_UDP_MODE
            assert cfg.udp_ports == UDP_TOP_PORTS
            return False

        monkeypatch.setattr(cli, "configure_from_args", _configure)
        with pytest.raises(SystemExit):
            cli.main()


def test_main_non_root_allow_non_root(monkeypatch):
    args = _base_args(allow_non_root=True)
    monkeypatch.setattr(cli, "parse_arguments", lambda: args)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1)

    def _configure(_app, _args):
        return False

    monkeypatch.setattr(cli, "configure_from_args", _configure)
    with pytest.raises(SystemExit):
        cli.main()


def test_cli_main_interactive_exit(monkeypatch):
    _patch_auditor(monkeypatch, [0])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys, "argv", ["redaudit", "--skip-update-check"])

    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_cli_main_interactive_start_scan_cancel(monkeypatch):
    _patch_auditor(monkeypatch, [1])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys, "argv", ["redaudit", "--skip-update-check"])

    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_cli_main_interactive_check_updates_non_root(monkeypatch):
    _patch_auditor(monkeypatch, [2, 0])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.sys, "argv", ["redaudit", "--allow-non-root", "--skip-update-check"])

    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_cli_main_interactive_diff_reports(monkeypatch, tmp_path):
    _patch_auditor(monkeypatch, [3, 0])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys, "argv", ["redaudit", "--skip-update-check"])

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        builtins,
        "input",
        lambda *_a, **_k: "old.json" if "old" in _a[0] else "new.json",
    )
    monkeypatch.setattr(
        "redaudit.core.diff.generate_diff_report", lambda *_a, **_k: {"generated_at": "2025-01-01"}
    )
    monkeypatch.setattr("redaudit.core.diff.format_diff_text", lambda *_a, **_k: "diff text")
    monkeypatch.setattr("redaudit.core.diff.format_diff_markdown", lambda *_a, **_k: "diff md")

    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_cli_max_hosts_arg():
    with patch("sys.argv", ["redaudit", "--target", "1.1.1.1", "--max-hosts", "5", "--yes"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.config = {}
                mock_app.check_dependencies.return_value = True
                mock_app.run_complete_scan.return_value = True
                with pytest.raises(SystemExit) as e:
                    cli.main()
                assert e.value.code == 0
                assert mock_app.config["max_hosts_value"] == 5


def test_cli_diff_chmod_exception(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "old.json").write_text("{}", encoding="utf-8")
    (tmp_path / "new.json").write_text("{}", encoding="utf-8")

    mock_diff = {
        "generated_at": "2025-01-01",
        "old_report": {"path": "old.json", "timestamp": "2025-01-01T00:00:00", "total_hosts": 1},
        "new_report": {"path": "new.json", "timestamp": "2025-01-01T00:01:00", "total_hosts": 2},
        "changes": {"new_hosts": ["1.1.1.1"], "removed_hosts": [], "changed_hosts": []},
        "summary": {
            "new_hosts_count": 1,
            "removed_hosts_count": 0,
            "changed_hosts_count": 0,
            "total_new_ports": 0,
            "total_closed_ports": 0,
            "total_new_vulnerabilities": 0,
            "has_changes": True,
        },
    }

    with patch("sys.argv", ["redaudit", "--diff", "old.json", "new.json"]):
        with patch("redaudit.core.diff.generate_diff_report", return_value=mock_diff):
            with patch("os.chmod", side_effect=OSError("Permission denied")):
                with pytest.raises(SystemExit) as e:
                    cli.main()
                assert e.value.code == 0


def test_cli_proxy_failure():
    with patch(
        "sys.argv", ["redaudit", "--target", "1.1.1.1", "--proxy", "socks5://bad:1080", "--yes"]
    ):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.proxy.ProxyManager") as MockProxy:
                mock_pm = MockProxy.return_value
                mock_pm.is_valid.return_value = True
                mock_pm.test_connection.return_value = (False, "Timeout")
                with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                    mock_app = MockAuditor.return_value
                    mock_app.check_dependencies.return_value = True
                    mock_app.t.return_value = "Proxy test failed"
                    with pytest.raises(SystemExit) as e:
                        cli.main()
                    assert e.value.code == 1


def test_cli_update_check_interactive():
    with patch("sys.argv", ["redaudit"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.clear_screen = MagicMock()
                mock_app.print_banner = MagicMock()
                mock_app.ask_yes_no.return_value = True

                with patch(
                    "redaudit.core.updater.interactive_update_check", return_value=True
                ) as mock_update:
                    with pytest.raises(SystemExit) as e:
                        cli.main()
                    assert e.value.code == 0
                    assert mock_update.called


def test_cli_main_menu_diff_failure():
    with patch("sys.argv", ["redaudit"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.ask_yes_no.return_value = False
                mock_app.show_main_menu.side_effect = [3, 0]
                with patch("builtins.input", side_effect=["old.json", "new.json"]):
                    with patch("redaudit.core.diff.generate_diff_report", return_value=None):
                        with pytest.raises(SystemExit) as e:
                            cli.main()
                        assert e.value.code == 0
                        assert mock_app.print_status.called


def test_cli_main_menu_update_check():
    with patch("sys.argv", ["redaudit"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.ask_yes_no.return_value = False
                mock_app.show_main_menu.side_effect = [2, 0]
                with patch("redaudit.core.updater.interactive_update_check") as mock_update:
                    with pytest.raises(SystemExit) as e:
                        cli.main()
                    assert e.value.code == 0
                    assert mock_update.called


def test_cli_stealth_mode_config():
    with patch("sys.argv", ["redaudit", "--target", "1.1.1.1", "--stealth", "--yes"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.config = {}
                mock_app.check_dependencies.return_value = True
                mock_app.run_complete_scan.return_value = True
                with pytest.raises(SystemExit) as e:
                    cli.main()
                assert e.value.code == 0
                assert mock_app.config["stealth_mode"] is True
                assert mock_app.config["threads"] == 1


def test_module_entrypoint_invokes_cli_main():
    with patch("redaudit.cli.main") as mocked:
        runpy.run_module("redaudit.__main__", run_name="__main__")
        mocked.assert_called_once()


def test_configure_from_args_scan_routed(monkeypatch):
    app = _DummyApp()
    # Provide no targets initially, but use --scan-routed
    args = _base_args(target=None, scan_routed=True)

    expected_routed = {"networks": ["192.168.50.0/24"]}

    # We must patch the function where it is imported.
    # Since cli.py does "from redaudit.core.net_discovery import detect_routed_networks" inside the function,
    # we need to patch the source module.
    mock_detect = MagicMock(return_value=expected_routed)
    monkeypatch.setattr("redaudit.core.net_discovery.detect_routed_networks", mock_detect)

    assert cli.configure_from_args(app, args) is True
    assert app.config["target_networks"] == ["192.168.50.0/24"]
    assert "Found and added 1 hidden routed networks" in app._statuses[-1]
