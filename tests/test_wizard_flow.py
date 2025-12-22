#!/usr/bin/env python3
"""
RedAudit - Tests for wizard flows and helpers.
"""

from redaudit.core.wizard import WizardMixin
from redaudit.utils.constants import DEFAULT_THREADS, UDP_SCAN_MODE_QUICK, UDP_TOP_PORTS


class _DummyWizard(WizardMixin):
    def __init__(self):
        self.lang = "en"
        self.config = {"dry_run": False}
        self.COLORS = {
            "ENDC": "",
            "OKBLUE": "",
            "CYAN": "",
            "BOLD": "",
            "HEADER": "",
            "FAIL": "",
            "OKGREEN": "",
            "WARNING": "",
        }
        self._messages = []
        self.rate_limit_delay = 0.0

    def t(self, key, *args):
        return key.format(*args) if args else key

    def print_status(self, message, status="INFO", update_activity=True, *, force=False):
        self._messages.append((status, message, force))

    def signal_handler(self, *_args):
        self._messages.append(("signal", "called", False))


def _set_inputs(monkeypatch, values):
    it = iter(values)
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(it))


def test_show_main_menu_text(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["2"])
    assert wiz.show_main_menu() == 2


def test_ask_yes_no_defaults_and_invalid(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["maybe", "n"])
    assert wiz.ask_yes_no("question", default="yes") is False
    _set_inputs(monkeypatch, [""])
    assert wiz.ask_yes_no("question", default="yes") is True


def test_ask_number_all(monkeypatch):
    wiz = _DummyWizard()
    _set_inputs(monkeypatch, ["all"])
    assert wiz.ask_number("threads", default=10, min_val=1, max_val=100) == "all"


def test_ask_choice_with_back(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "_use_arrow_menu", lambda: False)
    _set_inputs(monkeypatch, ["0"])
    assert (
        wiz.ask_choice_with_back("pick", ["a", "b"], default=0, step_num=2, total_steps=3)
        == wiz.WIZARD_BACK
    )
    _set_inputs(monkeypatch, ["2"])
    assert wiz.ask_choice_with_back("pick", ["a", "b"], default=0, step_num=1, total_steps=3) == 1


def test_ask_manual_network_validation(monkeypatch):
    wiz = _DummyWizard()
    _set_inputs(monkeypatch, ["bad", "10.0.0.0/24"])
    assert wiz.ask_manual_network() == "10.0.0.0/24"


def test_apply_run_defaults():
    wiz = _DummyWizard()
    defaults = {
        "scan_mode": "full",
        "threads": DEFAULT_THREADS + 1,
        "rate_limit": -1,
        "scan_vulnerabilities": False,
        "cve_lookup_enabled": True,
        "output_dir": "~/Reports",
        "generate_txt": False,
        "generate_html": False,
        "udp_mode": UDP_SCAN_MODE_QUICK,
        "udp_top_ports": UDP_TOP_PORTS,
        "topology_enabled": True,
        "topology_only": True,
    }
    wiz._apply_run_defaults(defaults)
    assert wiz.config["scan_mode"] == "full"
    assert wiz.config["threads"] == DEFAULT_THREADS + 1
    assert wiz.config["scan_vulnerabilities"] is False
    assert wiz.config["cve_lookup_enabled"] is True
    assert wiz.config["save_txt_report"] is False
    assert wiz.config["save_html_report"] is False
    assert wiz.config["udp_mode"] == UDP_SCAN_MODE_QUICK
    assert wiz.config["udp_top_ports"] == UDP_TOP_PORTS
    assert wiz.config["topology_enabled"] is True
    assert wiz.config["topology_only"] is True


def test_webhook_url_skip(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: False)
    assert wiz.ask_webhook_url() == ""


def test_webhook_url_flow(monkeypatch):
    wiz = _DummyWizard()
    answers = iter([True, True])

    def _ask_yes_no(*_args, **_kwargs):
        return next(answers)

    called = {}

    def _fake_test_webhook(url):
        called["url"] = url
        return True

    monkeypatch.setattr(wiz, "ask_yes_no", _ask_yes_no)
    monkeypatch.setattr(wiz, "_test_webhook", _fake_test_webhook)
    _set_inputs(monkeypatch, ["http://bad", "https://example.com/webhook"])

    assert wiz.ask_webhook_url() == "https://example.com/webhook"
    assert called["url"] == "https://example.com/webhook"


def test_net_discovery_options_default(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: False)
    opts = wiz.ask_net_discovery_options()
    assert opts["snmp_community"] == "public"
    assert opts["dns_zone"] == ""
    assert opts["redteam_max_targets"] == 50


def test_net_discovery_options_custom(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr(wiz, "ask_yes_no", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(wiz, "ask_number", lambda *_args, **_kwargs: 77)
    _set_inputs(monkeypatch, ["private", "corp.local"])
    opts = wiz.ask_net_discovery_options()
    assert opts["snmp_community"] == "private"
    assert opts["dns_zone"] == "corp.local"
    assert opts["redteam_max_targets"] == 77


def test_use_arrow_menu_env(monkeypatch):
    wiz = _DummyWizard()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.delenv("REDAUDIT_BASIC_PROMPTS", raising=False)
    assert wiz._use_arrow_menu() is True
    monkeypatch.setenv("REDAUDIT_BASIC_PROMPTS", "1")
    assert wiz._use_arrow_menu() is False
