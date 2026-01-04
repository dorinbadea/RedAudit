#!/usr/bin/env python3
"""
RedAudit - Tests for run_complete_scan orchestration.
"""

from contextlib import contextmanager
from unittest.mock import MagicMock

from redaudit.core.auditor import InteractiveNetworkAuditor


class _Logger:
    def debug(self, *_args, **_kwargs):
        return None

    def info(self, *_args, **_kwargs):
        return None

    def warning(self, *_args, **_kwargs):
        return None

    def error(self, *_args, **_kwargs):
        return None


@contextmanager
def _noop_cm():
    yield


def test_run_complete_scan_orchestration(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["topology_enabled"] = True
    app.config["net_discovery_enabled"] = True
    app.config["scan_vulnerabilities"] = True
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *_args, **_kwargs: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *_args, **_kwargs: ["10.0.0.2"])
    monkeypatch.setattr(
        app, "scan_hosts_concurrent", lambda *_args, **_kwargs: [{"ip": "10.0.0.1"}]
    )
    monkeypatch.setattr(app, "run_agentless_verification", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(app, "scan_vulnerabilities_concurrent", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(app, "save_results", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(app, "show_results", lambda *_args, **_kwargs: None)

    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        "redaudit.utils.session_log.start_session_log", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        "redaudit.core.topology.discover_topology", lambda *_args, **_kwargs: {"ok": True}
    )
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {
            "dhcp_servers": ["10.0.0.254"],
            "candidate_vlans": ["10.0.10.0/24"],
            "hyperscan_duration": 1.2,
            "arp_hosts": [{"ip": "10.0.0.1"}],
            "upnp_devices": [{"ip": "10.0.0.1"}],
            "hyperscan_tcp_hosts": {"10.0.0.1": [80]},
            "potential_backdoors": [{"ip": "10.0.0.1", "port": 31337}],
        },
    )

    assert app.run_complete_scan() is True


def test_run_complete_scan_topology_only(tmp_path, monkeypatch):
    """Test topology-only mode exits early."""
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["topology_enabled"] = True
    app.config["topology_only"] = True
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "save_results", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(app, "show_results", lambda *_args, **_kwargs: None)

    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        "redaudit.utils.session_log.start_session_log", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        "redaudit.core.topology.discover_topology", lambda *_args, **_kwargs: {"ok": True}
    )

    assert app.run_complete_scan() is True


def test_run_complete_scan_no_hosts(tmp_path, monkeypatch):
    """Test scan returns False when no hosts found."""
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **kw: [])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **kw: [])

    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **kw: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **kw: None)

    assert app.run_complete_scan() is False


def test_run_complete_scan_with_nuclei(tmp_path, monkeypatch):
    """Test nuclei integration branch."""
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["scan_mode"] = "completo"
    app.config["nuclei_enabled"] = True
    app.config["scan_vulnerabilities"] = True
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **kw: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **kw: [])
    monkeypatch.setattr(
        app,
        "scan_hosts_concurrent",
        lambda *a, **kw: [{"ip": "10.0.0.1", "ports": [{"port": 80, "service": "http"}]}],
    )
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **kw: None)
    monkeypatch.setattr(app, "scan_vulnerabilities_concurrent", lambda *a, **kw: None)
    monkeypatch.setattr(app, "save_results", lambda *a, **kw: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **kw: None)

    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **kw: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **kw: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **kw: None)
    monkeypatch.setattr("redaudit.core.auditor.is_nuclei_available", lambda: True)
    monkeypatch.setattr(
        "redaudit.core.auditor.get_http_targets_from_hosts", lambda h: ["http://10.0.0.1:80"]
    )
    monkeypatch.setattr(
        "redaudit.core.auditor.run_nuclei_scan",
        lambda **kw: {"success": True, "findings": [{"template_id": "test", "matched_at": "x"}]},
    )

    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    assert app.run_complete_scan() is True


def test_run_complete_scan_cve_lookup(tmp_path, monkeypatch):
    """Test CVE lookup integration branch."""
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["cve_lookup_enabled"] = True
    app.config["prevent_sleep"] = False
    app.config["scan_vulnerabilities"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **kw: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **kw: [])
    monkeypatch.setattr(
        app,
        "scan_hosts_concurrent",
        lambda *a, **kw: [{"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}]}],
    )
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **kw: None)
    monkeypatch.setattr(app, "save_results", lambda *a, **kw: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **kw: None)
    monkeypatch.setattr(app, "setup_nvd_api_key", lambda *a, **kw: None)

    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **kw: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **kw: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **kw: None)
    monkeypatch.setattr("redaudit.core.nvd.enrich_host_with_cves", lambda h, **kw: h)
    monkeypatch.setattr("redaudit.core.nvd.get_api_key_from_config", lambda: "key")

    assert app.run_complete_scan() is True


def test_run_complete_scan_interrupted(tmp_path, monkeypatch):
    """Test interrupted scan handling."""
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["prevent_sleep"] = False
    app.interrupted = True  # Simulate interruption

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **kw: [])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **kw: [])

    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **kw: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **kw: None)

    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    # Interrupted with no hosts should still return False
    assert app.run_complete_scan() is False
