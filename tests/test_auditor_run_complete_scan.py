#!/usr/bin/env python3
"""
RedAudit - Tests for run_complete_scan orchestration.
"""

from contextlib import contextmanager

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
