#!/usr/bin/env python3
"""
RedAudit - Tests for run_complete_scan orchestration.
"""

import os
from contextlib import contextmanager
from unittest.mock import MagicMock

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.models import Host


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
    app.config["nuclei_timeout"] = "bad"
    app.config["scan_vulnerabilities"] = True
    app.config["no_hyperscan_first"] = True
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


def test_run_complete_scan_nuclei_auto_fast_and_risk_recalc(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.ui.print_status = MagicMock()
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["scan_mode"] = "completo"
    app.config["scan_vulnerabilities"] = True
    app.config["nuclei_enabled"] = True
    app.config["nuclei_profile"] = "balanced"
    app.config["nuclei_full_coverage"] = False
    app.config["net_discovery_enabled"] = True
    app.config["prevent_sleep"] = True
    app.config["cve_lookup_enabled"] = False
    app.config["auth_enabled"] = False
    app.results["vulnerabilities"] = [{"host": "10.0.0.1", "vulnerabilities": [{"id": "CVE-1"}]}]

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "_progress_columns", lambda *_a, **_k: [])
    monkeypatch.setattr(app, "_progress_console", lambda: MagicMock())
    monkeypatch.setattr(app, "_format_eta", lambda *_a: "00:00")
    monkeypatch.setattr(app, "scan_network_discovery", lambda *_a, **_k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *_a, **_k: [])
    monkeypatch.setattr(app, "run_agentless_verification", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "scan_vulnerabilities_concurrent", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "run_deep_scans_concurrent", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "save_results", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "show_results", lambda *_a, **_k: None)
    app.scanner.detect_local_networks.side_effect = RuntimeError("fail")

    created_hosts = {}

    def _make_host(ip):
        host = Host(ip=ip)
        created_hosts[ip] = host
        return host

    app.scanner.get_or_create_host.side_effect = _make_host

    def _fake_hyperscan(hosts):
        app.results["net_discovery"] = []
        return {"10.0.0.1": [80]}

    monkeypatch.setattr(app, "_run_hyperscan_discovery", _fake_hyperscan)

    host_obj = Host(ip="10.0.0.1")
    host_dict = {"ip": "10.0.0.2", "agentless_fingerprint": {"server": "nginx"}}
    monkeypatch.setattr(app, "scan_hosts_concurrent", lambda *_a, **_k: [host_obj, host_dict])

    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_a, **_k: {
            "hyperscan_udp_ports": {"10.0.0.1": [1900]},
            "upnp_devices": [{"ip": "10.0.0.1", "device": "IoT (Printer)"}],
        },
    )
    monkeypatch.setattr(
        "redaudit.core.net_discovery.detect_default_route_interface", lambda **_k: None
    )

    monkeypatch.setattr("redaudit.core.auditor.is_nuclei_available", lambda: True)
    monkeypatch.setattr(
        "redaudit.core.auditor.get_http_targets_from_hosts",
        lambda _r: [
            "http://10.0.0.1:80",
            "https://10.0.0.1:443",
            "http://10.0.0.1:8080",
            "http://10.0.0.2:80",
            "http://10.0.0.2:8081",
            "bad://url",
        ],
    )

    from urllib.parse import urlparse as real_urlparse

    def _urlparse(url):
        if url == "bad://url":
            raise ValueError("bad url")
        return real_urlparse(url)

    monkeypatch.setattr("urllib.parse.urlparse", _urlparse)

    monkeypatch.setattr(
        "redaudit.core.auditor.run_nuclei_scan",
        lambda **_k: {
            "success": True,
            "findings": [{"template_id": "t1", "matched_at": "http://10.0.0.1"}],
            "raw_output_file": str(tmp_path / "nuclei.json"),
        },
    )
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nuclei_false_positives",
        lambda findings, _host_agentless, _logger, host_records=None: (findings, []),
    )
    monkeypatch.setattr(app, "_merge_nuclei_findings", lambda *_a, **_k: 0)

    def _raise_relpath(*_a, **_k):
        raise ValueError("relpath")

    monkeypatch.setattr(os.path, "relpath", _raise_relpath)

    monkeypatch.setattr("redaudit.core.siem.calculate_risk_score", lambda *_a, **_k: 7)
    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "redaudit.core.scanner.traffic.finalize_pcap_artifacts",
        lambda **_k: (_ for _ in ()).throw(RuntimeError("pcap")),
    )
    monkeypatch.setattr(
        "redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *_a, **_k: None
    )
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *_a, **_k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)

    class _Inhibitor:
        def __init__(self, logger=None):
            return None

        def start(self):
            return None

        def stop(self):
            raise RuntimeError("stop")

    monkeypatch.setattr("redaudit.core.power.SleepInhibitor", _Inhibitor)

    app.proxy_manager = MagicMock()
    app.proxy_manager.cleanup.side_effect = RuntimeError("cleanup")

    class _Progress:
        def __init__(self, *_a, **_k):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def add_task(self, *_a, **_k):
            return "task"

        def update(self, *_a, **_k):
            return None

    monkeypatch.setattr("rich.progress.Progress", _Progress)

    assert app.run_complete_scan() is True
    assert created_hosts["10.0.0.1"].services


def test_run_complete_scan_nuclei_failure(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["scan_mode"] = "completo"
    app.config["scan_vulnerabilities"] = True
    app.config["nuclei_enabled"] = True
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **k: [])
    monkeypatch.setattr(app, "scan_hosts_concurrent", lambda *a, **k: [{"ip": "10.0.0.1"}])
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **k: None)
    monkeypatch.setattr(app, "scan_vulnerabilities_concurrent", lambda *a, **k: None)
    monkeypatch.setattr(app, "_run_hyperscan_discovery", lambda *_a, **_k: {})
    monkeypatch.setattr(app, "save_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **k: None)

    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)
    monkeypatch.setattr("redaudit.core.auditor.is_nuclei_available", lambda: True)
    monkeypatch.setattr(
        "redaudit.core.auditor.get_http_targets_from_hosts", lambda h: ["http://10.0.0.1:80"]
    )
    monkeypatch.setattr(
        "redaudit.core.auditor.run_nuclei_scan",
        lambda **_k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    assert app.run_complete_scan() is True


def test_run_complete_scan_cve_breaks_on_interrupt(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["cve_lookup_enabled"] = True
    app.config["scan_vulnerabilities"] = False
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **k: [])
    monkeypatch.setattr(
        app,
        "scan_hosts_concurrent",
        lambda *a, **k: [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}],
    )
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **k: None)
    monkeypatch.setattr(app, "_run_hyperscan_discovery", lambda *_a, **_k: {})
    monkeypatch.setattr(app, "save_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "setup_nvd_api_key", lambda *a, **k: None)

    def _enrich(host, **_k):
        app.interrupted = True
        return host

    monkeypatch.setattr("redaudit.core.auditor.enrich_host_with_cves", _enrich)
    monkeypatch.setattr("redaudit.core.auditor.get_api_key_from_config", lambda: "key")
    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    assert app.run_complete_scan() is False
    assert app.interrupted is True


def test_run_complete_scan_cve_exception_logged(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["cve_lookup_enabled"] = True
    app.config["scan_vulnerabilities"] = False
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **k: [])
    monkeypatch.setattr(app, "scan_hosts_concurrent", lambda *a, **k: [{"ip": "10.0.0.1"}])
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **k: None)
    monkeypatch.setattr(app, "_run_hyperscan_discovery", lambda *_a, **_k: {})
    monkeypatch.setattr(app, "save_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "setup_nvd_api_key", lambda *a, **k: None)

    monkeypatch.setattr(
        "redaudit.core.auditor.enrich_host_with_cves",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr("redaudit.core.auditor.get_api_key_from_config", lambda: "key")
    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    assert app.run_complete_scan() is True
    assert app.logger.debug.called


def test_run_complete_scan_auth_and_snmp_topology(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["auth_enabled"] = True
    app.config["snmp_topology"] = True
    app.config["cve_lookup_enabled"] = True
    app.config["scan_vulnerabilities"] = False
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **k: [])
    monkeypatch.setattr(app, "scan_hosts_concurrent", lambda *a, **k: [{"ip": "10.0.0.1"}])
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **k: None)
    monkeypatch.setattr(app, "_run_hyperscan_discovery", lambda *_a, **_k: {})
    monkeypatch.setattr(app, "save_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "setup_nvd_api_key", lambda *a, **k: None)

    monkeypatch.setattr("redaudit.core.auditor.enrich_host_with_cves", lambda h, **_k: h)
    monkeypatch.setattr("redaudit.core.auditor.get_api_key_from_config", lambda: "key")
    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    called = {}
    monkeypatch.setattr(
        app, "_run_authenticated_scans", lambda *_a, **_k: called.setdefault("auth", True)
    )
    monkeypatch.setattr(
        app, "_process_snmp_topology", lambda *_a, **_k: called.setdefault("snmp", True)
    )

    assert app.run_complete_scan() is True
    assert called.get("auth") is True
    assert called.get("snmp") is True


def test_run_complete_scan_risk_recalc_exception(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["scan_vulnerabilities"] = False
    app.config["prevent_sleep"] = False
    app.results["vulnerabilities"] = [{"host": "10.0.0.1", "vulnerabilities": [{"id": "CVE-1"}]}]

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **k: [])
    monkeypatch.setattr(app, "scan_hosts_concurrent", lambda *a, **k: [Host(ip="10.0.0.1")])
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **k: None)
    monkeypatch.setattr(app, "_run_hyperscan_discovery", lambda *_a, **_k: {})
    monkeypatch.setattr(app, "save_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **k: None)

    monkeypatch.setattr(
        "redaudit.core.siem.calculate_risk_score",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("risk")),
    )
    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    assert app.run_complete_scan() is True
    assert app.logger.warning.called


def test_run_complete_scan_nuclei_full_coverage_skips_auto_fast(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["scan_mode"] = "completo"
    app.config["scan_vulnerabilities"] = True
    app.config["nuclei_enabled"] = True
    app.config["nuclei_full_coverage"] = True
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "_run_hyperscan_discovery", lambda *_a, **_k: {})
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **k: [])
    monkeypatch.setattr(app, "scan_hosts_concurrent", lambda *a, **k: [{"ip": "10.0.0.1"}])
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **k: None)
    monkeypatch.setattr(app, "scan_vulnerabilities_concurrent", lambda *a, **k: None)
    monkeypatch.setattr(app, "save_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **k: None)

    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)
    monkeypatch.setattr("redaudit.core.auditor.is_nuclei_available", lambda: True)
    monkeypatch.setattr(
        "redaudit.core.auditor.get_http_targets_from_hosts",
        lambda h: [
            "http://10.0.0.1:80",
            "https://10.0.0.1:443",
            "http://10.0.0.1:8080",
        ],
    )
    monkeypatch.setattr(
        "redaudit.core.auditor.run_nuclei_scan",
        lambda **_k: {"success": True, "findings": []},
    )
    monkeypatch.setattr(app, "_merge_nuclei_findings", lambda *_a, **_k: 0)
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    assert app.run_complete_scan() is True


def test_run_complete_scan_nuclei_full_coverage_bumps_timeout(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["scan_mode"] = "completo"
    app.config["scan_vulnerabilities"] = True
    app.config["nuclei_enabled"] = True
    app.config["nuclei_full_coverage"] = True
    app.config["nuclei_timeout"] = 10
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "_run_hyperscan_discovery", lambda *_a, **_k: {})
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **k: [])
    monkeypatch.setattr(app, "scan_hosts_concurrent", lambda *a, **k: [{"ip": "10.0.0.1"}])
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **k: None)
    monkeypatch.setattr(app, "scan_vulnerabilities_concurrent", lambda *a, **k: None)
    monkeypatch.setattr(app, "save_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **k: None)

    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)
    monkeypatch.setattr("redaudit.core.auditor.is_nuclei_available", lambda: True)
    monkeypatch.setattr(
        "redaudit.core.auditor.get_http_targets_from_hosts",
        lambda h: ["http://10.0.0.1:80", "https://10.0.0.1:443"],
    )

    captured = {}

    def _run_nuclei_scan(**kwargs):
        captured.update(kwargs)
        return {"success": True, "findings": []}

    monkeypatch.setattr("redaudit.core.auditor.run_nuclei_scan", _run_nuclei_scan)
    monkeypatch.setattr(app, "_merge_nuclei_findings", lambda *_a, **_k: 0)
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    assert app.run_complete_scan() is True
    assert captured["timeout"] == 900


def test_run_complete_scan_nuclei_filter_exception(tmp_path, monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()
    app.ui = MagicMock()
    app.ui.t.side_effect = lambda key, *args: key
    app.scanner = MagicMock()
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.config["output_dir"] = str(tmp_path)
    app.config["scan_mode"] = "completo"
    app.config["scan_vulnerabilities"] = True
    app.config["nuclei_enabled"] = True
    app.config["prevent_sleep"] = False

    monkeypatch.setattr(app, "start_heartbeat", lambda: None)
    monkeypatch.setattr(app, "stop_heartbeat", lambda: None)
    monkeypatch.setattr(app, "_progress_ui", _noop_cm)
    monkeypatch.setattr(app, "_select_net_discovery_interface", lambda: None)
    monkeypatch.setattr(app, "_filter_auditor_ips", lambda hosts: hosts)
    monkeypatch.setattr(app, "_run_hyperscan_discovery", lambda *_a, **_k: {})
    monkeypatch.setattr(app, "scan_network_discovery", lambda *a, **k: ["10.0.0.1"])
    monkeypatch.setattr(app, "_collect_discovery_hosts", lambda *a, **k: [])
    monkeypatch.setattr(app, "scan_hosts_concurrent", lambda *a, **k: [{"ip": "10.0.0.1"}])
    monkeypatch.setattr(app, "run_agentless_verification", lambda *a, **k: None)
    monkeypatch.setattr(app, "scan_vulnerabilities_concurrent", lambda *a, **k: None)
    monkeypatch.setattr(app, "save_results", lambda *a, **k: None)
    monkeypatch.setattr(app, "show_results", lambda *a, **k: None)

    monkeypatch.setattr("redaudit.core.auditor.generate_summary", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.core.auditor.maybe_chown_to_invoking_user", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *a, **k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda: None)
    monkeypatch.setattr("redaudit.core.auditor.is_nuclei_available", lambda: True)
    monkeypatch.setattr(
        "redaudit.core.auditor.get_http_targets_from_hosts",
        lambda h: ["http://10.0.0.1:80"],
    )
    monkeypatch.setattr(
        "redaudit.core.auditor.run_nuclei_scan",
        lambda **_k: {"success": True, "findings": [{"template_id": "t1"}]},
    )
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nuclei_false_positives",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("filter")),
    )
    monkeypatch.setattr(app, "_merge_nuclei_findings", lambda *_a, **_k: 0)
    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_args, **_kwargs: {},
    )

    assert app.run_complete_scan() is True
    assert app.logger.warning.called
