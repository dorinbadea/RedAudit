#!/usr/bin/env python3
"""
RedAudit - Tests for deep scan and concurrent scan flows.
"""

import builtins

from redaudit.core import auditor_scan
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.agentless_verify import AgentlessProbeTarget
from redaudit.utils.constants import STATUS_NO_RESPONSE, UDP_SCAN_MODE_FULL


def _fake_nmap_run(cmd, _timeout, _host_ip, deep_obj, **_kwargs):
    record = {
        "command": " ".join(cmd),
        "returncode": 0,
        "stdout": "ok",
        "stderr": "",
        "duration_seconds": 1.0,
    }
    deep_obj.setdefault("commands", []).append(record)
    return record


def test_deep_scan_host_identity_skip(monkeypatch, tmp_path):
    app = InteractiveNetworkAuditor()
    app.config["_actual_output_dir"] = str(tmp_path)

    monkeypatch.setattr(auditor_scan, "run_nmap_command", _fake_nmap_run)
    monkeypatch.setattr(auditor_scan, "output_has_identity", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        auditor_scan, "extract_vendor_mac", lambda *_args, **_kwargs: ("aa", "Acme")
    )
    monkeypatch.setattr(auditor_scan, "extract_os_detection", lambda *_args, **_kwargs: "TestOS")
    monkeypatch.setattr(
        auditor_scan,
        "start_background_capture",
        lambda *_args, **_kwargs: {"pcap_file": "cap.pcap", "pcap_file_abs": "cap.pcap"},
    )
    monkeypatch.setattr(
        auditor_scan,
        "stop_background_capture",
        lambda *_args, **_kwargs: {"pcap_file": "cap.pcap"},
    )

    called = {"udp": 0}

    def _fake_udp(*_args, **_kwargs):
        called["udp"] += 1
        return []

    monkeypatch.setattr(auditor_scan, "run_udp_probe", _fake_udp)

    deep = app.deep_scan_host("10.0.0.1")
    assert deep["phase2_skipped"] is True
    assert deep["mac_address"] == "aa"
    assert deep["vendor"] == "Acme"
    assert deep["os_detected"] == "TestOS"
    assert deep["pcap_capture"]["pcap_file"] == "cap.pcap"
    assert called["udp"] == 0


def test_deep_scan_host_full_udp(monkeypatch, tmp_path):
    app = InteractiveNetworkAuditor()
    app.config["udp_mode"] = UDP_SCAN_MODE_FULL
    app.config["udp_top_ports"] = 80
    app.config["_actual_output_dir"] = str(tmp_path)

    call_state = {"count": 0}

    def _fake_run(cmd, _timeout, _host_ip, deep_obj, **_kwargs):
        call_state["count"] += 1
        stdout = "first" if call_state["count"] == 1 else "second"
        record = {
            "command": " ".join(cmd),
            "returncode": 0,
            "stdout": stdout,
            "stderr": "",
            "duration_seconds": 1.0,
        }
        deep_obj.setdefault("commands", []).append(record)
        return record

    def _fake_extract_vendor(text):
        if "second" in text:
            return ("bb", "Vendor")
        return (None, None)

    monkeypatch.setattr(auditor_scan, "run_nmap_command", _fake_run)
    monkeypatch.setattr(auditor_scan, "output_has_identity", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(auditor_scan, "extract_vendor_mac", _fake_extract_vendor)
    monkeypatch.setattr(auditor_scan, "extract_os_detection", lambda *_args, **_kwargs: "TestOS2")
    monkeypatch.setattr(auditor_scan, "get_neighbor_mac", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        auditor_scan,
        "start_background_capture",
        lambda *_args, **_kwargs: {"pcap_file": "cap.pcap", "pcap_file_abs": "cap.pcap"},
    )
    monkeypatch.setattr(
        auditor_scan,
        "stop_background_capture",
        lambda *_args, **_kwargs: {"pcap_file": "cap.pcap"},
    )
    monkeypatch.setattr(
        auditor_scan,
        "run_udp_probe",
        lambda *_args, **_kwargs: [
            {"port": 53, "state": "responded"},
            {"port": 67, "state": "closed"},
            {"port": 123, "state": "no_response"},
        ],
    )

    deep = app.deep_scan_host("10.0.0.2")
    assert deep["udp_priority_probe"]["results"]
    assert deep["udp_top_ports"] == 80
    assert deep["mac_address"] == "bb"
    assert deep["vendor"] == "Vendor"
    assert deep["os_detected"] == "TestOS2"
    assert call_state["count"] == 2


def test_scan_host_ports_nmap_failure(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["dry_run"] = False

    monkeypatch.setattr(app, "_run_nmap_xml_scan", lambda *_args, **_kwargs: (None, "fail"))
    monkeypatch.setattr(app, "_lookup_topology_identity", lambda *_args, **_kwargs: ("aa", "Acme"))
    monkeypatch.setattr(auditor_scan, "get_neighbor_mac", lambda *_args, **_kwargs: None)

    result = app.scan_host_ports("10.0.0.1")
    assert result["status"] == STATUS_NO_RESPONSE
    assert result["error"] == "fail"
    assert result["deep_scan"]["mac_address"] == "aa"
    assert result["deep_scan"]["vendor"] == "Acme"


def test_scan_hosts_concurrent_fallback(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["threads"] = 2

    monkeypatch.setattr(app, "scan_host_ports", lambda host: {"ip": host, "status": "up"})

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name.startswith("rich"):
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    results = app.scan_hosts_concurrent(["10.0.0.1", "10.0.0.2"])
    assert len(results) == 2
    assert app.results["hosts"] == results


def test_run_agentless_verification_updates_hosts(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["windows_verify_enabled"] = True
    host_results = [{"ip": "10.0.0.3", "ports": []}]

    target = AgentlessProbeTarget(ip="10.0.0.3", smb=True)

    monkeypatch.setattr(
        auditor_scan, "select_agentless_probe_targets", lambda *_args, **_kwargs: [target]
    )
    monkeypatch.setattr(
        auditor_scan,
        "probe_agentless_services",
        lambda *_args, **_kwargs: {"ip": "10.0.0.3", "smb_signing_required": True},
    )
    monkeypatch.setattr(
        auditor_scan,
        "summarize_agentless_fingerprint",
        lambda *_args, **_kwargs: {"smb_signing_required": True},
    )

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name.startswith("rich"):
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    app.run_agentless_verification(host_results)
    host = host_results[0]
    assert host["agentless_probe"]["ip"] == "10.0.0.3"
    assert host["agentless_fingerprint"]["smb_signing_required"] is True


def test_run_agentless_verification_merges_existing_http_fingerprint(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["windows_verify_enabled"] = True
    host_results = [
        {"ip": "10.0.0.3", "ports": [], "agentless_fingerprint": {"http_title": "Zyxel"}}
    ]

    target = AgentlessProbeTarget(ip="10.0.0.3", smb=True)

    monkeypatch.setattr(
        auditor_scan, "select_agentless_probe_targets", lambda *_args, **_kwargs: [target]
    )
    monkeypatch.setattr(
        auditor_scan,
        "probe_agentless_services",
        lambda *_args, **_kwargs: {"ip": "10.0.0.3", "smb_signing_required": True},
    )
    monkeypatch.setattr(
        auditor_scan,
        "summarize_agentless_fingerprint",
        lambda *_args, **_kwargs: {"smb_signing_required": True},
    )

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name.startswith("rich"):
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    app.run_agentless_verification(host_results)
    host = host_results[0]
    assert host["agentless_fingerprint"]["http_title"] == "Zyxel"
    assert host["agentless_fingerprint"]["smb_signing_required"] is True
