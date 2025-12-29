#!/usr/bin/env python3
"""
RedAudit - Tests for auditor scan helpers.
"""

from redaudit.core import auditor_scan
from redaudit.core.auditor import InteractiveNetworkAuditor


class _DummyScanner:
    def __init__(self):
        self.xml = None
        self.parsed = False

    def analyse_nmap_xml_scan(self, xml_output, **_kwargs):
        self.parsed = True
        self.xml = xml_output


class _DummyNmap:
    PortScanner = _DummyScanner


def test_collect_discovery_hosts_filters():
    app = InteractiveNetworkAuditor()
    app.results["net_discovery"] = {
        "alive_hosts": ["10.0.0.1", "bad"],
        "arp_hosts": [{"ip": "10.0.0.2"}],
        "dhcp_servers": [{"ip": "192.168.1.5"}],
    }
    hosts = app._collect_discovery_hosts(["10.0.0.0/24"])
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_select_net_discovery_interface():
    app = InteractiveNetworkAuditor()
    app.config["net_discovery_interface"] = "eth9"
    assert app._select_net_discovery_interface() == "eth9"

    app.config["net_discovery_interface"] = None
    app.config["target_networks"] = ["10.0.0.0/24"]
    app.results["network_info"] = [
        {"network": "10.0.0.0/24", "interface": "eth0"},
        {"network": "192.168.1.0/24", "interface": "wlan0"},
    ]
    assert app._select_net_discovery_interface() == "eth0"


def test_scan_mode_host_timeout_s():
    app = InteractiveNetworkAuditor()
    app.config["scan_mode"] = "fast"
    assert app._scan_mode_host_timeout_s() == 10.0
    app.config["scan_mode"] = "full"
    assert app._scan_mode_host_timeout_s() == 300.0
    app.config["scan_mode"] = "normal"
    assert app._scan_mode_host_timeout_s() == 60.0


def test_extract_nmap_xml():
    raw = 'noise<?xml version="1.0"?><nmaprun>ok</nmaprun>tail'
    assert app_extract(raw) == "<nmaprun>ok</nmaprun>"


def app_extract(raw):
    app = InteractiveNetworkAuditor()
    return app._extract_nmap_xml(raw)


def test_parse_host_timeout_s():
    assert auditor_scan.AuditorScanMixin._parse_host_timeout_s("--host-timeout 1500ms") == 1.5
    assert auditor_scan.AuditorScanMixin._parse_host_timeout_s("--host-timeout 10s") == 10.0
    assert auditor_scan.AuditorScanMixin._parse_host_timeout_s("--host-timeout 2m") == 120.0
    assert auditor_scan.AuditorScanMixin._parse_host_timeout_s("--host-timeout 1h") == 3600.0
    assert auditor_scan.AuditorScanMixin._parse_host_timeout_s("--host-timeout 5x") is None


def test_lookup_topology_identity():
    app = InteractiveNetworkAuditor()
    app.results["topology"] = {
        "interfaces": [{"arp": {"hosts": [{"ip": "10.0.0.1", "mac": "aa", "vendor": "Unknown"}]}}]
    }
    mac, vendor = app._lookup_topology_identity("10.0.0.1")
    assert mac == "aa"
    assert vendor is None

    app.results["topology"]["interfaces"][0]["arp"]["hosts"][0]["vendor"] = "Acme"
    mac, vendor = app._lookup_topology_identity("10.0.0.1")
    assert vendor == "Acme"


def test_apply_net_discovery_identity():
    app = InteractiveNetworkAuditor()
    app.results["net_discovery"] = {
        "netbios_hosts": [{"ip": "10.0.0.5", "name": "DEVICE1"}],
        "arp_hosts": [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Tuya Smart Inc."}],
        "upnp_devices": [{"ip": "10.0.0.5", "device": "Test UPnP Device"}],
    }
    host_record = {"ip": "10.0.0.5", "hostname": "", "ports": [], "status": "down"}
    app._apply_net_discovery_identity(host_record)

    assert host_record.get("hostname") == "DEVICE1"
    deep = host_record.get("deep_scan") or {}
    assert deep.get("mac_address") == "aa:bb:cc:dd:ee:ff"
    assert deep.get("vendor") == "Tuya Smart Inc."
    agentless = host_record.get("agentless_fingerprint") or {}
    assert agentless.get("http_title") == "Test UPnP Device"


def test_run_nmap_xml_scan_dry_run():
    app = InteractiveNetworkAuditor()
    app.config["dry_run"] = True
    nm, err = app._run_nmap_xml_scan("10.0.0.1", "-sV")
    assert nm is None
    assert err == "dry_run"


def test_run_nmap_xml_scan_missing_binary(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["dry_run"] = False
    monkeypatch.setattr(auditor_scan.shutil, "which", lambda _name: None)
    nm, err = app._run_nmap_xml_scan("10.0.0.1", "-sV")
    assert nm is None
    assert err == "nmap_not_available"


def test_run_nmap_xml_scan_missing_python_nmap(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["dry_run"] = False
    monkeypatch.setattr(auditor_scan.shutil, "which", lambda _name: "nmap")
    monkeypatch.setattr(auditor_scan, "nmap", None)
    nm, err = app._run_nmap_xml_scan("10.0.0.1", "-sV")
    assert nm is None
    assert err == "python_nmap_missing"


def test_run_nmap_xml_scan_parses_xml(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["dry_run"] = False

    def _fake_run(*_args, **_kwargs):
        xml = "noise<nmaprun>ok</nmaprun>tail"
        return {"stdout_full": xml, "stderr": "", "error": ""}

    monkeypatch.setattr(auditor_scan.shutil, "which", lambda _name: "nmap")
    monkeypatch.setattr(auditor_scan, "run_nmap_command", _fake_run)
    monkeypatch.setattr(auditor_scan, "nmap", _DummyNmap())

    nm, err = app._run_nmap_xml_scan("10.0.0.1", "-sV")
    assert err == ""
    assert nm.parsed is True
    assert nm.xml == "<nmaprun>ok</nmaprun>"


def test_run_nmap_xml_scan_empty_output(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.config["dry_run"] = False

    def _fake_run(*_args, **_kwargs):
        return {"stdout_full": "", "stderr": "", "error": ""}

    monkeypatch.setattr(auditor_scan.shutil, "which", lambda _name: "nmap")
    monkeypatch.setattr(auditor_scan, "run_nmap_command", _fake_run)
    monkeypatch.setattr(auditor_scan, "nmap", _DummyNmap())

    nm, err = app._run_nmap_xml_scan("10.0.0.1", "-sV")
    assert nm is None
    assert err == "empty_nmap_output"


def test_scan_network_discovery_dry_run():
    app = InteractiveNetworkAuditor()
    app.config["dry_run"] = True
    assert app.scan_network_discovery("10.0.0.0/24") == []


def test_scan_host_ports_dry_run_and_invalid():
    app = InteractiveNetworkAuditor()
    app.config["dry_run"] = True
    result = app.scan_host_ports("10.0.0.1")
    assert result["dry_run"] is True
    invalid = app.scan_host_ports("bad")
    assert invalid["error"] == "Invalid IP"
