#!/usr/bin/env python3
"""
RedAudit - Tests for scan_host_ports flow.
"""

from unittest.mock import patch

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.scanner import STATUS_UP


class _Logger:
    def debug(self, *_args, **_kwargs):
        return None

    def warning(self, *_args, **_kwargs):
        return None

    def error(self, *_args, **_kwargs):
        return None


class _FakeHost:
    def __init__(self):
        self._hostnames = [{"name": "host1"}]
        self._state = STATUS_UP
        self._protocols = {
            "tcp": {
                80: {
                    "name": "http",
                    "product": "nginx",
                    "version": "1.0",
                    "extrainfo": "",
                    "cpe": ["cpe:/a:nginx:nginx"],
                },
                2222: {
                    "name": "",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "cpe": [],
                },
            }
        }
        self._addresses = {"mac": "AA:BB:CC:DD:EE:FF"}
        self._vendor = {"AA:BB:CC:DD:EE:FF": "Acme"}

    def hostnames(self):
        return self._hostnames

    def all_protocols(self):
        return list(self._protocols.keys())

    def __getitem__(self, proto):
        return self._protocols[proto]

    def state(self):
        return self._state

    def get(self, key, default=None):
        if key == "addresses":
            return self._addresses
        if key == "vendor":
            return self._vendor
        return default


class _QuietHost:
    def __init__(self):
        self._hostnames = []
        self._state = STATUS_UP
        self._addresses = {"mac": "AA:BB:CC:DD:EE:FF"}
        self._vendor = {"AA:BB:CC:DD:EE:FF": "Zyxel"}

    def hostnames(self):
        return self._hostnames

    def all_protocols(self):
        return []

    def __getitem__(self, proto):
        raise KeyError(proto)

    def state(self):
        return self._state

    def get(self, key, default=None):
        if key == "addresses":
            return self._addresses
        if key == "vendor":
            return self._vendor
        return default


class _FakeNmap:
    def __init__(self, host):
        self._host = host

    def all_hosts(self):
        return ["10.0.0.1"]

    def __getitem__(self, key):
        if key != "10.0.0.1":
            raise KeyError(key)
        return self._host


def test_scan_host_ports_success_flow():
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.config["scan_mode"] = "normal"
    app.config["deep_id_scan"] = False
    app.results["net_discovery"] = {
        "upnp_devices": [{"ip": "10.0.0.1", "device_type": "router"}],
        "mdns_services": [{"addresses": ["10.0.0.1"], "type": "_printer._tcp"}],
    }

    fake_host = _FakeHost()
    fake_nm = _FakeNmap(fake_host)

    with patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV"):
        with patch(
            "redaudit.core.auditor_scan.banner_grab_fallback", return_value={2222: {"banner": "x"}}
        ):
            with patch(
                "redaudit.core.auditor_scan.enrich_host_with_dns", lambda *_args, **_kwargs: None
            ):
                with patch(
                    "redaudit.core.auditor_scan.enrich_host_with_whois",
                    lambda *_args, **_kwargs: None,
                ):
                    with patch(
                        "redaudit.core.auditor_scan.finalize_host_status",
                        lambda host: host.get("status", STATUS_UP),
                    ):
                        with patch.object(app, "_run_nmap_xml_scan", return_value=(fake_nm, "")):
                            result = app.scan_host_ports("10.0.0.1")

    assert result["ip"] == "10.0.0.1"
    assert result["web_ports_count"] == 1
    assert result["total_ports_found"] == 2
    assert result["status"] == STATUS_UP
    assert result["deep_scan"]["vendor"] == "Acme"


def test_scan_host_ports_http_probe_on_quiet_host():
    app = InteractiveNetworkAuditor()
    app.logger = _Logger()
    app.config["scan_mode"] = "normal"
    app.config["deep_id_scan"] = True

    fake_host = _QuietHost()
    fake_nm = _FakeNmap(fake_host)

    with patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV"):
        with patch(
            "redaudit.core.auditor_scan.http_identity_probe",
            return_value={"http_title": "Zyxel GS1200-5"},
        ):
            with patch(
                "redaudit.core.auditor_scan.enrich_host_with_dns", lambda *_args, **_kwargs: None
            ):
                with patch(
                    "redaudit.core.auditor_scan.enrich_host_with_whois",
                    lambda *_args, **_kwargs: None,
                ):
                    with patch(
                        "redaudit.core.auditor_scan.finalize_host_status",
                        lambda host: host.get("status", STATUS_UP),
                    ):
                        with patch.object(app, "_run_nmap_xml_scan", return_value=(fake_nm, "")):
                            result = app.scan_host_ports("10.0.0.1")

    assert result["agentless_fingerprint"]["http_title"] == "Zyxel GS1200-5"
    assert "http_probe" in result["smart_scan"]["signals"]
