"""Acceptance tests for SPEC_FOR_CODEX v1 SmartScan changes."""

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import pytest

import redaudit.core.auditor_scan as scan_mod
from redaudit.core.auditor_scan import AuditorScanMixin


class MockAuditor(AuditorScanMixin):
    def __init__(self):
        self.results = {"hosts": []}
        self.config = {
            "output_dir": "/tmp",
            "scan_mode": "normal",
            "deep_id_scan": True,
            "threads": 1,
            "stealth_mode": False,
            "udp_mode": "quick",
            "udp_top_ports": 100,
            "deep_scan_budget": 0,
            "identity_threshold": 3,
            "low_impact_enrichment": False,
            "dry_run": False,
        }
        self.extra_tools = {}
        self.logger = MagicMock()
        self.rate_limit_delay = 0.0
        self.interrupted = False
        self.lang = "en"
        self.COLORS = {
            "HEADER": "",
            "OKGREEN": "",
            "WARNING": "",
            "FAIL": "",
            "ENDC": "",
            "INFO": "",
        }
        self.current_phase = ""
        self._deep_executed_count = 0

    def t(self, key, *args):
        return f"{key}:{args}"

    def print_status(self, msg, color=None, force=False, update_activity=True):
        pass

    def _progress_ui(self):
        class Dummy:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        return Dummy()

    def _progress_console(self):
        return MagicMock()

    def _progress_columns(self, **kwargs):
        return []

    def _set_ui_detail(self, detail):
        self._ui_detail = detail

    def _get_ui_detail(self):
        return getattr(self, "_ui_detail", "")

    def _touch_activity(self):
        pass

    def _coerce_text(self, val):
        return str(val or "")

    def _format_eta(self, s):
        return str(s)

    def _safe_text_column(self, *args, **kwargs):
        return MagicMock()


def _make_nmap_mock(ip="1.1.1.1", ports=None, hostname=""):
    nm = MagicMock()
    nm.all_hosts.return_value = [ip]
    data = MagicMock()
    ports = ports or {"tcp": {}}
    data.all_protocols.return_value = list(ports.keys())

    def _get_proto(proto):
        return ports.get(proto, {})

    data.__getitem__.side_effect = _get_proto
    data.hostnames.return_value = [{"name": hostname}] if hostname else []
    data.state.return_value = "up"
    data.get = MagicMock(return_value={})
    nm.__getitem__.return_value = data
    return nm


@pytest.fixture()
def patch_common(monkeypatch):
    monkeypatch.setattr(scan_mod, "enrich_host_with_dns", lambda *args, **kwargs: None)
    monkeypatch.setattr(scan_mod, "enrich_host_with_whois", lambda *args, **kwargs: None)
    monkeypatch.setattr(scan_mod, "banner_grab_fallback", lambda *args, **kwargs: {})
    monkeypatch.setattr(scan_mod, "http_identity_probe", lambda *args, **kwargs: {})


def test_identity_score_calculation():
    auditor = MockAuditor()
    host_record = {
        "ip": "1.1.1.1",
        "hostname": "host",
        "ports": [
            {
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "product": "nginx",
                "version": "1.0",
                "cpe": ["cpe:/a:nginx:nginx:1.0"],
            }
        ],
        "deep_scan": {"mac_address": "aa:bb:cc:dd:ee:ff", "vendor": "Acme"},
    }
    score, signals = auditor._compute_identity_score(host_record)
    assert score == 4
    assert set(signals) >= {"hostname", "service_version", "cpe", "mac_vendor"}


def test_low_visibility_no_trigger_alone():
    auditor = MockAuditor()
    trigger, reasons = auditor._should_trigger_deep(
        total_ports=2,
        any_version=True,
        suspicious=False,
        device_type_hints=[],
        identity_score=3,
        identity_threshold=3,
    )
    assert trigger is False
    assert "low_visibility" not in reasons
    assert "identity_strong" in reasons


def test_no_trigger_when_score_meets_threshold(patch_common):
    auditor = MockAuditor()
    ports = {"tcp": {80: {"name": "http", "product": "nginx", "version": "1.0", "cpe": []}}}
    nm = _make_nmap_mock(ports=ports, hostname="host")

    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm, "")):
        with patch.object(auditor, "_compute_identity_score", return_value=(3, ["hostname"])):
            with patch.object(auditor, "deep_scan_host", return_value={}) as deep:
                res = auditor.scan_host_ports("1.1.1.1")
    assert deep.called is False
    assert res["smart_scan"]["trigger_deep"] is False
    assert "low_visibility" not in res["smart_scan"]["reasons"]
    assert "identity_weak" not in res["smart_scan"]["reasons"]


def test_low_visibility_triggers_with_weak_identity():
    auditor = MockAuditor()
    trigger, reasons = auditor._should_trigger_deep(
        total_ports=2,
        any_version=False,
        suspicious=False,
        device_type_hints=[],
        identity_score=1,
        identity_threshold=3,
    )
    assert trigger is True
    assert "identity_weak" in reasons
    assert "low_visibility" in reasons


def test_budget_exhausted(patch_common):
    auditor = MockAuditor()
    auditor.config["deep_scan_budget"] = 2
    ports = {"tcp": {80: {"name": "http", "product": "", "version": "", "cpe": []}}}

    def _nmap_side_effect(target, _args):
        return _make_nmap_mock(ip=target, ports=ports), ""

    with patch.object(auditor, "_run_nmap_xml_scan", side_effect=_nmap_side_effect):
        with patch.object(auditor, "_should_trigger_deep", return_value=(True, ["identity_weak"])):
            with patch.object(auditor, "_run_udp_priority_probe", return_value=False):
                with patch.object(
                    auditor,
                    "deep_scan_host",
                    return_value={"os_detected": "Linux"},
                ) as deep:
                    res1 = auditor.scan_host_ports("1.1.1.1")
                    res2 = auditor.scan_host_ports("1.1.1.2")
                    res3 = auditor.scan_host_ports("1.1.1.3")
    assert deep.call_count == 2
    assert res1["smart_scan"]["deep_scan_executed"] is True
    assert res2["smart_scan"]["deep_scan_executed"] is True
    assert res3["smart_scan"]["deep_scan_executed"] is False
    assert "budget_exhausted" in res3["smart_scan"]["reasons"]


def test_budget_zero_no_limit(patch_common):
    auditor = MockAuditor()
    auditor.config["deep_scan_budget"] = 0
    nm = _make_nmap_mock(
        ports={"tcp": {80: {"name": "http", "product": "", "version": "", "cpe": []}}}
    )
    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm, "")):
        with patch.object(auditor, "_should_trigger_deep", return_value=(True, ["identity_weak"])):
            with patch.object(auditor, "_run_udp_priority_probe", return_value=False):
                with patch.object(auditor, "deep_scan_host", return_value={}) as deep:
                    for i in range(5):
                        auditor.scan_host_ports(f"1.1.1.{10 + i}")
    assert deep.call_count == 5


def test_stealth_no_udp_reorder(patch_common):
    auditor = MockAuditor()
    auditor.config["stealth_mode"] = True
    nm = _make_nmap_mock(
        ports={"tcp": {80: {"name": "http", "product": "", "version": "", "cpe": []}}}
    )
    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm, "")):
        with patch.object(auditor, "_should_trigger_deep", return_value=(True, ["identity_weak"])):
            with patch.object(auditor, "_run_udp_priority_probe") as udp_probe:
                with patch.object(auditor, "deep_scan_host", return_value={}):
                    auditor.scan_host_ports("1.1.1.1")
    assert udp_probe.called is False


def test_udp_reorder_resolves_identity(patch_common):
    auditor = MockAuditor()
    auditor.config["identity_threshold"] = 2
    nm = _make_nmap_mock(
        ports={"tcp": {80: {"name": "http", "product": "", "version": "", "cpe": []}}},
        hostname="host",
    )

    def _udp_probe(host_record):
        phase0 = host_record.setdefault("phase0_enrichment", {})
        phase0["mdns_name"] = "device.local"
        return True

    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm, "")):
        with patch.object(auditor, "_should_trigger_deep", return_value=(True, ["identity_weak"])):
            with patch.object(auditor, "_run_udp_priority_probe", side_effect=_udp_probe):
                with patch.object(auditor, "deep_scan_host", return_value={}) as deep:
                    res = auditor.scan_host_ports("1.1.1.1")
    assert deep.called is False
    assert res["smart_scan"]["trigger_deep"] is False
    assert "udp_resolved_identity" in res["smart_scan"]["reasons"]


def test_phase0_enrichment_signals(patch_common):
    auditor = MockAuditor()
    auditor.config["low_impact_enrichment"] = True
    auditor.config["deep_id_scan"] = False
    nm = _make_nmap_mock(ports={"tcp": {}})
    with patch.object(auditor, "_run_low_impact_enrichment", return_value={"dns_reverse": "host"}):
        with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm, "")):
            res = auditor.scan_host_ports("1.1.1.1")
    assert res["phase0_enrichment"]["dns_reverse"] == "host"
    assert "dns_reverse" in res["smart_scan"]["signals"]
    assert res["smart_scan"]["identity_score"] >= 1


def test_phase0_dns_fallback_no_global_timeout(monkeypatch):
    auditor = MockAuditor()
    auditor.config["low_impact_enrichment"] = True

    class DummySocket:
        def settimeout(self, *_args, **_kwargs):
            return None

        def sendto(self, *_args, **_kwargs):
            return None

        def recvfrom(self, *_args, **_kwargs):
            return b"", ("0.0.0.0", 0)

        def close(self):
            return None

    monkeypatch.setattr(scan_mod.socket, "socket", lambda *_args, **_kwargs: DummySocket())
    mock_setdefault = MagicMock()
    monkeypatch.setattr(scan_mod.socket, "setdefaulttimeout", mock_setdefault)
    monkeypatch.setattr(scan_mod.socket, "gethostbyaddr", lambda _ip: ("host.local", [], []))
    monkeypatch.setattr(scan_mod.shutil, "which", lambda _name: None)

    result = auditor._run_low_impact_enrichment("1.1.1.1")
    assert result.get("dns_reverse") == "host.local"
    mock_setdefault.assert_not_called()


def test_budget_thread_safe_under_concurrency(patch_common):
    auditor = MockAuditor()
    auditor.config["deep_scan_budget"] = 1
    ports = {"tcp": {80: {"name": "http", "product": "", "version": "", "cpe": []}}}
    barrier = threading.Barrier(2)
    deep_started = threading.Event()
    release = threading.Event()

    def _nmap_side_effect(target, _args):
        return _make_nmap_mock(ip=target, ports=ports), ""

    def _should_trigger(*_args, **_kwargs):
        barrier.wait()
        return True, ["identity_weak"]

    def _deep_scan(_ip):
        deep_started.set()
        release.wait(timeout=0.5)
        return {"os_detected": "Linux"}

    with patch.object(auditor, "_run_nmap_xml_scan", side_effect=_nmap_side_effect):
        with patch.object(auditor, "_should_trigger_deep", side_effect=_should_trigger):
            with patch.object(auditor, "_run_udp_priority_probe", return_value=False):
                with patch.object(auditor, "deep_scan_host", side_effect=_deep_scan) as deep:
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        fut1 = pool.submit(auditor.scan_host_ports, "1.1.1.1")
                        fut2 = pool.submit(auditor.scan_host_ports, "1.1.1.2")
                        deep_started.wait(timeout=1.0)
                        release.set()
                        res1 = fut1.result(timeout=2.0)
                        res2 = fut2.result(timeout=2.0)

    assert deep.call_count == 1
    assert "budget_exhausted" in (res1.get("smart_scan") or {}).get(
        "reasons", []
    ) or "budget_exhausted" in (res2.get("smart_scan") or {}).get("reasons", [])


def test_escalation_reason_in_json(patch_common):
    auditor = MockAuditor()
    nm = _make_nmap_mock(
        ports={"tcp": {80: {"name": "http", "product": "", "version": "", "cpe": []}}}
    )
    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm, "")):
        with patch.object(auditor, "_should_trigger_deep", return_value=(True, ["identity_weak"])):
            with patch.object(auditor, "_run_udp_priority_probe", return_value=False):
                with patch.object(auditor, "deep_scan_host", return_value={"os_detected": "Linux"}):
                    res = auditor.scan_host_ports("1.1.1.1")
    assert isinstance(res["smart_scan"]["escalation_reason"], str)


def test_escalation_path_recorded(patch_common):
    auditor = MockAuditor()
    nm = _make_nmap_mock(
        ports={"tcp": {80: {"name": "http", "product": "", "version": "", "cpe": []}}}
    )
    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm, "")):
        with patch.object(auditor, "_should_trigger_deep", return_value=(True, ["identity_weak"])):
            with patch.object(auditor, "_run_udp_priority_probe", return_value=False):
                with patch.object(auditor, "deep_scan_host", return_value={"os_detected": "Linux"}):
                    res = auditor.scan_host_ports("1.1.1.1")
    path = res["smart_scan"]["escalation_path"] or ""
    assert "nmap_initial" in path
    assert "tcp_aggressive" in path
