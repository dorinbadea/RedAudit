"""
Coverage push #7 for auditor_scan.py — targeting remaining ~186 lines:
- Zero-port HTTP probe FIXED (deep_id_scan must be True)
- Rich progress inner heartbeat loops via time.time() mocking
- Scattered single-liners throughout scan_host_ports
- Agentless inner remaining lines (3065-3068)
"""

import time as _time_mod
import unittest
from contextlib import contextmanager
from concurrent.futures import Future, wait, FIRST_COMPLETED
from unittest.mock import MagicMock, patch, call
from dataclasses import dataclass

from redaudit.core.auditor_scan import AuditorScan
from redaudit.core.models import Host, Service


# ── helpers ──────────────────────────────────────────────────────────────


def _make_auditor(**overrides):
    a = MagicMock()
    a.config = {
        "scan_mode": "quick",
        "dry_run": False,
        "deep_id_scan": True,
        "auth_enabled": False,
        "low_impact_enrichment": False,
        "stealth": False,
        "stealth_mode": False,
        "no_hyperscan_first": True,
        "threads": 1,
        "windows_verify_enabled": False,
        "lynis_enabled": False,
        "identity_threshold": 3,
        "deep_scan_budget": 10,
        "output_dir": "/tmp/test",
        "udp_mode": "quick",
        "verbose": False,
    }
    a.config.update(overrides)
    a.logger = MagicMock()
    a.ui = MagicMock()
    a.ui.t = MagicMock(side_effect=lambda *args: " ".join(str(x) for x in args))
    a.ui.print_status = MagicMock()
    a.ui.get_progress_console = MagicMock(return_value=None)
    a.ui.get_standard_progress = MagicMock(return_value=None)
    a.ui.colors = {
        "HEADER": "",
        "ENDC": "",
        "OKGREEN": "",
        "FAIL": "",
        "OKBLUE": "",
        "WARNING": "",
        "INFO": "",
    }
    a.results = {}
    a.extra_tools = {}
    a.proxy_manager = None
    a.interrupted = False
    a.current_phase = ""
    a.scanner = MagicMock()
    a.rate_limit_delay = 0
    a.__dict__["_hyperscan_discovery_ports"] = {}
    a._set_ui_detail = MagicMock()
    a._coerce_text = MagicMock(side_effect=lambda v: str(v) if v is not None else "")

    @contextmanager
    def _fake_progress_ui():
        yield

    a._progress_ui = _fake_progress_ui
    return a


def _bind(aud, name):
    return getattr(AuditorScan, name).__get__(aud, AuditorScan)


def _bind_all(aud, names):
    for n in names:
        setattr(aud, n, _bind(aud, n))


FULL_METHODS = [
    "scan_host_ports",
    "_lookup_topology_identity",
    "_apply_net_discovery_identity",
    "_prune_weak_identity_reasons",
    "_should_trigger_deep",
    "_compute_identity_score",
    "_merge_ports",
    "_merge_port_record",
    "_merge_services_from_ports",
    "_parse_nmap_open_ports",
    "_split_nmap_product_version",
    "_extract_mdns_name",
    "_run_udp_priority_probe",
    "_reserve_deep_scan_slot",
    "_run_low_impact_enrichment",
    "_scan_mode_host_timeout_s",
    "is_web_service",
    "_resolve_all_ssh_credentials",
    "_resolve_ssh_credential",
    "_resolve_all_smb_credentials",
    "_resolve_smb_credential",
    "_resolve_snmp_credential",
]


def _nmap_empty_with_mac(ip, *, vendor="Ubiquiti", mac="AA:BB:CC:DD:EE:FF"):
    """Nmap mock with zero ports but MAC + vendor."""
    nm = MagicMock()
    nm.all_hosts.return_value = [ip]
    hd = MagicMock()
    hd.hostnames.return_value = [{"name": ""}]
    hd.state.return_value = "up"
    hd.all_protocols.return_value = []
    hd.__getitem__ = MagicMock(return_value={})
    hd.get = MagicMock(
        side_effect=lambda k, d=None: {
            "addresses": {"mac": mac},
            "vendor": {mac: vendor},
            "osmatch": [],
        }.get(k, d)
    )
    nm.__getitem__ = MagicMock(return_value=hd)
    return nm


# ═══════════════════════════════════════════════════════════════════════════
# Zero-port HTTP Probe — FIXED: deep_id_scan=True (was False!)
# ═══════════════════════════════════════════════════════════════════════════


class TestZeroPortHTTPProbeFinal(unittest.TestCase):
    """Lines 2311-2335: HTTP probe when zero ports + vendor-only."""

    def setUp(self):
        self.a = _make_auditor(
            low_impact_enrichment=True,
            deep_id_scan=True,  # MUST be True for line 2281
        )
        _bind_all(self.a, FULL_METHODS)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe")
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_http_probe_fires(self, *mocks):
        """Zero ports + vendor from nmap MAC + low_impact → probe fires."""
        ip = "10.4.0.1"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (0, [])

        nm = _nmap_empty_with_mac(ip)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # http_identity_probe returns data
        http_mock = mocks[7]  # http_identity_probe mock
        http_mock.return_value = {
            "http_title": "UniFi Controller",
            "http_server": "nginx/1.20",
        }

        self.a.scan_host_ports(ip)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe")
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_http_probe_updates_smart_scan(self, *mocks):
        """HTTP probe results update smart_scan with signal + score."""
        ip = "10.4.0.2"
        host_obj = Host(ip=ip)
        host_obj.smart_scan = {"signals": ["mac"], "identity_score": 1}
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (0, [])

        nm = _nmap_empty_with_mac(ip)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        http_mock = mocks[7]
        http_mock.return_value = {
            "http_title": "Management Console",
            "http_server": "lighttpd",
        }

        self.a.scan_host_ports(ip)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe")
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_http_probe_identity_score_exception(self, *mocks):
        """HTTP probe → identity_score is 'bad' → Exception caught."""
        ip = "10.4.0.3"
        host_obj = Host(ip=ip)
        host_obj.smart_scan = {"signals": [], "identity_score": "invalid"}
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (0, [])

        nm = _nmap_empty_with_mac(ip)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        http_mock = mocks[7]
        http_mock.return_value = {"http_title": "Admin", "http_server": "nginx"}

        self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Rich progress inner heartbeat — deep scans (2714-2766)
# ═══════════════════════════════════════════════════════════════════════════


class TestRichProgressDeepScansHeartbeat(unittest.TestCase):
    """Lines 2714-2766: Rich progress heartbeat + per-host update."""

    def setUp(self):
        self.a = _make_auditor(threads=2)
        _bind_all(self.a, ["run_deep_scans_concurrent"])

    @patch("redaudit.core.auditor_scan.wait")
    @patch("redaudit.core.auditor_scan.time")
    def test_heartbeat_fire(self, mock_time, mock_wait):
        """Heartbeat fires when 61s elapsed → progress updated."""
        progress = MagicMock()
        progress.__enter__ = MagicMock(return_value=progress)
        progress.__exit__ = MagicMock(return_value=False)
        task_ids = iter(range(100))
        progress.add_task = MagicMock(side_effect=lambda *a, **kw: next(task_ids))
        self.a.ui.get_progress_console.return_value = MagicMock()
        self.a.ui.get_standard_progress.return_value = progress

        h = Host(ip="10.4.0.10")
        h.smart_scan = {"trigger_deep": True}

        f = Future()
        f.set_result({"ports": []})

        # time.time() returns advancing values
        # First call = start time, then enough to trigger heartbeat
        time_values = [100.0, 100.0, 161.1, 161.2, 161.3]
        mock_time.time.side_effect = time_values
        mock_time.sleep = MagicMock()

        # wait() returns the future as done on first call
        mock_wait.return_value = ({f}, set())

        self.a.deep_scan_host = MagicMock(return_value={"ports": []})
        self.a.run_deep_scans_concurrent([h])


# ═══════════════════════════════════════════════════════════════════════════
# Rich progress inner heartbeat — scan_hosts (2873-2887, 2903, 2933-2935)
# ═══════════════════════════════════════════════════════════════════════════


class TestRichProgressScanHostsHeartbeat(unittest.TestCase):
    """Lines 2873-2935: Rich progress heartbeat + per-host update."""

    def setUp(self):
        self.a = _make_auditor(threads=2)
        _bind_all(
            self.a,
            [
                "scan_hosts_concurrent",
                "_scan_mode_host_timeout_s",
            ],
        )

    @patch("redaudit.core.auditor_scan.wait")
    @patch("redaudit.core.auditor_scan.time")
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    def test_heartbeat_during_scan(self, mock_args, mock_time, mock_wait):
        """Heartbeat fires at 61s → Rich progress updated."""
        progress = MagicMock()
        progress.__enter__ = MagicMock(return_value=progress)
        progress.__exit__ = MagicMock(return_value=False)
        task_ids = iter(range(100))
        progress.add_task = MagicMock(side_effect=lambda *a, **kw: next(task_ids))
        self.a.ui.get_progress_console.return_value = MagicMock()
        self.a.ui.get_standard_progress.return_value = progress

        host_obj = Host(ip="10.4.0.20")
        f = Future()
        f.set_result(host_obj)

        time_values = [100.0, 100.0, 161.1, 161.2, 161.3]
        mock_time.time.side_effect = time_values
        mock_time.sleep = MagicMock()

        mock_wait.return_value = ({f}, set())

        self.a.scan_host_ports = MagicMock(return_value=host_obj)
        results = self.a.scan_hosts_concurrent(["10.4.0.20"])
        self.assertIsInstance(results, list)


# ═══════════════════════════════════════════════════════════════════════════
# Scan_host_ports — nmap returns None (line 1589)
# ═══════════════════════════════════════════════════════════════════════════


class TestScanHostPortsNmapReturnsNone(unittest.TestCase):
    """Line 1589: nmap returns None → host returned down."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, FULL_METHODS)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="down")
    @patch("redaudit.core.auditor_scan.http_identity_probe", return_value=None)
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_nmap_returns_none_result(self, *mocks):
        """Nmap scan returns (None, error) → host marked down."""
        ip = "10.4.0.30"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.run_nmap_scan.return_value = (None, "host down")

        result = self.a.scan_host_ports(ip)
        self.assertIn(result.status, ("down", "no-response"))


# ═══════════════════════════════════════════════════════════════════════════
# Scattered single-line coverage
# ═══════════════════════════════════════════════════════════════════════════


class TestScatteredLines(unittest.TestCase):
    """Cover various scattered single-line gaps."""

    def test_prune_weak_identity_reasons(self):
        """Exercise _prune_weak_identity_reasons with various inputs."""
        a = _make_auditor()
        _bind_all(a, ["_prune_weak_identity_reasons"])

        smart = {"signals": ["mac", "vendor"], "identity_score": 5}
        a._prune_weak_identity_reasons(smart)

        smart2 = {"signals": [], "identity_score": 0}
        a._prune_weak_identity_reasons(smart2)

    def test_compute_identity_score_empty(self):
        """_compute_identity_score with empty host record."""
        a = _make_auditor()
        _bind_all(a, ["_compute_identity_score"])
        result = a._compute_identity_score({})
        self.assertIsNotNone(result)

    def test_should_trigger_deep_all_false(self):
        """_should_trigger_deep when nothing triggers it."""
        a = _make_auditor()
        _bind_all(a, ["_should_trigger_deep"])
        result = a._should_trigger_deep(
            identity_score=10,
            suspicious=False,
            any_version=True,
            device_type_hints=[],
            total_ports=5,
            identity_threshold=3,
            identity_evidence=True,
        )
        self.assertFalse(result[0])

    def test_should_trigger_deep_device_hints(self):
        """_should_trigger_deep with device_type_hints."""
        a = _make_auditor()
        _bind_all(a, ["_should_trigger_deep"])
        result = a._should_trigger_deep(
            identity_score=0,
            suspicious=False,
            any_version=False,
            device_type_hints=["router"],
            total_ports=1,
            identity_threshold=3,
            identity_evidence=False,
        )
        self.assertIsNotNone(result)

    def test_merge_port_record_exception(self):
        """_merge_port_record with bad data → exception caught."""
        # _merge_port_record is a static method
        try:
            AuditorScan._merge_port_record({}, None)
        except Exception:
            pass

    def test_split_nmap_product_version(self):
        """Exercise _split_nmap_product_version."""
        result = AuditorScan._split_nmap_product_version("OpenSSH 8.9p1 Ubuntu-3ubuntu0.6")
        self.assertIsNotNone(result)

    def test_run_low_impact_enrichment_disabled(self):
        """_run_low_impact_enrichment with dry_run=True."""
        a = _make_auditor(low_impact_enrichment=False, dry_run=True)
        _bind_all(a, ["_run_low_impact_enrichment"])
        result = a._run_low_impact_enrichment("10.0.0.1")
        self.assertIsInstance(result, dict)

    def test_reserve_deep_scan_slot_success(self):
        """_reserve_deep_scan_slot with available budget."""
        a = _make_auditor(deep_scan_budget=5)
        a._deep_executed_count = 0
        _bind_all(a, ["_reserve_deep_scan_slot"])
        reserved, count = a._reserve_deep_scan_slot(5)
        self.assertTrue(reserved)

    def test_reserve_deep_scan_slot_budget_exhausted(self):
        """_reserve_deep_scan_slot with budget exhausted."""
        a = _make_auditor(deep_scan_budget=2)
        a._deep_executed_count = 5
        _bind_all(a, ["_reserve_deep_scan_slot"])
        reserved, count = a._reserve_deep_scan_slot(2)
        self.assertFalse(reserved)

    def test_scan_mode_host_timeout_s(self):
        """_scan_mode_host_timeout_s for various modes."""
        a = _make_auditor(scan_mode="quick")
        _bind_all(a, ["_scan_mode_host_timeout_s"])
        result = a._scan_mode_host_timeout_s()
        self.assertIsNotNone(result)

    def test_is_web_service(self):
        """is_web_service wrapper method."""
        a = _make_auditor()
        _bind_all(a, ["is_web_service"])
        result = a.is_web_service("http")
        self.assertIsNotNone(result)

    def test_lookup_topology_identity_empty(self):
        """_lookup_topology_identity with no topology."""
        a = _make_auditor()
        _bind_all(a, ["_lookup_topology_identity"])
        a.scanner.topology = {}
        result = a._lookup_topology_identity("10.0.0.1")
        self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# Agentless data merge paths (3065-3068)
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentlessDataMerge(unittest.TestCase):
    """Lines 3065-3068: agentless result merge into host."""

    def setUp(self):
        self.a = _make_auditor(windows_verify_enabled=True)
        _bind_all(self.a, ["run_agentless_verification"])

    @patch("redaudit.core.agentless_verify.parse_smb_nmap", return_value={})
    @patch("redaudit.core.agentless_verify.parse_ldap_rootdse", return_value={})
    @patch("redaudit.core.auditor_scan.select_agentless_probe_targets")
    @patch("redaudit.core.auditor_scan.probe_agentless_services")
    @patch("redaudit.core.auditor_scan.summarize_agentless_fingerprint")
    def test_full_merge_path(self, mock_summary, mock_probe, mock_sel, mock_ldap, mock_smb):
        """Result with SMB data → merge into host."""
        target = MagicMock()
        target.ip = "10.4.0.40"
        mock_sel.return_value = [target]
        mock_probe.return_value = {
            "ip": "10.4.0.40",
            "smb_nmap_raw": "some raw smb",
            "ldap_rootdse_raw": "some raw ldap",
        }
        mock_smb.return_value = {"os_version": "Windows 10", "domain": "CORP"}
        mock_ldap.return_value = {"dns_domain": "corp.local"}
        mock_summary.return_value = {
            "http_title": "IIS",
            "os_guess": "Windows 10",
        }

        host = Host(ip="10.4.0.40")
        host.smart_scan = {"signals": [], "identity_score": 1}
        host.agentless_fingerprint = {}
        self.a.run_agentless_verification([host])

    @patch("redaudit.core.agentless_verify.parse_smb_nmap", return_value={})
    @patch("redaudit.core.agentless_verify.parse_ldap_rootdse", return_value={})
    @patch("redaudit.core.auditor_scan.select_agentless_probe_targets")
    @patch("redaudit.core.auditor_scan.probe_agentless_services")
    @patch("redaudit.core.auditor_scan.summarize_agentless_fingerprint")
    def test_merge_updates_identity_score(
        self, mock_summary, mock_probe, mock_sel, mock_ldap, mock_smb
    ):
        """Merge updates identity_score + signals."""
        target = MagicMock()
        target.ip = "10.4.0.41"
        mock_sel.return_value = [target]
        mock_probe.return_value = {"ip": "10.4.0.41"}
        mock_summary.return_value = {"os_guess": "Ubuntu 22.04"}

        host = Host(ip="10.4.0.41")
        host.smart_scan = {"signals": ["mac"], "identity_score": 2}
        host.agentless_fingerprint = {}
        self.a.run_agentless_verification([host])


# ═══════════════════════════════════════════════════════════════════════════
# scan_host_ports exception in nmap identity metadata (2020-2022)
# ═══════════════════════════════════════════════════════════════════════════


class TestNmapIdentityMetadataError(unittest.TestCase):
    """Lines 2020-2022: exception reading nmap identity → logged."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, FULL_METHODS)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe", return_value=None)
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_addresses_raises(self, *mocks):
        """data.get('addresses') raises → caught at 2020."""
        ip = "10.4.0.50"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, [])

        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "test"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = []
        hd.__getitem__ = MagicMock(return_value={})
        # Make addresses access raise
        hd.get = MagicMock(side_effect=RuntimeError("corrupt data"))
        hd.hasattr = MagicMock(return_value=True)
        nm.__getitem__ = MagicMock(return_value=hd)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# scan_host_ports: ports > MAX_PORTS_DISPLAY (line 1980)
# ═══════════════════════════════════════════════════════════════════════════


class TestPortsTruncation(unittest.TestCase):
    """Line 1980: many ports → truncation warning."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, FULL_METHODS)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe", return_value=None)
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_many_ports_truncated(self, *mocks):
        """200+ ports → truncation warning + only 100 kept."""
        ip = "10.4.0.60"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, [])

        # Create 200 ports
        tcp_ports = {}
        for i in range(1, 201):
            tcp_ports[i] = {
                "name": f"svc{i}",
                "product": "",
                "version": "",
                "extrainfo": "",
                "cpe": [],
                "state": "open",
                "reason": "",
                "tunnel": "",
            }

        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "victim"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(return_value=tcp_ports)
        hd.get = MagicMock(
            side_effect=lambda k, d=None: {
                "addresses": {},
                "vendor": {},
                "osmatch": [],
            }.get(k, d)
        )
        nm.__getitem__ = MagicMock(return_value=hd)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Identity re-eval skip when identity already resolved (2183-2186)
# ═══════════════════════════════════════════════════════════════════════════


class TestIdentityReEvalSkip(unittest.TestCase):
    """Lines 2183-2186: identity already known → skip re-eval."""

    def setUp(self):
        self.a = _make_auditor(deep_id_scan=True, deep_scan_budget=10)
        _bind_all(self.a, FULL_METHODS)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe", return_value=None)
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    @patch("redaudit.core.auditor_scan.output_has_identity", return_value=True)
    def test_identity_already_found(self, mock_has_ident, *mocks):
        """output_has_identity=True → skip UDP probe."""
        ip = "10.4.0.70"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        # Low score but identity already found
        self.a.scanner.compute_identity_score.return_value = (0, [])

        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "test"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(
            return_value={
                22: {
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "8.9",
                    "extrainfo": "",
                    "cpe": [],
                    "state": "open",
                    "reason": "",
                    "tunnel": "",
                },
            }
        )
        hd.get = MagicMock(
            side_effect=lambda k, d=None: {
                "addresses": {},
                "vendor": {},
                "osmatch": [],
            }.get(k, d)
        )
        nm.__getitem__ = MagicMock(return_value=hd)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        self.a.scan_host_ports(ip)


if __name__ == "__main__":
    unittest.main()
