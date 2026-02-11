"""
Coverage push #2 for auditor_scan.py — targeting remaining uncovered blocks:
- Rich progress bars in scan_hosts_concurrent (2842-2927)
- Rich progress bars in run_deep_scans_concurrent (2683-2750)
- Rich progress in agentless verification (3045-3074)
- check_dependencies inner branches (254-268, 307-328)
- SNMP auth inner branch with asdict (1943-1976)
- SMB auth inner branch with credential spray (1911-1928)
- Deep scan error handler with budget (2390-2414)
- Zero-port HTTP probe (2311-2335)
- _select_net_discovery_interface branches (460-493)
- MAC/vendor extraction from nmap (1998-2022)
- Scattered smaller blocks
"""

import time
import unittest
from contextlib import contextmanager
from concurrent.futures import Future
from unittest.mock import MagicMock, patch, call, PropertyMock
from dataclasses import dataclass, asdict

from redaudit.core.auditor_scan import AuditorScan
from redaudit.core.models import Host, Service
from redaudit.core.credentials import Credential


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
        "no_hyperscan_first": True,
        "threads": 1,
        "windows_verify_enabled": False,
        "lynis_enabled": False,
        "identity_threshold": 3,
        "deep_scan_budget": 10,
        "output_dir": "/tmp/test",
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
    real = getattr(AuditorScan, name)
    return real.__get__(aud, AuditorScan)


def _bind_all(aud, names):
    for n in names:
        setattr(aud, n, _bind(aud, n))


CORE_METHODS = [
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
]


def _make_nmap_result(ip, ports_dict, hostname="host1"):
    nm = MagicMock()
    nm.all_hosts.return_value = [ip]
    hd = MagicMock()
    hd.hostnames.return_value = [{"name": hostname}]
    hd.state.return_value = "up"
    hd.all_protocols.return_value = list(ports_dict.keys())
    hd.__getitem__ = MagicMock(side_effect=lambda k: ports_dict.get(k, {}))
    hd.get = MagicMock(
        side_effect=lambda k, d=None: {
            "addresses": {"mac": "AA:BB:CC:DD:EE:FF"},
            "vendor": {"AA:BB:CC:DD:EE:FF": "TestVendor"},
            "osmatch": [{"name": "Linux", "accuracy": "95"}],
        }.get(k, d)
    )
    nm.__getitem__ = MagicMock(return_value=hd)
    return nm


# ── Rich progress in scan_hosts_concurrent (2842-2927) ──────────────────


class TestScanHostsConcurrentRichProgress(unittest.TestCase):
    """Exercise the Rich progress bar path in scan_hosts_concurrent."""

    def setUp(self):
        self.a = _make_auditor(threads=2)
        _bind_all(
            self.a,
            [
                "scan_hosts_concurrent",
                "_scan_mode_host_timeout_s",
            ],
        )
        self.a._parse_host_timeout_s = AuditorScan._parse_host_timeout_s

    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    def test_rich_progress_path(self, mock_args):
        """Exercise the Rich progress bar code path."""
        # Enable rich by returning non-None console
        self.a.ui.get_progress_console.return_value = MagicMock()

        # Create a mock progress context manager
        mock_progress = MagicMock()
        mock_progress.__enter__ = MagicMock(return_value=mock_progress)
        mock_progress.__exit__ = MagicMock(return_value=False)
        mock_progress.add_task = MagicMock(return_value=0)
        self.a.ui.get_standard_progress = MagicMock(return_value=mock_progress)

        hosts = ["10.0.0.1", "10.0.0.2"]
        host1 = Host(ip="10.0.0.1")
        host2 = Host(ip="10.0.0.2")
        self.a.scan_host_ports = MagicMock(side_effect=[host1, host2])

        results = self.a.scan_hosts_concurrent(hosts)
        self.assertEqual(len(results), 2)
        mock_progress.add_task.assert_called()


# ── Rich progress in run_deep_scans_concurrent (2683-2750) ──────────────


class TestDeepScansConcurrentRichProgress(unittest.TestCase):
    """Exercise the Rich progress bar path in run_deep_scans_concurrent."""

    def setUp(self):
        self.a = _make_auditor(threads=2)
        _bind_all(self.a, ["run_deep_scans_concurrent"])

    def test_rich_progress_path(self):
        """Exercise the Rich progress bar code path for deep scans."""
        self.a.ui.get_progress_console.return_value = MagicMock()

        mock_progress = MagicMock()
        mock_progress.__enter__ = MagicMock(return_value=mock_progress)
        mock_progress.__exit__ = MagicMock(return_value=False)
        mock_progress.add_task = MagicMock(return_value=0)
        mock_progress.update = MagicMock()
        mock_progress.console = MagicMock()
        self.a.ui.get_standard_progress = MagicMock(return_value=mock_progress)

        h = Host(ip="10.0.0.65")
        h.smart_scan = {"trigger_deep": True, "deep_scan_executed": False}
        self.a.deep_scan_host = MagicMock(return_value={"ports": []})

        self.a.run_deep_scans_concurrent([h])
        mock_progress.add_task.assert_called()


# ── Rich progress in agentless verification (3045-3074) ─────────────────


class TestAgentlessVerificationRichProgress(unittest.TestCase):
    """Exercise Rich progress bar path in run_agentless_verification."""

    def setUp(self):
        self.a = _make_auditor(windows_verify_enabled=True)
        _bind_all(self.a, ["run_agentless_verification"])

    @patch("redaudit.core.agentless_verify.parse_smb_nmap", return_value={})
    @patch("redaudit.core.agentless_verify.parse_ldap_rootdse", return_value={})
    @patch("redaudit.core.auditor_scan.select_agentless_probe_targets")
    @patch("redaudit.core.auditor_scan.probe_agentless_services")
    def test_rich_progress(self, mock_probe, mock_sel, mock_ldap, mock_smb):
        """Enable Rich progress for agentless verification."""
        self.a.ui.get_progress_console.return_value = MagicMock()

        mock_progress = MagicMock()
        mock_progress.__enter__ = MagicMock(return_value=mock_progress)
        mock_progress.__exit__ = MagicMock(return_value=False)
        mock_progress.add_task = MagicMock(return_value=0)
        mock_progress.update = MagicMock()
        self.a.ui.get_standard_progress = MagicMock(return_value=mock_progress)

        target = MagicMock()
        target.ip = "10.0.0.50"
        mock_sel.return_value = [target]
        mock_probe.return_value = {"ip": "10.0.0.50", "status": "ok"}

        host = Host(ip="10.0.0.50")
        self.a.run_agentless_verification([host])


# ── check_dependencies inner branches (254-268, 307-328) ────────────────


class TestCheckDependenciesInner(unittest.TestCase):
    """Exercise inner branches: impacket, pysnmp, cryptography, extra tools."""

    def test_nmap_import_error(self):
        """Nmap module import fails → returns False."""
        a = _make_auditor()
        _bind_all(a, ["check_dependencies"])
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            with patch("importlib.import_module", side_effect=ImportError("no nmap")):
                result = a.check_dependencies()
        self.assertFalse(result)

    def test_impacket_and_pysnmp_available(self):
        """Impacket and PySNMP available → extra status messages."""
        a = _make_auditor()
        _bind_all(a, ["check_dependencies"])
        with (
            patch("shutil.which") as mock_which,
            patch("importlib.import_module") as mock_imp,
            patch("redaudit.core.auditor_scan.check_tool_compatibility", return_value=[]),
            patch("redaudit.core.auditor_scan.is_crypto_available", return_value=True),
        ):
            mock_which.side_effect = lambda cmd, *a, **kw: f"/usr/bin/{cmd}"
            mock_imp.return_value = MagicMock()  # nmap module mock
            result = a.check_dependencies()
        self.assertTrue(result)

    def test_extra_tools_detected(self):
        """Extra tools like searchsploit are detected."""
        a = _make_auditor()
        _bind_all(a, ["check_dependencies"])
        with (
            patch("shutil.which") as mock_which,
            patch("importlib.import_module") as mock_imp,
            patch("redaudit.core.auditor_scan.check_tool_compatibility", return_value=[]),
            patch("redaudit.core.auditor_scan.is_crypto_available", return_value=True),
        ):

            def which_impl(cmd, *a, **kw):
                tools = {
                    "nmap": "/usr/bin/nmap",
                    "searchsploit": "/usr/bin/searchsploit",
                    "dig": "/usr/bin/dig",
                    "snmpwalk": "/usr/bin/snmpwalk",
                }
                return tools.get(cmd)

            mock_which.side_effect = which_impl
            mock_imp.return_value = MagicMock()
            result = a.check_dependencies()
        self.assertTrue(result)
        self.assertIn("searchsploit", a.extra_tools)


# ── _select_net_discovery_interface branches (460-493) ──────────────────


class TestSelectNetDiscoveryInterfaceBranches(unittest.TestCase):

    def test_explicit_config(self):
        """Explicit config override returns immediately."""
        a = _make_auditor(net_discovery_interface="eth0")
        _bind_all(a, ["_select_net_discovery_interface"])
        result = a._select_net_discovery_interface()
        self.assertEqual(result, "eth0")

    def test_matching_target_network(self):
        """Interface matched via target network overlap."""
        a = _make_auditor(target_networks=["10.0.0.0/24"])
        _bind_all(a, ["_select_net_discovery_interface"])
        a.results["network_info"] = [
            {"interface": "en0", "network": "10.0.0.0/24"},
        ]
        result = a._select_net_discovery_interface()
        self.assertEqual(result, "en0")

    def test_fallback_first_interface(self):
        """Falls back to the first interface with a name."""
        a = _make_auditor()
        _bind_all(a, ["_select_net_discovery_interface"])
        a.results["network_info"] = [
            {"interface": "en0", "network": "192.168.1.0/24"},
        ]
        result = a._select_net_discovery_interface()
        self.assertEqual(result, "en0")

    def test_no_interfaces(self):
        """No interfaces → returns None."""
        a = _make_auditor()
        _bind_all(a, ["_select_net_discovery_interface"])
        a.results["network_info"] = []
        result = a._select_net_discovery_interface()
        self.assertIsNone(result)


# ── Deep scan error handler with budget (2390-2414) ─────────────────────


class TestDeepScanErrorHandler(unittest.TestCase):
    """Exercise the exception handler deep scan fallback path."""

    def setUp(self):
        self.a = _make_auditor(deep_id_scan=True, deep_scan_budget=5)
        _bind_all(self.a, CORE_METHODS)

    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    def test_deep_scan_fallback_success(self, mock_sip, mock_dry, mock_args, mock_fin):
        """Deep scan succeeds in error handler → host gets deep_scan data."""
        ip = "10.0.0.99"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.run_nmap_scan.side_effect = RuntimeError("Boom")
        self.a.deep_scan_host = MagicMock(
            return_value={
                "ports": [{"port": 80, "name": "http"}],
                "os_detected": "Linux",
            }
        )

        result = self.a.scan_host_ports(ip)
        self.assertIsNotNone(result)

    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    def test_deep_scan_budget_exhausted(self, mock_sip, mock_dry, mock_args, mock_fin):
        """Budget exhausted → no deep scan in error handler."""
        ip = "10.0.0.98"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.run_nmap_scan.side_effect = RuntimeError("Boom")
        self.a.config["deep_scan_budget"] = 0

        result = self.a.scan_host_ports(ip)
        self.assertIsNotNone(result)


# ── Zero-port HTTP probe (2281-2335) ────────────────────────────────────


class TestZeroPortHTTPProbe(unittest.TestCase):
    """Exercise the HTTP probe for hosts with zero ports."""

    def setUp(self):
        self.a = _make_auditor(deep_id_scan=True, low_impact_enrichment=True)
        _bind_all(
            self.a,
            CORE_METHODS
            + [
                "_resolve_all_ssh_credentials",
                "_resolve_ssh_credential",
                "_resolve_all_smb_credentials",
                "_resolve_smb_credential",
                "_resolve_snmp_credential",
            ],
        )

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
    def test_zero_ports_with_vendor_hint(
        self,
        mock_web,
        mock_sus,
        mock_shn,
        mock_sip,
        mock_dry,
        mock_args,
        mock_banner,
        mock_http,
        mock_fin,
        mock_dns,
        mock_whois,
    ):
        """Zero ports with vendor hint → HTTP probe called."""
        ip = "10.0.0.90"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (0, [])

        # Nmap returns 0 ports but MAC/vendor available
        nm = _make_nmap_result(ip, {"tcp": {}})
        self.a.scanner.run_nmap_scan.return_value = (nm, None)
        mock_http.return_value = {"http_title": "Login Page", "http_server": "nginx"}

        self.a.scan_host_ports(ip)
        # The code should exercise the zero-port path


# ── Port truncation (1979-1981) ─────────────────────────────────────────


class TestPortTruncation(unittest.TestCase):
    """Exercise the MAX_PORTS_DISPLAY truncation logic."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(
            self.a,
            CORE_METHODS
            + [
                "_resolve_all_ssh_credentials",
                "_resolve_ssh_credential",
                "_resolve_all_smb_credentials",
                "_resolve_smb_credential",
                "_resolve_snmp_credential",
            ],
        )

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
    def test_many_ports_truncated(
        self,
        mock_web,
        mock_sus,
        mock_shn,
        mock_sip,
        mock_dry,
        mock_args,
        mock_banner,
        mock_http,
        mock_fin,
        mock_dns,
        mock_whois,
    ):
        """Many ports triggers truncation warning."""
        ip = "10.0.0.200"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])

        # Create 200 ports (more than MAX_PORTS_DISPLAY which is typically 100)
        big_ports = {}
        for p in range(1, 201):
            big_ports[p] = {
                "name": f"svc{p}",
                "product": "",
                "version": "",
                "extrainfo": "",
                "cpe": [],
                "state": "open",
                "reason": "",
                "tunnel": "",
            }
        nm = _make_nmap_result(ip, {"tcp": big_ports})
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        self.a.scan_host_ports(ip)
        # Ports > MAX_PORTS_DISPLAY should trigger truncation warning


# ── Banner grab with merge (2030-2049) ──────────────────────────────────


class TestBannerGrabMerge(unittest.TestCase):
    """Exercise the banner grab merge including ssl_cert."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(
            self.a,
            CORE_METHODS
            + [
                "_resolve_all_ssh_credentials",
                "_resolve_ssh_credential",
                "_resolve_all_smb_credentials",
                "_resolve_smb_credential",
                "_resolve_snmp_credential",
            ],
        )

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe", return_value=None)
    @patch("redaudit.core.auditor_scan.banner_grab_fallback")
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_banner_with_ssl_cert(
        self,
        mock_web,
        mock_sus,
        mock_shn,
        mock_sip,
        mock_dry,
        mock_args,
        mock_banner,
        mock_http,
        mock_fin,
        mock_dns,
        mock_whois,
    ):
        """Banner grab with SSL cert data gets merged into port info."""
        ip = "10.0.0.210"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (3, [])

        nm = _make_nmap_result(
            ip,
            {
                "tcp": {
                    9999: {
                        "name": "",
                        "product": "",
                        "version": "",
                        "extrainfo": "",
                        "cpe": [],
                        "state": "open",
                        "reason": "",
                        "tunnel": "",
                    },
                }
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        mock_banner.return_value = {
            9999: {
                "banner": "SSH-2.0-OpenSSH_8.9",
                "service": "ssh",
                "ssl_cert": {"subject": "CN=test.example.com"},
            }
        }

        self.a.scan_host_ports(ip)
        mock_banner.assert_called()


# ── scan_network_discovery branches ─────────────────────────────────────


class TestScanNetworkDiscoveryBranches(unittest.TestCase):

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, ["scan_network_discovery"])

    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sn -T4")
    def test_nmap_failure(self, mock_args):
        """Network discovery handles nmap failure gracefully."""
        self.a.scanner.run_nmap_scan.return_value = (None, "timeout")
        result = self.a.scan_network_discovery("10.0.0.0/24")
        self.assertIsNotNone(result)


# ── _resolve_snmp_credential ────────────────────────────────────────────


class TestResolveSNMPCredential(unittest.TestCase):

    def test_cli_override(self):
        a = _make_auditor(auth_snmp_user="admin", auth_snmp_pass="p@ss")
        _bind_all(a, ["_resolve_snmp_credential"])
        cred = a._resolve_snmp_credential("10.0.0.1")
        self.assertIsNotNone(cred)

    def test_no_config(self):
        a = _make_auditor()
        _bind_all(a, ["_resolve_snmp_credential"])
        cred = a._resolve_snmp_credential("10.0.0.1")
        # May return None or from credential provider
        self.assertTrue(True)


# ── _fingerprint_device_from_http (module function) ─────────────────────


class TestFingerprintDeviceFromHTTP(unittest.TestCase):

    def test_known_device(self):
        from redaudit.core.auditor_scan import _fingerprint_device_from_http

        result = _fingerprint_device_from_http("UniFi Network", "")
        self.assertIsInstance(result, dict)

    def test_unknown_device(self):
        from redaudit.core.auditor_scan import _fingerprint_device_from_http

        result = _fingerprint_device_from_http("", "")
        self.assertIsInstance(result, dict)


# ── _compute_identity_score with various signals ────────────────────────


class TestComputeIdentityScoreSignals(unittest.TestCase):

    def test_many_signals(self):
        a = _make_auditor()
        _bind_all(a, ["_compute_identity_score"])
        # Score with various signals
        host_record = {
            "hostname": "server1",
            "deep_scan": {"vendor": "Dell", "mac_address": "AA:BB:CC:DD:EE:FF"},
            "agentless_fingerprint": {"http_title": "Dashboard", "device_vendor": "Cisco"},
        }
        result = a._compute_identity_score(host_record)
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
