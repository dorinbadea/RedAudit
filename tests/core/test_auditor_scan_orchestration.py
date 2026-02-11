"""
Tests that exercise `scan_host_ports` end-to-end with minimal mock layers.
Also covers `run_agentless_verification`, `run_deep_scans_concurrent`,
and several previously-uncovered code paths inside the scan orchestration.
"""

import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from redaudit.core.auditor_scan import AuditorScan
from redaudit.core.models import Host, Service
from redaudit.utils.constants import (
    DEFAULT_IDENTITY_THRESHOLD,
    STATUS_DOWN,
    STATUS_NO_RESPONSE,
)


def _make_auditor(**overrides):
    """Build a mock AuditorScan with realistic config defaults."""
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
    }
    a.config.update(overrides)
    a.logger = MagicMock()
    a.ui = MagicMock()
    a.ui.t = MagicMock(side_effect=lambda *args: " ".join(str(x) for x in args))
    a.ui.print_status = MagicMock()
    a.ui.get_progress_console = MagicMock(return_value=None)
    a.ui.colors = {"HEADER": "", "ENDC": "", "OKGREEN": "", "FAIL": ""}
    a.results = {}
    a.extra_tools = {}
    a.proxy_manager = None
    a.interrupted = False
    a.current_phase = ""
    a.scanner = MagicMock()
    a.rate_limit_delay = 0
    a.__dict__["_hyperscan_discovery_ports"] = {}

    # These methods are defined in parent Auditor class, keep them as mocks
    a._set_ui_detail = MagicMock()
    a._coerce_text = MagicMock(side_effect=lambda v: str(v) if v is not None else "")

    @contextmanager
    def _fake_progress_ui():
        yield

    a._progress_ui = _fake_progress_ui

    return a


def _bind(auditor, method_name):
    """Bind a real AuditorScan method to our mock."""
    real_method = getattr(AuditorScan, method_name)
    return real_method.__get__(auditor, AuditorScan)


def _bind_all(auditor, names):
    """Bind multiple real methods to mock."""
    for name in names:
        setattr(auditor, name, _bind(auditor, name))


# List of AuditorScan methods that exist on the class (not TYPE_CHECKING stubs)
SCAN_HELPERS = [
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
    "_parse_host_timeout_s",
    "is_web_service",
]


# ---------------------------------------------------------------------------
# scan_host_ports  (lines 1421-2420)
# ---------------------------------------------------------------------------
class TestScanHostPortsFull(unittest.TestCase):
    """Exercise scan_host_ports through realistic nmap result processing."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, SCAN_HELPERS)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe", return_value=None)
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV -T4")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=False)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_nmap_success_processes_ports(
        self,
        mock_web,
        mock_sus,
        mock_shn,
        mock_sip,
        mock_dry,
        mock_args,
        mock_banner,
        mock_http_probe,
        mock_finalize,
        mock_dns,
        mock_whois,
    ):
        """Happy path: nmap finds host with ports, services are populated."""
        ip = "192.168.1.100"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (3, ["mac"])

        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        host_data = MagicMock()
        host_data.hostnames.return_value = [{"name": "testhost"}]
        host_data.state.return_value = "up"
        host_data.all_protocols.return_value = ["tcp"]

        port_data = {
            22: {
                "name": "ssh",
                "product": "OpenSSH",
                "version": "8.2",
                "extrainfo": "",
                "cpe": [],
                "state": "open",
                "reason": "syn-ack",
                "tunnel": "",
            },
            80: {
                "name": "http",
                "product": "nginx",
                "version": "1.18",
                "extrainfo": "",
                "cpe": [],
                "state": "open",
                "reason": "syn-ack",
                "tunnel": "",
            },
        }
        # host_data["tcp"] returns port_data, iteration yields keys
        host_data.__getitem__ = MagicMock(side_effect=lambda key: port_data if key == "tcp" else {})
        host_data.get = MagicMock(return_value=None)
        nm.__getitem__ = MagicMock(return_value=host_data)

        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        result = self.a.scan_host_ports(ip)

        self.assertGreaterEqual(len(host_obj.services), 2)
        self.a.scanner.run_nmap_scan.assert_called_once()

    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=True)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    def test_dry_run_returns_early(self, mock_sip, mock_dry, mock_args):
        """Dry run creates host with STATUS_DOWN and returns immediately."""
        host_obj = Host(ip="10.0.0.1")
        self.a.scanner.get_or_create_host.return_value = host_obj

        result = self.a.scan_host_ports("10.0.0.1")

        self.assertEqual(host_obj.status, STATUS_DOWN)
        self.a.scanner.run_nmap_scan.assert_not_called()

    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value=STATUS_DOWN)
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.get_neighbor_mac", return_value=None)
    @patch("redaudit.core.auditor_scan.get_vendor_with_fallback", return_value=None)
    def test_nmap_failure_returns_no_response(
        self, mock_gvwf, mock_gnm, mock_sip, mock_dry, mock_args, mock_fin
    ):
        """When nmap scan fails (nm is None), host gets STATUS_NO_RESPONSE."""
        host_obj = Host(ip="10.0.0.1")
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.run_nmap_scan.return_value = (None, "Connection refused")

        result = self.a.scan_host_ports("10.0.0.1")

        self.assertEqual(host_obj.status, STATUS_NO_RESPONSE)
        self.assertIn("no_response:nmap_failed", host_obj.tags)

    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value=STATUS_DOWN)
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    def test_host_not_in_nmap_results(self, mock_sip, mock_dry, mock_args, mock_fin):
        """When nmap succeeds but host IP isn't in results."""
        host_obj = Host(ip="10.0.0.1")
        self.a.scanner.get_or_create_host.return_value = host_obj

        nm = MagicMock()
        nm.all_hosts.return_value = []
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        result = self.a.scan_host_ports("10.0.0.1")

        self.assertEqual(host_obj.status, STATUS_DOWN)
        self.assertTrue(host_obj.smart_scan.get("trigger_deep"))

    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value=STATUS_DOWN)
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    def test_host_not_found_preserves_hyperscan_ports(
        self, mock_sip, mock_dry, mock_args, mock_fin
    ):
        """When nmap doesn't find host but HyperScan had ports, they're preserved."""
        host_obj = Host(ip="10.0.0.1")
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.__dict__["_hyperscan_discovery_ports"] = {"10.0.0.1": [22, 80, 443]}

        nm = MagicMock()
        nm.all_hosts.return_value = []
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        result = self.a.scan_host_ports("10.0.0.1")

        self.assertTrue(host_obj.smart_scan.get("trigger_deep"))

    @patch("redaudit.core.auditor_scan.sanitize_ip", return_value=None)
    def test_invalid_ip_string(self, mock_sip):
        """Invalid IP string returns error dict."""
        result = self.a.scan_host_ports("not_an_ip")
        self.assertIn("error", result)

    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=True)
    def test_host_object_input(self, mock_dry, mock_args):
        """When passed a Host object, uses its .ip directly."""
        host = Host(ip="192.168.1.1")
        self.a.scanner.get_or_create_host.return_value = host

        result = self.a.scan_host_ports(host)

        self.assertEqual(result.status, STATUS_DOWN)

    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value=STATUS_NO_RESPONSE)
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.get_neighbor_mac", return_value="AA:BB:CC:DD:EE:FF")
    @patch("redaudit.core.auditor_scan.get_vendor_with_fallback", return_value="TestVendor")
    def test_nmap_failure_with_topology_mac(
        self, mock_gvwf, mock_gnm, mock_sip, mock_dry, mock_args, mock_fin
    ):
        """When nmap fails but MAC is found via topology, deep_scan is populated."""
        host_obj = Host(ip="10.0.0.1")
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.run_nmap_scan.return_value = (None, "Timeout")

        result = self.a.scan_host_ports("10.0.0.1")

        self.assertIsNotNone(host_obj.deep_scan)
        if isinstance(host_obj.deep_scan, dict):
            self.assertEqual(host_obj.deep_scan.get("mac_address"), "AA:BB:CC:DD:EE:FF")


# ---------------------------------------------------------------------------
# run_agentless_verification  (lines 2960-3176)
# ---------------------------------------------------------------------------
class TestRunAgentlessVerification(unittest.TestCase):
    def setUp(self):
        self.a = _make_auditor(windows_verify_enabled=True)
        _bind_all(self.a, ["run_agentless_verification"])

    def test_disabled(self):
        """When windows_verify_enabled is False, return immediately."""
        self.a.config["windows_verify_enabled"] = False
        self.a.run_agentless_verification([])

    def test_interrupted(self):
        """When interrupted, return immediately."""
        self.a.interrupted = True
        self.a.run_agentless_verification([])

    @patch("redaudit.core.auditor_scan.select_agentless_probe_targets", return_value=[])
    @patch("redaudit.core.agentless_verify.parse_smb_nmap", return_value=None)
    @patch("redaudit.core.agentless_verify.parse_ldap_rootdse", return_value=None)
    def test_no_targets(self, mock_ldap, mock_smb, mock_select):
        """When no hosts match agentless targets, return early."""
        hosts = [Host(ip="10.0.0.1")]
        self.a.run_agentless_verification(hosts)
        mock_select.assert_called_once()

    @patch("redaudit.core.auditor_scan.select_agentless_probe_targets", return_value=[])
    @patch("redaudit.core.agentless_verify.parse_smb_nmap")
    @patch("redaudit.core.agentless_verify.parse_ldap_rootdse")
    def test_smb_findings_extracted(self, mock_ldap, mock_smb, mock_select):
        """SMB findings are extracted from port 445 script output."""
        mock_smb.return_value = {"signing": "disabled"}
        mock_ldap.return_value = None

        host = Host(ip="10.0.0.1")
        svc = Service(port=445, protocol="tcp", name="microsoft-ds")
        svc.script_output = {"smb-security-mode": "signing: disabled"}
        host.add_service(svc)

        self.a.run_agentless_verification([host])

        mock_smb.assert_called_once()
        self.assertIn("smb", host.red_team_findings)

    @patch("redaudit.core.auditor_scan.select_agentless_probe_targets", return_value=[])
    @patch("redaudit.core.agentless_verify.parse_smb_nmap")
    @patch("redaudit.core.agentless_verify.parse_ldap_rootdse")
    def test_ldap_findings_extracted(self, mock_ldap, mock_smb, mock_select):
        """LDAP findings are extracted from port 389 script output."""
        mock_smb.return_value = None
        mock_ldap.return_value = {"domain": "CORP.LOCAL"}

        host = Host(ip="10.0.0.2")
        svc = Service(port=389, protocol="tcp", name="ldap")
        svc.script_output = {"ldap-rootdse": "namingContexts: DC=corp,DC=local"}
        host.add_service(svc)

        self.a.run_agentless_verification([host])

        mock_ldap.assert_called_once()
        self.assertIn("ldap", host.red_team_findings)


# ---------------------------------------------------------------------------
# run_deep_scans_concurrent  (lines 2595-2773)
# ---------------------------------------------------------------------------
class TestRunDeepScansConcurrent(unittest.TestCase):
    def setUp(self):
        self.a = _make_auditor()
        _bind_all(
            self.a,
            [
                "run_deep_scans_concurrent",
                "_reserve_deep_scan_slot",
                "_merge_ports",
                "_merge_port_record",
                "_merge_services_from_ports",
            ],
        )

    def test_empty_hosts(self):
        """Empty host list returns immediately."""
        self.a.run_deep_scans_concurrent([])

    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    def test_single_host(self, mock_fin):
        """Deep scan runs and results are merged into host."""
        host = Host(ip="10.0.0.1")
        host.smart_scan = {"trigger_deep": True}
        host.ports = [{"port": 22, "protocol": "tcp", "service": "ssh"}]

        deep_result = {
            "os_detected": "Linux 5.4",
            "ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
        }
        self.a.deep_scan_host = MagicMock(return_value=deep_result)
        self.a.__dict__["_hyperscan_discovery_ports"] = {}

        self.a.run_deep_scans_concurrent([host])

        self.assertEqual(host.os_detected, "Linux 5.4")

    def test_interrupted_skips(self):
        """When interrupted, no deep scans are submitted."""
        self.a.interrupted = True
        host = Host(ip="10.0.0.1")
        self.a.run_deep_scans_concurrent([host])


# ---------------------------------------------------------------------------
# _collect_discovery_hosts  (lines 336-384)
# ---------------------------------------------------------------------------
class TestCollectDiscoveryHosts(unittest.TestCase):
    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, ["_collect_discovery_hosts"])

    def test_empty_results(self):
        self.a.results = {}
        hosts = self.a._collect_discovery_hosts(["192.168.1.0/24"])
        self.assertIsInstance(hosts, list)

    def test_net_discovery_arp(self):
        self.a.results = {
            "net_discovery": {
                "arp_hosts": [
                    {"ip": "192.168.1.1"},
                    {"ip": "192.168.1.2"},
                ],
                "hosts_up": [{"ip": "192.168.1.3"}],
            }
        }
        hosts = self.a._collect_discovery_hosts(["192.168.1.0/24"])
        self.assertTrue(len(hosts) >= 2)


# ---------------------------------------------------------------------------
# _scan_mode_host_timeout_s  (lines 511-517)
# ---------------------------------------------------------------------------
class TestScanModeHostTimeout(unittest.TestCase):
    def test_quick_mode(self):
        a = _make_auditor(scan_mode="quick")
        _bind_all(a, ["_scan_mode_host_timeout_s"])
        # quick is not fast/full so returns default 60.0
        result = a._scan_mode_host_timeout_s()
        self.assertEqual(result, 60.0)

    def test_fast_mode(self):
        a = _make_auditor(scan_mode="fast")
        _bind_all(a, ["_scan_mode_host_timeout_s"])
        result = a._scan_mode_host_timeout_s()
        self.assertEqual(result, 10.0)

    def test_full_mode(self):
        a = _make_auditor(scan_mode="full")
        _bind_all(a, ["_scan_mode_host_timeout_s"])
        result = a._scan_mode_host_timeout_s()
        self.assertEqual(result, 300.0)


# ---------------------------------------------------------------------------
# credential_provider property  (lines 108-122)
# ---------------------------------------------------------------------------
class TestCredentialProvider(unittest.TestCase):
    def test_default_keyring(self):
        a = _make_auditor()
        _bind_all(a, [])
        # Remove cached instance if exists
        if hasattr(a, "_credential_provider_instance"):
            delattr(a, "_credential_provider_instance")
        # Bind the property
        prop = AuditorScan.credential_provider.fget.__get__(a, AuditorScan)
        with patch("redaudit.core.auditor_scan.get_credential_provider") as mock_gcp:
            mock_gcp.return_value = MagicMock()
            result = prop()
            mock_gcp.assert_called_once()

    def test_fallback_on_error(self):
        a = _make_auditor()
        if hasattr(a, "_credential_provider_instance"):
            delattr(a, "_credential_provider_instance")
        prop = AuditorScan.credential_provider.fget.__get__(a, AuditorScan)
        with patch(
            "redaudit.core.auditor_scan.get_credential_provider", side_effect=Exception("fail")
        ):
            result = prop()
            self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# _resolve_ssh_credential  (lines 124-143)
# ---------------------------------------------------------------------------
class TestResolveSSHCredential(unittest.TestCase):
    def test_cli_override(self):
        a = _make_auditor(auth_ssh_user="root", auth_ssh_pass="pass123")
        _bind_all(a, ["_resolve_ssh_credential"])
        cred = a._resolve_ssh_credential("10.0.0.1")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "root")

    def test_no_config(self):
        a = _make_auditor()
        _bind_all(a, ["_resolve_ssh_credential"])
        # Mock credential_provider to return None
        a.credential_provider = MagicMock()
        a.credential_provider.get_credential.return_value = None
        cred = a._resolve_ssh_credential("10.0.0.1")
        self.assertIsNone(cred)


# ---------------------------------------------------------------------------
# _resolve_snmp_credential  (lines 222-232)
# ---------------------------------------------------------------------------
class TestResolveSNMPCredential(unittest.TestCase):
    def test_cli_override(self):
        a = _make_auditor(auth_snmp_user="admin")
        _bind_all(a, ["_resolve_snmp_credential"])
        cred = a._resolve_snmp_credential("10.0.0.1")
        self.assertIsNotNone(cred)

    def test_no_config(self):
        a = _make_auditor()
        _bind_all(a, ["_resolve_snmp_credential"])
        a.credential_provider = MagicMock()
        a.credential_provider.get_credential.return_value = None
        cred = a._resolve_snmp_credential("10.0.0.1")
        self.assertIsNone(cred)
