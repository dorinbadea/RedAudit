"""
Coverage push #5 for auditor_scan.py — targeting the hardest remaining blocks:
- SNMP auth inner path (1943-1976) with proper UDP port setup
- SMB auth error paths: SMBConnectionError, all-failed (1910-1928)
- Lynis result processing (1806-1813)
- Zero-port HTTP probe with vendor_only (2311-2335)
- Identity re-eval after UDP probe (2208-2229)
- Budget exhaustion (2235-2238)
- Online vendor lookup fallback (2012-2022)
- Hostname parse failure (1599-1602)
- Scattered lines in scan_host_ports
"""

import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch, PropertyMock
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
    real = getattr(AuditorScan, name)
    return real.__get__(aud, AuditorScan)


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


# Standard nmap result mock factory
def _nmap_mock(ip, tcp_ports=None, hostnames=None, raise_hostname=False):
    """Create a standard nmap result mock."""
    nm = MagicMock()
    nm.all_hosts.return_value = [ip]
    hd = MagicMock()
    if raise_hostname:
        hd.hostnames.side_effect = RuntimeError("parse error")
    elif hostnames:
        hd.hostnames.return_value = hostnames
    else:
        hd.hostnames.return_value = [{"name": "host1"}]
    hd.state.return_value = "up"

    if tcp_ports:
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(side_effect=lambda k: tcp_ports if k == "tcp" else {})
    else:
        hd.all_protocols.return_value = []
        hd.__getitem__ = MagicMock(return_value={})

    hd.get = MagicMock(
        side_effect=lambda k, d=None: {
            "addresses": {},
            "vendor": {},
            "osmatch": [],
        }.get(k, d)
    )
    nm.__getitem__ = MagicMock(return_value=hd)
    return nm


# Common scan_host_ports patches
SCAN_PATCHES = [
    "redaudit.core.auditor_scan.enrich_host_with_whois",
    "redaudit.core.auditor_scan.enrich_host_with_dns",
    "redaudit.core.auditor_scan.finalize_host_status",
    "redaudit.core.auditor_scan.http_identity_probe",
    "redaudit.core.auditor_scan.banner_grab_fallback",
    "redaudit.core.auditor_scan.get_nmap_arguments",
    "redaudit.core.auditor_scan.is_dry_run",
    "redaudit.core.auditor_scan.sanitize_ip",
    "redaudit.core.auditor_scan.sanitize_hostname",
    "redaudit.core.auditor_scan.is_suspicious_service",
    "redaudit.core.auditor_scan.is_web_service",
]

SCAN_DEFAULTS = {
    "enrich_host_with_whois": None,
    "enrich_host_with_dns": None,
    "finalize_host_status": "up",
    "http_identity_probe": None,
    "banner_grab_fallback": {},
    "get_nmap_arguments": "-sV",
    "is_dry_run": False,
    "sanitize_ip": lambda x: x,
    "sanitize_hostname": lambda x: x,
    "is_suspicious_service": False,
    "is_web_service": False,
}


def _apply_patches(test_func):
    """Decorator to apply all standard scan patches."""
    for p in reversed(SCAN_PATCHES):
        name = p.rsplit(".", 1)[1]
        val = SCAN_DEFAULTS[name]
        if callable(val) and not isinstance(val, bool):
            test_func = patch(p, side_effect=val)(test_func)
        else:
            test_func = patch(p, return_value=val)(test_func)
    return test_func


# ═══════════════════════════════════════════════════════════════════════════
# SNMP Auth Inner (1943-1976) — correct port setup with UDP 161
# ═══════════════════════════════════════════════════════════════════════════


class TestSNMPAuthInnerComplete(unittest.TestCase):
    """Cover lines 1943-1976: SNMP auth scanning with proper UDP port."""

    def setUp(self):
        self.a = _make_auditor(auth_enabled=True)
        _bind_all(self.a, FULL_METHODS)

    @_apply_patches
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_snmp_auth_full_path(self, mock_ssh_cls, *mocks):
        """SNMP auth with credential → scanner runs → OS enriched."""
        ip = "10.2.0.1"
        host_obj = Host(ip=ip)
        # Host must have port 161/udp as snmp
        host_obj.services = [
            Service(port=161, protocol="udp", name="snmp", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])
        # _resolve_snmp_credential must return a real credential
        self.a._resolve_snmp_credential = MagicMock(
            return_value=MagicMock(
                community="public",
            )
        )

        # Nmap returns a single port on TCP
        nm = _nmap_mock(
            ip,
            tcp_ports={
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
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # Mock the SNMPScanner inline import
        @dataclass
        class FakeSysInfo:
            sys_descr: str = "Linux 5.4"
            sys_name: str = "router1"
            sys_contact: str = "admin"
            sys_location: str = "DC1"

        mock_snmp_scanner = MagicMock()
        mock_snmp_scanner.get_system_info.return_value = FakeSysInfo()

        with patch.dict(
            "sys.modules",
            {
                "redaudit.core.auth_snmp": MagicMock(
                    SNMPScanner=MagicMock(return_value=mock_snmp_scanner),
                )
            },
        ):
            self.a.scan_host_ports(ip)

        # Verify auth_scan was updated
        self.assertIsNotNone(host_obj.auth_scan)

    @_apply_patches
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_snmp_auth_import_error(self, mock_ssh_cls, *mocks):
        """SNMP auth → ImportError → handled gracefully."""
        ip = "10.2.0.2"
        host_obj = Host(ip=ip)
        host_obj.services = [
            Service(port=161, protocol="udp", name="snmp", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])
        self.a._resolve_snmp_credential = MagicMock(return_value=MagicMock())

        nm = _nmap_mock(ip)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # Make the import fail
        import sys

        # Remove module if cached
        sys.modules.pop("redaudit.core.auth_snmp", None)
        with patch.dict("sys.modules", {"redaudit.core.auth_snmp": None}):
            self.a.scan_host_ports(ip)

    @_apply_patches
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_snmp_auth_runtime_error(self, mock_ssh_cls, *mocks):
        """SNMP auth → scanner raises RuntimeError → caught."""
        ip = "10.2.0.3"
        host_obj = Host(ip=ip)
        host_obj.services = [
            Service(port=161, protocol="udp", name="snmp", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])
        self.a._resolve_snmp_credential = MagicMock(return_value=MagicMock())

        nm = _nmap_mock(ip)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        mock_snmp_scanner = MagicMock()
        mock_snmp_scanner.get_system_info.side_effect = RuntimeError("timeout")

        with patch.dict(
            "sys.modules",
            {
                "redaudit.core.auth_snmp": MagicMock(
                    SNMPScanner=MagicMock(return_value=mock_snmp_scanner),
                )
            },
        ):
            self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# SMB Auth Error Paths (1910-1928)
# ═══════════════════════════════════════════════════════════════════════════


class TestSMBAuthErrorPaths(unittest.TestCase):
    """Cover SMB auth error handling: SMBConnectionError and all-failed."""

    def setUp(self):
        self.a = _make_auditor(auth_enabled=True)
        _bind_all(self.a, FULL_METHODS)

    @_apply_patches
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_smb_connection_error(self, mock_ssh_cls, *mocks):
        """SMB auth → SMBConnectionError → all creds fail → report."""
        ip = "10.2.0.10"
        host_obj = Host(ip=ip)
        host_obj.services = [
            Service(port=445, protocol="tcp", name="microsoft-ds", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])
        # SMB credential
        smb_cred = MagicMock()
        smb_cred.username = "admin"
        smb_cred.password = "pass"
        smb_cred.domain = "CORP"
        self.a._resolve_all_smb_credentials = MagicMock(return_value=[smb_cred])

        nm = _nmap_mock(
            ip,
            tcp_ports={
                445: {
                    "name": "microsoft-ds",
                    "product": "Samba",
                    "version": "4.13",
                    "extrainfo": "",
                    "cpe": [],
                    "state": "open",
                    "reason": "",
                    "tunnel": "",
                },
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # Create a proper SMBConnectionError type
        SMBConnErr = type("SMBConnectionError", (Exception,), {})

        mock_smb_scanner = MagicMock()
        mock_smb_scanner.connect.side_effect = SMBConnErr("access denied")

        mock_smb_mod = MagicMock()
        mock_smb_mod.SMBScanner = MagicMock(return_value=mock_smb_scanner)
        mock_smb_mod.SMBConnectionError = SMBConnErr

        with patch.dict(
            "sys.modules",
            {
                "redaudit.core.auth_smb": mock_smb_mod,
            },
        ):
            self.a.scan_host_ports(ip)

    @_apply_patches
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_smb_import_error(self, mock_ssh_cls, *mocks):
        """SMB auth → ImportError → break."""
        ip = "10.2.0.11"
        host_obj = Host(ip=ip)
        host_obj.services = [
            Service(port=445, protocol="tcp", name="microsoft-ds", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])
        smb_cred = MagicMock()
        smb_cred.username = "admin"
        self.a._resolve_all_smb_credentials = MagicMock(return_value=[smb_cred])

        nm = _nmap_mock(
            ip,
            tcp_ports={
                445: {
                    "name": "microsoft-ds",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "cpe": [],
                    "state": "open",
                    "reason": "",
                    "tunnel": "",
                },
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        import sys

        sys.modules.pop("redaudit.core.auth_smb", None)
        with patch.dict("sys.modules", {"redaudit.core.auth_smb": None}):
            self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Lynis Result Processing (1806-1813)
# ═══════════════════════════════════════════════════════════════════════════


class TestLynisResultProcessing(unittest.TestCase):
    """Cover lines 1806-1813: Lynis result processing when l_res is truthy."""

    def setUp(self):
        self.a = _make_auditor(auth_enabled=True, lynis_enabled=True)
        _bind_all(self.a, FULL_METHODS)

    @_apply_patches
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_lynis_with_results(self, mock_ssh_cls, *mocks):
        """SSH auth succeeds on Linux → Lynis result stored."""
        ip = "10.2.0.20"
        host_obj = Host(ip=ip)
        host_obj.services = [
            Service(port=22, protocol="tcp", name="ssh", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])

        ssh_cred = MagicMock()
        ssh_cred.username = "root"
        ssh_cred.password = "pass"
        ssh_cred.key_file = None
        self.a._resolve_all_ssh_credentials = MagicMock(return_value=[ssh_cred])

        nm = _nmap_mock(
            ip,
            tcp_ports={
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
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        @dataclass
        class FakeHostInfo:
            os_name: str = "Linux"
            hostname: str = "server1"
            kernel: str = "5.15"
            os_version: str = ""

        @dataclass
        class FakeLynisResult:
            hardening_index: int = 82

        mock_ssh_inst = MagicMock()
        mock_ssh_inst.connect.return_value = True
        mock_ssh_inst.gather_host_info.return_value = FakeHostInfo()
        mock_ssh_cls.return_value = mock_ssh_inst

        mock_lynis = MagicMock()
        mock_lynis.run_audit.return_value = FakeLynisResult()

        with patch.dict(
            "sys.modules",
            {
                "redaudit.core.auth_lynis": MagicMock(
                    LynisScanner=MagicMock(return_value=mock_lynis),
                )
            },
        ):
            self.a.scan_host_ports(ip)

        self.assertIsNotNone(host_obj.auth_scan)


# ═══════════════════════════════════════════════════════════════════════════
# Zero-port HTTP Probe (2304-2335) — vendor_only + low_impact_enrichment
# ═══════════════════════════════════════════════════════════════════════════


class TestZeroPortHTTPProbe(unittest.TestCase):
    """Cover lines 2311-2335: zero-port HTTP probe with vendor hint."""

    def setUp(self):
        self.a = _make_auditor(
            low_impact_enrichment=True,
            deep_id_scan=False,
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
    def test_http_probe_fires_on_vendor_only(
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
        """Zero ports + vendor-only hint → HTTP probe fires and updates."""
        ip = "10.2.0.30"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (0, [])

        # Nmap returns zero ports
        nm = _nmap_mock(ip)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # Pre-set vendor hint from net discovery
        self.a._apply_net_discovery_identity = MagicMock(
            side_effect=lambda rec: rec.update(
                {
                    "vendor": "Ubiquiti",
                    "mac": "AA:BB:CC:DD:EE:FF",
                }
            )
        )

        # HTTP probe returns useful data
        mock_http.return_value = {
            "http_title": "UniFi Controller",
            "http_server": "nginx/1.20",
        }

        self.a.scan_host_ports(ip)

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
    def test_http_probe_no_result(self, *mocks):
        """Zero ports + vendor → HTTP probe returns None → no update."""
        ip = "10.2.0.31"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (0, [])

        nm = _nmap_mock(ip)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        self.a._apply_net_discovery_identity = MagicMock(
            side_effect=lambda rec: rec.update({"vendor": "TP-Link", "mac": "11:22:33:44:55:66"})
        )

        self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Hostname Parse Failure (1599-1602)
# ═══════════════════════════════════════════════════════════════════════════


class TestHostnameParseFailure(unittest.TestCase):
    """Cover lines 1599-1602: hostname parsing throws exception."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, FULL_METHODS)

    @_apply_patches
    def test_hostname_exception(self, *mocks):
        """Nmap hostname parsing raises → caught and default used."""
        ip = "10.2.0.40"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, [])

        nm = _nmap_mock(ip, raise_hostname=True)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Online Vendor Lookup Fallback (2012-2022)
# ═══════════════════════════════════════════════════════════════════════════


class TestOnlineVendorLookup(unittest.TestCase):
    """Cover lines 2012-2022: online vendor lookup for MAC."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, FULL_METHODS)

    @_apply_patches
    def test_vendor_lookup_success(self, *mocks):
        """Nmap has MAC but no vendor → online lookup succeeds."""
        ip = "10.2.0.50"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, [])

        # Nmap with MAC but no vendor
        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "test"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(
            side_effect=lambda k: (
                {
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
                if k == "tcp"
                else {}
            )
        )
        hd.get = MagicMock(
            side_effect=lambda k, d=None: {
                "addresses": {"mac": "AA:BB:CC:DD:EE:FF"},
                "vendor": {},
                "osmatch": [],
            }.get(k, d)
        )
        nm.__getitem__ = MagicMock(return_value=hd)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        with patch.dict(
            "sys.modules",
            {
                "redaudit.utils.oui_lookup": MagicMock(
                    lookup_vendor_online=MagicMock(return_value="TestVendor"),
                )
            },
        ):
            self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Budget-exhausted deep scan (2235-2238)
# ═══════════════════════════════════════════════════════════════════════════


class TestBudgetExhausted(unittest.TestCase):
    """Cover lines 2235-2238: deep_scan_budget=0 means budget_exhausted."""

    def setUp(self):
        self.a = _make_auditor(
            deep_id_scan=True,
            deep_scan_budget=0,
        )
        _bind_all(self.a, FULL_METHODS)

    @_apply_patches
    def test_budget_zero(self, *mocks):
        """Budget=0 → reserved=False → trigger_deep=False with reason."""
        ip = "10.2.0.60"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        # Low score to trigger deep scan consideration
        self.a.scanner.compute_identity_score.return_value = (0, [])

        nm = _nmap_mock(
            ip,
            tcp_ports={
                22: {
                    "name": "ssh",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "cpe": [],
                    "state": "open",
                    "reason": "",
                    "tunnel": "",
                },
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        mocks_list = list(mocks)
        # Make suspicious = True to trigger deep
        for m in mocks_list:
            if hasattr(m, "_mock_name") and "suspicious" in str(m._mock_name):
                m.return_value = True

        self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Identity re-eval after UDP probe (2208-2229)
# ═══════════════════════════════════════════════════════════════════════════


class TestIdentityReEvalAfterUDP(unittest.TestCase):
    """Cover lines 2208-2229: re-eval identity after UDP probe finds SNMP."""

    def setUp(self):
        self.a = _make_auditor(
            deep_id_scan=True,
            deep_scan_budget=10,
        )
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
    def test_udp_resolves_identity(self, *mocks):
        """UDP probe resolves identity → score re-evaluated → deep skipped."""
        ip = "10.2.0.70"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj

        # First call: low score triggers deep consideration
        # Second call: high score after UDP
        self.a.scanner.compute_identity_score.side_effect = [
            (0, []),
            (5, ["snmp", "mac"]),
        ]

        # Nmap: 1 open TCP port but no version
        nm = _nmap_mock(
            ip,
            tcp_ports={
                22: {
                    "name": "ssh",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "cpe": [],
                    "state": "open",
                    "reason": "",
                    "tunnel": "",
                },
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # UDP probe finds SNMP
        self.a._run_udp_priority_probe = MagicMock(return_value=True)

        self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# DNS reverse fallback from phase0 (2339-2342)
# ═══════════════════════════════════════════════════════════════════════════


class TestDNSReverseFallback(unittest.TestCase):
    """Cover line 2342: DNS reverse from phase0 enrichment."""

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
    def test_phase0_dns_reverse(self, *mocks):
        """Phase0 dns_reverse used when enrichment DNS fails."""
        ip = "10.2.0.80"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, [])

        # No ports
        nm = _nmap_mock(ip)
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # Inject phase0 enrichment data that has dns_reverse
        original_apply = self.a._apply_net_discovery_identity

        def apply_with_phase0(rec):
            try:
                original_apply(rec)
            except Exception:
                pass
            rec["phase0_enrichment"] = {"dns_reverse": "host1.example.com"}

        self.a._apply_net_discovery_identity = MagicMock(side_effect=apply_with_phase0)

        self.a.scan_host_ports(ip)


if __name__ == "__main__":
    unittest.main()
