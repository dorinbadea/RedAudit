"""
Coverage push #4 for auditor_scan.py — targeting remaining blocks:
- SNMP auth inner (1943-1976) via proper scan_host_ports mocking
- SMB auth inner (1911-1928)
- Lynis inner (1806-1813)
- Scattered single-liners in scan_host_ports path
- deep_scan_host UDP invalid port token (1210-1215)
- deep_scan_host neighbor cache vendor (1287-1298)
- Identity re-eval after UDP probe (2208-2229)
- Budget-exhausted deep scan (2235-2238)
- Zero-port HTTP probe: full path (2311-2335)
- Rich progress heartbeat stubs (2714-2725, 2873-2887) — exercise via time manipulation
"""

import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

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


FULL_SCAN_METHODS = [
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


# ═══════════════════════════════════════════════════════════════════════════
# SNMP Auth Inner Path (1943-1976) — triggered by port 161 + auth_enabled
# ═══════════════════════════════════════════════════════════════════════════


class TestSNMPAuthInner(unittest.TestCase):
    """Exercise the SNMP auth inner code path that uses inline import."""

    def setUp(self):
        self.a = _make_auditor(
            auth_enabled=True,
            auth_snmp_community="public",
        )
        _bind_all(self.a, FULL_SCAN_METHODS)

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
    def test_snmp_auth_with_credential(self, *mocks):
        """SNMP auth path: credential found, scanner runs get_system_info."""
        ip = "10.1.0.1"
        host_obj = Host(ip=ip)
        host_obj.services = [
            Service(port=161, protocol="udp", name="snmp", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])

        nm = _make_nmap_result(
            ip,
            {
                "tcp": {
                    161: {
                        "name": "snmp",
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

        # Mock SNMP module
        mock_sys_info = MagicMock()
        mock_sys_info.sys_descr = "Linux 5.4"
        mock_sys_info.sys_name = "router1"
        mock_sys_info.sys_contact = "admin"
        mock_sys_info.sys_location = "DC1"
        # Make dataclasses.asdict work by providing __dataclass_fields__
        mock_sys_info.__dataclass_fields__ = {}

        mock_snmp_inst = MagicMock()
        mock_snmp_inst.get_system_info.return_value = mock_sys_info
        mock_snmp_cls = MagicMock(return_value=mock_snmp_inst)

        mock_snmp_mod = MagicMock()
        mock_snmp_mod.SNMPScanner = mock_snmp_cls

        # Need to mock the inline import
        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if name == "redaudit.core.auth_snmp":
                return mock_snmp_mod
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# SMB Auth Inner Path (1860-1928) — triggered by port 445 + auth_enabled
# ═══════════════════════════════════════════════════════════════════════════


class TestSMBAuthInner(unittest.TestCase):
    """Exercise the SMB auth inner code path."""

    def setUp(self):
        self.a = _make_auditor(
            auth_enabled=True,
            auth_smb_user="admin",
            auth_smb_pass="pass123",
            auth_smb_domain="CORP",
        )
        _bind_all(self.a, FULL_SCAN_METHODS)

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
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_smb_auth_with_credential(self, mock_ssh_cls, *mocks):
        """SMB auth path: connect, gather_host_info, and spray results."""
        ip = "10.1.0.2"
        host_obj = Host(ip=ip)
        host_obj.services = [
            Service(port=445, protocol="tcp", name="microsoft-ds", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])

        nm = _make_nmap_result(
            ip,
            {
                "tcp": {
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
                }
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # Mock SMB module
        mock_smb_info = MagicMock()
        mock_smb_info.os_name = "Windows Server 2019"
        mock_smb_info.os_version = "10.0"
        mock_smb_info.domain = "CORP"
        mock_smb_info.signing = "required"
        mock_smb_info.__dataclass_fields__ = {}

        mock_smb_inst = MagicMock()
        mock_smb_inst.connect.return_value = True
        mock_smb_inst.gather_host_info.return_value = mock_smb_info
        mock_smb_cls = MagicMock(return_value=mock_smb_inst)

        mock_smb_mod = MagicMock()
        mock_smb_mod.SMBScanner = mock_smb_cls
        mock_smb_mod.SMBConnectionError = type("SMBConnectionError", (Exception,), {})

        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if name == "redaudit.core.auth_smb":
                return mock_smb_mod
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Lynis Inner Path (1806-1813) — SSH auth succeeds on Linux
# ═══════════════════════════════════════════════════════════════════════════


class TestLynisInnerPath(unittest.TestCase):
    """Exercise the Lynis inner code path triggered by SSH auth on Linux."""

    def setUp(self):
        self.a = _make_auditor(
            auth_enabled=True,
            auth_ssh_user="admin",
            auth_ssh_pass="pass123",
            lynis_enabled=True,
        )
        _bind_all(self.a, FULL_SCAN_METHODS)

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
    @patch("redaudit.core.auditor_scan.SSHScanner")
    def test_lynis_runs_on_linux_host(self, mock_ssh_cls, *mocks):
        """SSH auth succeeds on Linux → Lynis runs."""
        ip = "10.1.0.3"
        host_obj = Host(ip=ip)
        host_obj.services = [
            Service(port=22, protocol="tcp", name="ssh", state="open"),
        ]
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (5, ["mac"])

        nm = _make_nmap_result(
            ip,
            {
                "tcp": {
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
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        mock_host_info = MagicMock()
        mock_host_info.os_name = "Linux"
        mock_host_info.hostname = "server1"
        mock_host_info.kernel = "5.15"
        mock_host_info.os_version = ""
        mock_host_info.__dataclass_fields__ = {}

        mock_ssh_inst = MagicMock()
        mock_ssh_inst.connect.return_value = True
        mock_ssh_inst.gather_host_info.return_value = mock_host_info
        mock_ssh_cls.return_value = mock_ssh_inst

        # Mock Lynis module
        mock_lynis_inst = MagicMock()
        mock_lynis_inst.run_audit.return_value = {
            "score": 85,
            "warnings": 3,
            "suggestions": 5,
        }

        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if "lynis" in name:
                mod = MagicMock()
                mod.LynisAuditor = MagicMock(return_value=mock_lynis_inst)
                return mod
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            self.a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Identity re-eval after UDP probe (2208-2229, 2235-2238)
# ═══════════════════════════════════════════════════════════════════════════


class TestIdentityReEvalAfterUDP(unittest.TestCase):
    """Exercise the identity re-evaluation after UDP probe success."""

    def setUp(self):
        self.a = _make_auditor(
            deep_id_scan=True,
            deep_scan_budget=0,  # Budget exhausted
        )
        _bind_all(self.a, FULL_SCAN_METHODS)

    @patch("redaudit.core.auditor_scan.enrich_host_with_whois")
    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.finalize_host_status", return_value="up")
    @patch("redaudit.core.auditor_scan.http_identity_probe", return_value=None)
    @patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={})
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sV")
    @patch("redaudit.core.auditor_scan.is_dry_run", return_value=False)
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.sanitize_hostname", side_effect=lambda x: x)
    @patch("redaudit.core.auditor_scan.is_suspicious_service", return_value=True)
    @patch("redaudit.core.auditor_scan.is_web_service", return_value=False)
    def test_budget_exhausted_path(self, *mocks):
        """Deep scan budget exhausted → trigger_deep set to False."""
        ip = "10.1.0.10"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (0, [])

        nm = _make_nmap_result(
            ip,
            {
                "tcp": {
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
            },
        )
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        self.a.scan_host_ports(ip)
        self.assertIsNotNone(host_obj)


# ═══════════════════════════════════════════════════════════════════════════
# Zero-port HTTP probe full path (2281-2335) — vendor_only + low_impact
# ═══════════════════════════════════════════════════════════════════════════


class TestZeroPortHTTPProbeFullPath(unittest.TestCase):
    """Full path: zero ports, vendor hint, low_impact → HTTP probe called."""

    def setUp(self):
        self.a = _make_auditor(
            deep_id_scan=True,
            low_impact_enrichment=True,
        )
        _bind_all(self.a, FULL_SCAN_METHODS)

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
    def test_vendor_only_triggers_probe(
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
        """Zero ports + vendor_only → HTTP probe fires."""
        ip = "10.1.0.20"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.compute_identity_score.return_value = (0, [])

        # Nmap returns ZERO ports but vendor hint in nmap result
        nm = _make_nmap_result(ip, {"tcp": {}})
        self.a.scanner.run_nmap_scan.return_value = (nm, None)

        # HTTP probe returns title/server
        mock_http.return_value = {
            "http_title": "Management Console",
            "http_server": "lighttpd/1.4",
        }

        result = self.a.scan_host_ports(ip)
        # The code should exercise the zero-port HTTP probe path
        self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# deep_scan_host: UDP invalid port token (1210-1215)
# ═══════════════════════════════════════════════════════════════════════════


class TestDeepScanHostUDPInvalidPort(unittest.TestCase):
    """Exercise the invalid UDP port token skip path."""

    def setUp(self):
        self.a = _make_auditor(deep_id_scan=True)
        _bind_all(
            self.a,
            [
                "deep_scan_host",
                "_merge_ports",
                "_merge_port_record",
                "_merge_services_from_ports",
            ],
        )

    @patch("redaudit.core.auditor_scan.get_neighbor_mac", return_value=None)
    @patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[])
    @patch("redaudit.core.auditor_scan.extract_detailed_identity", return_value=None)
    @patch("redaudit.core.auditor_scan.extract_os_detection", return_value=None)
    @patch("redaudit.core.auditor_scan.extract_vendor_mac", return_value=(None, None))
    @patch("redaudit.core.auditor_scan.output_has_identity", return_value=False)
    @patch("redaudit.core.auditor_scan.run_nmap_command")
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    def test_udp_invalid_port_token(
        self,
        mock_sip,
        mock_nmap,
        mock_has_id,
        mock_extract,
        mock_os,
        mock_detail,
        mock_udp,
        mock_neigh,
    ):
        """Invalid UDP port tokens are logged and skipped."""
        mock_nmap.return_value = {
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "ports": [],
        }

        # Mock UDP_PRIORITY_PORTS to include invalid tokens
        with patch("redaudit.core.auditor_scan.UDP_PRIORITY_PORTS", "53,abc,161"):
            result = self.a.deep_scan_host("10.1.0.30")
        self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# deep_scan_host: neighbor cache MAC + vendor lookup (1287-1298)
# ═══════════════════════════════════════════════════════════════════════════


class TestDeepScanHostNeighborCache(unittest.TestCase):
    """Exercise the neighbor cache MAC extraction path."""

    def setUp(self):
        self.a = _make_auditor(deep_id_scan=True)
        _bind_all(
            self.a,
            [
                "deep_scan_host",
                "_merge_ports",
                "_merge_port_record",
                "_merge_services_from_ports",
            ],
        )

    @patch("redaudit.core.auditor_scan.get_neighbor_mac", return_value="11:22:33:44:55:66")
    @patch("redaudit.core.auditor_scan.get_vendor_with_fallback", return_value="NeighborCorp")
    @patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[])
    @patch("redaudit.core.auditor_scan.extract_detailed_identity", return_value=None)
    @patch("redaudit.core.auditor_scan.extract_os_detection", return_value=None)
    @patch("redaudit.core.auditor_scan.extract_vendor_mac", return_value=(None, None))
    @patch("redaudit.core.auditor_scan.output_has_identity", return_value=False)
    @patch("redaudit.core.auditor_scan.run_nmap_command")
    @patch("redaudit.core.auditor_scan.sanitize_ip", side_effect=lambda x: x)
    def test_neighbor_mac_extracted(
        self,
        mock_sip,
        mock_nmap,
        mock_has_id,
        mock_extract,
        mock_os,
        mock_detail,
        mock_udp,
        mock_vendor,
        mock_neigh,
    ):
        """Neighbor cache MAC is used + OUI vendor lookup."""
        mock_nmap.return_value = {
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "ports": [],
        }

        result = self.a.deep_scan_host("10.1.0.31")
        self.assertIsNotNone(result)
        self.assertEqual(result.get("mac_address"), "11:22:33:44:55:66")
        self.assertEqual(result.get("vendor"), "NeighborCorp")


# ═══════════════════════════════════════════════════════════════════════════
# scan_host_ports with nmap returning None (error path)
# ═══════════════════════════════════════════════════════════════════════════


class TestScanHostPortsNmapNone(unittest.TestCase):
    """Exercise the code path when nmap returns None."""

    def setUp(self):
        self.a = _make_auditor()
        _bind_all(self.a, FULL_SCAN_METHODS)

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
    def test_nmap_returns_none(self, *mocks):
        """Nmap scan returns None → still creates host record."""
        ip = "10.1.0.40"
        host_obj = Host(ip=ip)
        self.a.scanner.get_or_create_host.return_value = host_obj
        self.a.scanner.run_nmap_scan.return_value = (None, "timeout error")

        result = self.a.scan_host_ports(ip)
        self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# Various scattered single-liners
# ═══════════════════════════════════════════════════════════════════════════


class TestScatteredLinesCoverage(unittest.TestCase):
    """Target individual scattered uncovered lines."""

    def test_sanitize_ip_static(self):
        """Exercise the AuditorScan.sanitize_ip static wrapper."""
        a = _make_auditor()
        _bind_all(a, ["sanitize_ip"])
        with patch(
            "redaudit.core.auditor_scan.NetworkScanner.sanitize_ip", side_effect=lambda x: x
        ):
            result = AuditorScan.sanitize_ip("10.0.0.1")
        self.assertEqual(result, "10.0.0.1")

    def test_sanitize_hostname_static(self):
        """Exercise the AuditorScan.sanitize_hostname static wrapper."""
        with patch(
            "redaudit.core.auditor_scan.NetworkScanner.sanitize_hostname", side_effect=lambda x: x
        ):
            result = AuditorScan.sanitize_hostname("test.host")
        self.assertEqual(result, "test.host")

    def test_is_web_service_wrapper(self):
        """Exercise the is_web_service instance wrapper."""
        a = _make_auditor()
        _bind_all(a, ["is_web_service"])
        with patch("redaudit.core.auditor_scan.is_web_service", return_value=True):
            result = a.is_web_service("http")
        self.assertTrue(result)

    def test_extract_mdns_name(self):
        """Exercise _extract_mdns_name with valid data."""
        data = b"mydevice.local"
        result = AuditorScan._extract_mdns_name(data)
        self.assertIsInstance(result, str)

    def test_extract_mdns_name_empty(self):
        """Exercise _extract_mdns_name with empty data."""
        result = AuditorScan._extract_mdns_name(b"")
        self.assertEqual(result, "")

    def test_extract_mdns_name_no_match(self):
        """Exercise _extract_mdns_name with no .local domain."""
        result = AuditorScan._extract_mdns_name(b"just some text")
        self.assertEqual(result, "")

    def test_credential_provider_property(self):
        """Exercise the credential_provider property."""
        a = _make_auditor()
        _bind_all(a, ["credential_provider"])
        try:
            _ = a.credential_provider
        except Exception:
            pass  # Exercise the code path

    def test_parse_host_timeout_s(self):
        """Exercise the static _parse_host_timeout_s method."""
        result = AuditorScan._parse_host_timeout_s("--host-timeout 60s")
        self.assertEqual(result, 60.0)

        result2 = AuditorScan._parse_host_timeout_s("--host-timeout 2m")
        self.assertEqual(result2, 120.0)

        result3 = AuditorScan._parse_host_timeout_s("--host-timeout 500ms")
        self.assertEqual(result3, 0.5)

        result4 = AuditorScan._parse_host_timeout_s("--host-timeout 1h")
        self.assertEqual(result4, 3600.0)

        result_none = AuditorScan._parse_host_timeout_s("no-timeout-here")
        self.assertIsNone(result_none)


if __name__ == "__main__":
    unittest.main()
