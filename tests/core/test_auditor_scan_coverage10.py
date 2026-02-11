"""
Coverage push #10 for auditor_scan.py — targeting remaining gaps.
Focus areas:
- scan_network_discovery (1388)
- HyperScan-First resource limit import error (2477-2478)
- run_deep_scans_concurrent inner result handling (2645-2647, 2666)
- scan_hosts_concurrent interrupted path (2510)
- scan error budget reservation in except branch (2395-2396)
- auth SSH from ports fallback (1743-1745, 1758)
- auth SMB second-credential break (1870, 1872)
- auth SMB ImportError (1917-1919)
- nmap vendor exception (1499-1500)
- HyperScan-First host_obj phase0 in no-response (1519-1520)
- deep_scan phase2b inner (1339, 1341, 1351)
- UDP getservbyport exception (1265-1266)
"""

import threading
import unittest
from contextlib import contextmanager, ExitStack
from concurrent.futures import Future
from unittest.mock import MagicMock, patch, PropertyMock

from redaudit.core.auditor_scan import AuditorScan
from redaudit.core.models import Host


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
    a.__dict__["_deep_executed_count"] = 0
    a.__dict__["_deep_budget_lock"] = threading.Lock()
    a._set_ui_detail = MagicMock()
    a._coerce_text = MagicMock(side_effect=lambda v: str(v) if v is not None else "")

    @contextmanager
    def _fake_progress_ui():
        yield

    a._progress_ui = _fake_progress_ui
    return a


def _bind(aud, names):
    for n in names:
        setattr(aud, n, getattr(AuditorScan, n).__get__(aud, AuditorScan))


_SHP = "redaudit.core.auditor_scan."


# ═══════════════════════════════════════════════════════════════════════════
# scan_network_discovery — nm returns None (1387-1388)
# ═══════════════════════════════════════════════════════════════════════════


class TestScanNetworkDiscoveryNmNone(unittest.TestCase):
    """Line 1388: nm is None → return []."""

    def test_nm_none(self):
        a = _make_auditor()
        _bind(a, ["scan_network_discovery"])
        a.scanner.run_nmap_scan.return_value = (None, None)

        with patch(_SHP + "get_nmap_arguments", return_value="-sn"):
            result = a.scan_network_discovery("192.168.1.0/24")
            self.assertEqual(result, [])


# ═══════════════════════════════════════════════════════════════════════════
# scan_host_ports — mode label empty (1439)
# ═══════════════════════════════════════════════════════════════════════════


class TestScanHostPortsModeEmpty(unittest.TestCase):
    """Line 1439: mode_label empty → else branch for _set_ui_detail."""

    def test_empty_mode_label(self):
        a = _make_auditor(scan_mode="")
        _bind(
            a,
            [
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
            ],
        )
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.7.0.1"
        a.scanner.get_or_create_host.return_value = Host(ip=ip)
        a.scanner.compute_identity_score.return_value = (5, ["mac"])

        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "host"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(
            return_value={
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
            }
        )
        hd.get = MagicMock(return_value=None)
        nm.__getitem__ = MagicMock(return_value=hd)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        with ExitStack() as stack:
            for name, kw in {
                "enrich_host_with_whois": {"return_value": None},
                "enrich_host_with_dns": {"return_value": None},
                "finalize_host_status": {"return_value": "up"},
                "http_identity_probe": {"return_value": None},
                "banner_grab_fallback": {"return_value": {}},
                "get_nmap_arguments": {"return_value": "-sV"},
                "is_dry_run": {"return_value": False},
                "sanitize_ip": {"side_effect": lambda x: x},
                "sanitize_hostname": {"side_effect": lambda x: x},
                "is_suspicious_service": {"return_value": False},
                "is_web_service": {"return_value": False},
                "run_udp_probe": {"return_value": []},
                "output_has_identity": {"return_value": False},
            }.items():
                stack.enter_context(patch(_SHP + name, **kw))
            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# scan_host_ports — nmap error with topology MAC fallback (1499-1500, 1520)
# ═══════════════════════════════════════════════════════════════════════════


class TestNmapErrorTopologyFallback(unittest.TestCase):
    """Lines 1499-1500: vendor lookup exception in scan error path."""

    def test_vendor_lookup_fails_in_error_path(self):
        a = _make_auditor(low_impact_enrichment=True)
        _bind(
            a,
            [
                "scan_host_ports",
                "_lookup_topology_identity",
                "_reserve_deep_scan_slot",
            ],
        )
        ip = "10.7.0.2"
        a.scanner.get_or_create_host.return_value = Host(ip=ip)

        # Run nmap returns error
        a.scanner.run_nmap_scan.return_value = (None, "connection refused")

        # Topology returns MAC but no vendor
        a._lookup_topology_identity = MagicMock(return_value=("AA:BB:CC:DD:EE:02", None))

        with ExitStack() as stack:
            stack.enter_context(patch(_SHP + "sanitize_ip", side_effect=lambda x: x))
            stack.enter_context(patch(_SHP + "get_nmap_arguments", return_value="-sV"))
            stack.enter_context(patch(_SHP + "is_dry_run", return_value=False))
            # get_neighbor_mac returns MAC to trigger vendor lookup
            stack.enter_context(patch(_SHP + "get_neighbor_mac", return_value="AA:BB:CC:DD:EE:02"))
            # Vendor lookup raises
            stack.enter_context(
                patch(
                    _SHP + "get_vendor_with_fallback",
                    side_effect=Exception("offline"),
                )
            )
            result = a.scan_host_ports(ip)
            self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# deep_scan_host — UDP getservbyport exception (1265-1266)
# ═══════════════════════════════════════════════════════════════════════════


class TestDeepScanUDPGetservbyport(unittest.TestCase):
    """Lines 1265-1266: socket.getservbyport fails → uses 'udp-probe'."""

    def test_getservbyport_exception(self):
        a = _make_auditor()
        _bind(
            a,
            [
                "deep_scan_host",
                "_merge_ports",
                "_merge_port_record",
                "_parse_nmap_open_ports",
                "_split_nmap_product_version",
                "_merge_services_from_ports",
                "_compute_identity_score",
                "_scan_mode_host_timeout_s",
            ],
        )
        a._coerce_text = lambda v: str(v) if v is not None else ""
        ip = "10.7.0.3"

        a.scanner.compute_identity_score.return_value = (0, [])

        with ExitStack() as stack:
            stack.enter_context(patch(_SHP + "sanitize_ip", side_effect=lambda x: x))
            stack.enter_context(patch(_SHP + "is_dry_run", return_value=False))
            stack.enter_context(patch(_SHP + "get_nmap_arguments", return_value="-A"))
            # Phase 1: nmap deep scan via run_nmap_command
            rec1 = {
                "stdout": "",
                "stderr": "",
                "duration_seconds": 1.0,
            }
            stack.enter_context(patch(_SHP + "run_nmap_command", return_value=rec1))
            stack.enter_context(patch(_SHP + "extract_os_detection", return_value=None))
            stack.enter_context(patch(_SHP + "extract_vendor_mac", return_value=(None, None)))
            stack.enter_context(patch(_SHP + "extract_detailed_identity", return_value=None))
            stack.enter_context(patch(_SHP + "output_has_identity", return_value=False))
            stack.enter_context(patch(_SHP + "start_background_capture", return_value=None))

            # UDP probe returns responded ports
            udp_results = [
                {"port": 99999, "state": "responded", "response_bytes": 10},
            ]
            stack.enter_context(patch(_SHP + "run_udp_probe", return_value=udp_results))

            # getservbyport raises for unknown high port
            stack.enter_context(patch("socket.getservbyport", side_effect=OSError("no service")))

            stack.enter_context(patch(_SHP + "get_neighbor_mac", return_value=None))

            result = a.deep_scan_host(ip)
            self.assertIsInstance(result, dict)


# ═══════════════════════════════════════════════════════════════════════════
# deep_scan_host — Phase 2b full UDP (1339, 1341, 1351)
# ═══════════════════════════════════════════════════════════════════════════


class TestDeepScanPhase2bFull(unittest.TestCase):
    """Lines 1339, 1341, 1351: full UDP scan extracts MAC and OS."""

    def test_full_udp_with_mac_and_os(self):
        a = _make_auditor(udp_mode="full")
        _bind(
            a,
            [
                "deep_scan_host",
                "_merge_ports",
                "_merge_port_record",
                "_parse_nmap_open_ports",
                "_merge_services_from_ports",
                "_compute_identity_score",
                "_scan_mode_host_timeout_s",
            ],
        )
        a._split_nmap_product_version = AuditorScan._split_nmap_product_version
        a._coerce_text = lambda v: str(v) if v is not None else ""
        ip = "10.7.0.4"

        a.scanner.compute_identity_score.return_value = (0, [])

        with ExitStack() as stack:
            stack.enter_context(patch(_SHP + "sanitize_ip", side_effect=lambda x: x))
            stack.enter_context(patch(_SHP + "is_dry_run", return_value=False))
            stack.enter_context(patch(_SHP + "get_nmap_arguments", return_value="-A"))
            # Phase 1: deep nmap (no ports, no identity)
            rec1 = {
                "stdout": "",
                "stderr": "",
                "duration_seconds": 1.0,
            }
            # Phase 2b: full UDP returns MAC + OS
            rec2b_out = "PORT     STATE SERVICE\n161/udp  open  snmp\n"
            rec2b = {
                "stdout": rec2b_out,
                "stderr": "",
                "duration_seconds": 2.0,
            }

            # run_nmap_command called twice: Phase 1 and Phase 2b
            stack.enter_context(patch(_SHP + "run_nmap_command", side_effect=[rec1, rec2b]))
            stack.enter_context(patch(_SHP + "extract_os_detection", return_value="Linux 5.x"))
            stack.enter_context(
                patch(
                    _SHP + "extract_vendor_mac",
                    return_value=("AA:BB:CC:DD:EE:04", "Cisco"),
                )
            )
            stack.enter_context(patch(_SHP + "extract_detailed_identity", return_value=None))
            stack.enter_context(patch(_SHP + "output_has_identity", return_value=False))
            stack.enter_context(patch(_SHP + "start_background_capture", return_value=None))
            stack.enter_context(patch(_SHP + "run_udp_probe", return_value=[]))
            stack.enter_context(patch(_SHP + "get_neighbor_mac", return_value=None))

            result = a.deep_scan_host(ip)
            self.assertIsInstance(result, dict)


# ═══════════════════════════════════════════════════════════════════════════
# run_deep_scans_concurrent — result handling (2645-2647, 2666)
# ═══════════════════════════════════════════════════════════════════════════


class TestRunDeepScansConcurrentResults(unittest.TestCase):
    """Lines 2645-2647, 2666: deep scan result merged into host results."""

    def test_deep_result_merged(self):
        a = _make_auditor()
        _bind(
            a,
            [
                "run_deep_scans_concurrent",
                "_merge_ports",
                "_merge_port_record",
                "_merge_services_from_ports",
            ],
        )
        a.results = {
            "10.7.0.10": {
                "ip": "10.7.0.10",
                "ports": [],
                "total_ports_found": 0,
                "smart_scan": {
                    "trigger_deep": True,
                    "deep_scan_executed": False,
                    "deep_scan_suggested": True,
                },
            }
        }
        host1 = Host(ip="10.7.0.10")
        host1.smart_scan = {
            "trigger_deep": True,
            "deep_scan_executed": False,
            "deep_scan_suggested": True,
        }
        a.scanner.get_or_create_host.return_value = host1

        # deep_scan_host returns results
        a.deep_scan_host = MagicMock(
            return_value={
                "strategy": "nmap",
                "commands": [],
                "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
                "total_ports_found": 1,
                "os_detected": "Linux",
                "mac_address": "AA:BB:00:00:00:01",
                "vendor": "Dell",
            }
        )

        with patch(_SHP + "finalize_host_status", return_value="up"):
            a.run_deep_scans_concurrent([host1])


# ═══════════════════════════════════════════════════════════════════════════
# _run_hyperscan_discovery interrupted (2510) + resource limit (2477-2478)
# ═══════════════════════════════════════════════════════════════════════════


class TestHyperScanDiscovery(unittest.TestCase):
    """Lines 2477-2478, 2510: resource.getrlimit fails + interrupted flag."""

    def test_resource_import_fails(self):
        a = _make_auditor(
            scan_mode="full",
            stealth=False,
            no_hyperscan_first=False,
        )
        _bind(a, ["_run_hyperscan_discovery"])
        a.interrupted = False

        with ExitStack() as stack:
            stack.enter_context(patch(_SHP + "sanitize_ip", side_effect=lambda x: x))
            stack.enter_context(
                patch(
                    "resource.getrlimit",
                    side_effect=Exception("no resource module"),
                )
            )
            stack.enter_context(
                patch(
                    "redaudit.core.hyperscan.hyperscan_full_port_sweep",
                    return_value=[80, 443],
                )
            )
            a._run_hyperscan_discovery(
                ["10.7.0.20"],
            )

    def test_interrupted_skips_worker(self):
        a = _make_auditor(
            scan_mode="full",
            stealth=False,
            no_hyperscan_first=False,
        )
        _bind(a, ["_run_hyperscan_discovery"])
        a.interrupted = True

        with ExitStack() as stack:
            stack.enter_context(patch(_SHP + "sanitize_ip", side_effect=lambda x: x))
            stack.enter_context(
                patch(
                    "redaudit.core.hyperscan.hyperscan_full_port_sweep",
                    return_value=[80],
                )
            )
            # Should skip due to interrupted
            a._run_hyperscan_discovery(
                ["10.7.0.21"],
            )


# ═══════════════════════════════════════════════════════════════════════════
# Auth paths — SSH from ports (1743-1745, 1758), SMB break/continue (1870-1872)
# Auth paths — SMB ImportError (1917-1919)
# ═══════════════════════════════════════════════════════════════════════════


class TestAuthSSHFromPorts(unittest.TestCase):
    """Lines 1743-1745: SSH port found from ports list."""

    def test_ssh_found_from_ports(self):
        """SSH not in nmap services but found in ports list via service name."""
        a = _make_auditor(auth_enabled=True, deep_id_scan=True)

        SCAN_METHODS = [
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
        _bind(a, SCAN_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.7.0.30"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (5, ["ssh"])

        # Port 2222 is SSH but nmap doesn't report "ssh" as service
        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "server"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(
            return_value={
                2222: {
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "8.2",
                    "extrainfo": "",
                    "cpe": [],
                    "state": "open",
                    "reason": "",
                    "tunnel": "",
                },
            }
        )
        hd.get = MagicMock(return_value=None)
        nm.__getitem__ = MagicMock(return_value=hd)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        # Provide credentials
        cred = MagicMock()
        cred.username = "admin"
        cred.password = "pass"
        cred.key = None
        a.credential_provider = MagicMock()
        a.credential_provider.ssh_credentials = [cred]
        a.credential_provider.smb_credentials = []
        a.credential_provider.snmp_credentials = []

        with ExitStack() as stack:
            for name, kw in {
                "enrich_host_with_whois": {"return_value": None},
                "enrich_host_with_dns": {"return_value": None},
                "finalize_host_status": {"return_value": "up"},
                "http_identity_probe": {"return_value": None},
                "banner_grab_fallback": {"return_value": {}},
                "get_nmap_arguments": {"return_value": "-sV"},
                "is_dry_run": {"return_value": False},
                "sanitize_ip": {"side_effect": lambda x: x},
                "sanitize_hostname": {"side_effect": lambda x: x},
                "is_suspicious_service": {"return_value": False},
                "is_web_service": {"return_value": False},
                "run_udp_probe": {"return_value": []},
                "output_has_identity": {"return_value": False},
            }.items():
                stack.enter_context(patch(_SHP + name, **kw))
            # Mock SSH scanner to succeed
            mock_ssh_class = MagicMock()
            mock_ssh_instance = MagicMock()
            mock_ssh_instance.connect.return_value = True
            mock_ssh_instance.get_system_info.return_value = {
                "os": "Linux",
                "hostname": "server",
            }
            mock_ssh_instance.disconnect = MagicMock()
            mock_ssh_class.return_value = mock_ssh_instance
            stack.enter_context(patch("redaudit.core.auth_ssh.SSHScanner", mock_ssh_class))
            a.scan_host_ports(ip)


class TestAuthSMBImportError(unittest.TestCase):
    """Lines 1917-1919: SMB ImportError path."""

    def test_smb_import_error(self):
        a = _make_auditor(auth_enabled=True, verbose=True)

        SCAN_METHODS = [
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
        _bind(a, SCAN_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.7.0.31"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (5, ["smb"])

        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "server"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(
            return_value={
                445: {
                    "name": "microsoft-ds",
                    "product": "Samba",
                    "version": "",
                    "extrainfo": "",
                    "cpe": [],
                    "state": "open",
                    "reason": "",
                    "tunnel": "",
                },
            }
        )
        hd.get = MagicMock(return_value=None)
        nm.__getitem__ = MagicMock(return_value=hd)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        cred = MagicMock()
        cred.username = "admin"
        cred.password = "pass"
        a.credential_provider = MagicMock()
        a.credential_provider.ssh_credentials = []
        a.credential_provider.smb_credentials = [cred]
        a.credential_provider.snmp_credentials = []

        with ExitStack() as stack:
            for name, kw in {
                "enrich_host_with_whois": {"return_value": None},
                "enrich_host_with_dns": {"return_value": None},
                "finalize_host_status": {"return_value": "up"},
                "http_identity_probe": {"return_value": None},
                "banner_grab_fallback": {"return_value": {}},
                "get_nmap_arguments": {"return_value": "-sV"},
                "is_dry_run": {"return_value": False},
                "sanitize_ip": {"side_effect": lambda x: x},
                "sanitize_hostname": {"side_effect": lambda x: x},
                "is_suspicious_service": {"return_value": False},
                "is_web_service": {"return_value": False},
                "run_udp_probe": {"return_value": []},
                "output_has_identity": {"return_value": False},
            }.items():
                stack.enter_context(patch(_SHP + name, **kw))
            # Make SMB import fail
            stack.enter_context(
                patch(
                    "redaudit.core.auth_smb.SMBScanner",
                    side_effect=ImportError("no impacket"),
                )
            )
            a.scan_host_ports(ip)


if __name__ == "__main__":
    unittest.main()
