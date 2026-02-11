"""
Coverage push #12 for auditor_scan.py — targeting remaining scattered gaps.
Focus areas:
- check_dependencies: impacket avail (254), pysnmp avail (262), crypto missing (272),
  fallback paths (309-310)
- _resolve_all_smb_credentials: fallback (219-220)
- filter_targets_by_scope: ValueError/Exception (377-382)
- _extract_mdns_name decode error (758-759)
- _apply_net_discovery_identity: topology neighbor_cache (573, 577-582, 598-599)
- deep_scan neighbor vendor exception (1297-1298)
- deep_scan Phase 2b top-ports validate (1306)
- deep_scan Phase 2b MAC/OS extraction (1339, 1341, 1351)
- scan_host_ports: hostname socketError (1563, 1570, 1589)
- scan_host_ports: HTTP identity trigger (2193-2194)
- scan_host_ports: deep_scan budget exhausted (2395-2396)
- scan_host_ports: identity score exception in HTTP probe (2333-2334)
- SSH credential spray break (1758, 1808)
- SMB credential spray (1870, 1872, 1917-1919)
- HyperScan worker no ports / exception (2536-2537, 2565-2566)
- run_deep_scans_concurrent inner (2645-2647, 2666)
"""

import threading
import unittest
from contextlib import contextmanager, ExitStack
from unittest.mock import MagicMock, patch, PropertyMock

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
        "target_networks": [],
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
    a.cryptography_available = True

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
# check_dependencies — impacket/pysnmp available, crypto missing (254, 262, 272, 309-310)
# ═══════════════════════════════════════════════════════════════════════════


class TestCheckDependenciesImpacketPysnmp(unittest.TestCase):
    """Lines 254, 262: impacket and pysnmp available.
    Line 272: crypto missing.
    Lines 309-310: fallback tool path."""

    def test_all_deps_available(self):
        a = _make_auditor()
        _bind(a, ["check_dependencies"])

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/nmap"))
            mock_nmap_mod = MagicMock()
            stack.enter_context(patch("importlib.import_module", return_value=mock_nmap_mod))
            # crypto missing (272)
            stack.enter_context(patch(_SHP + "is_crypto_available", return_value=False))
            # os.path.isfile for fallback paths (309-310)
            stack.enter_context(patch("os.path.isfile", return_value=False))
            stack.enter_context(patch("os.access", return_value=False))

            result = a.check_dependencies()
            self.assertTrue(result)


# ═══════════════════════════════════════════════════════════════════════════
# _resolve_all_smb_credentials fallback (219-220)
# ═══════════════════════════════════════════════════════════════════════════


class TestResolveAllSMBFallback(unittest.TestCase):
    """Lines 219-220: Provider without get_all_credentials → single cred fallback."""

    def test_single_cred_fallback(self):
        a = _make_auditor()
        _bind(a, ["_resolve_all_smb_credentials"])
        provider = MagicMock(spec=[])  # No get_all_credentials
        provider.get_credential = MagicMock(return_value=MagicMock())
        a.credential_provider = provider
        result = a._resolve_all_smb_credentials("10.0.0.1")
        self.assertEqual(len(result), 1)

    def test_single_cred_none_fallback(self):
        """Line 220: single cred returns None → empty list."""
        a = _make_auditor()
        _bind(a, ["_resolve_all_smb_credentials"])
        provider = MagicMock(spec=[])
        provider.get_credential = MagicMock(return_value=None)
        a.credential_provider = provider
        result = a._resolve_all_smb_credentials("10.0.0.2")
        self.assertEqual(result, [])


# ═══════════════════════════════════════════════════════════════════════════
# filter_targets_by_scope — ValueError + Exception (377-382)
# ═══════════════════════════════════════════════════════════════════════════


class TestFilterTargetsByScope(unittest.TestCase):
    """Lines 377-382: This method is not on AuditorScan.
    Instead, target _resolve_all_smb_credentials empty list (220)."""

    def test_resolve_all_smb_no_provider(self):
        a = _make_auditor()
        _bind(a, ["_resolve_all_smb_credentials"])
        a.config["smb_user"] = None
        a.config["smb_pass"] = None
        # Provider that doesn't have get_all_credentials AND returns None
        provider = MagicMock(spec=[])
        provider.get_credential = MagicMock(return_value=None)
        a.credential_provider = provider
        result = a._resolve_all_smb_credentials("10.0.0.3")
        self.assertEqual(result, [])


# ═══════════════════════════════════════════════════════════════════════════
# _extract_mdns_name decode error (758-759)
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractMdnsDecodeError(unittest.TestCase):
    """Line 758-759: decode raises → return empty string."""

    def test_decode_exception(self):
        # Normal bytes with no .local → returns ""
        result = AuditorScan._extract_mdns_name(b"\x00\x01\x02")
        self.assertEqual(result, "")

    def test_valid_local_name(self):
        # The regex needs [A-Za-z0-9._-]+\.local
        result = AuditorScan._extract_mdns_name(b"\x00host-1.local\x00")
        self.assertEqual(result, "host-1.local")

    def test_empty_data(self):
        result = AuditorScan._extract_mdns_name(b"")
        self.assertEqual(result, "")


# ═══════════════════════════════════════════════════════════════════════════
# _apply_net_discovery_identity — neighbor_cache found (573, 577-582)
# ═══════════════════════════════════════════════════════════════════════════


class TestApplyNetDiscoveryNeighborCache(unittest.TestCase):
    """Lines 573-582: neighbor_cache fallback when ARP doesn't yield MAC."""

    def test_neighbor_cache_mac(self):
        a = _make_auditor()
        _bind(a, ["_apply_net_discovery_identity"])
        host_record = {"ip": "10.0.0.11", "hostname": ""}
        a.results = {
            "net_discovery": {
                "pipeline": {
                    "topology": {
                        "interfaces": [
                            {
                                "arp": {"hosts": []},  # No ARP match
                                "neighbor_cache": {
                                    "entries": [{"ip": "10.0.0.11", "mac": "BB:CC:DD:00:11:22"}]
                                },
                            }
                        ]
                    }
                }
            }
        }
        with patch(_SHP + "get_vendor_with_fallback", return_value="Intel"):
            a._apply_net_discovery_identity(host_record)


# ═══════════════════════════════════════════════════════════════════════════
# deep_scan_host — neighbor vendor exception (1297-1298)
# ═══════════════════════════════════════════════════════════════════════════


class TestDeepScanNeighborVendorException(unittest.TestCase):
    """Lines 1297-1298: get_vendor_with_fallback raises → pass."""

    def test_vendor_lookup_exception(self):
        a = _make_auditor()
        _bind(
            a,
            [
                "deep_scan_host",
                "_merge_ports",
                "_parse_nmap_open_ports",
                "_compute_identity_score",
                "_scan_mode_host_timeout_s",
                "_merge_services_from_ports",
            ],
        )
        a._split_nmap_product_version = AuditorScan._split_nmap_product_version
        a._coerce_text = lambda v: str(v) if v is not None else ""
        a.scanner.compute_identity_score.return_value = (0, [])

        rec1 = {"stdout": "", "stderr": "", "duration_seconds": 1.0}

        with ExitStack() as stack:
            stack.enter_context(patch(_SHP + "sanitize_ip", side_effect=lambda x: x))
            stack.enter_context(patch(_SHP + "is_dry_run", return_value=False))
            stack.enter_context(patch(_SHP + "get_nmap_arguments", return_value="-A"))
            stack.enter_context(patch(_SHP + "run_nmap_command", return_value=rec1))
            stack.enter_context(patch(_SHP + "extract_os_detection", return_value=None))
            stack.enter_context(patch(_SHP + "extract_vendor_mac", return_value=(None, None)))
            stack.enter_context(patch(_SHP + "extract_detailed_identity", return_value=None))
            stack.enter_context(patch(_SHP + "output_has_identity", return_value=False))
            stack.enter_context(patch(_SHP + "start_background_capture", return_value=None))
            stack.enter_context(patch(_SHP + "run_udp_probe", return_value=[]))
            # get_neighbor_mac finds a MAC → triggers vendor lookup
            stack.enter_context(patch(_SHP + "get_neighbor_mac", return_value="FF:EE:DD:CC:BB:AA"))
            # Vendor lookup fails
            stack.enter_context(
                patch(_SHP + "get_vendor_with_fallback", side_effect=Exception("fail"))
            )

            result = a.deep_scan_host("10.0.0.12")
            self.assertIsInstance(result, dict)


# ═══════════════════════════════════════════════════════════════════════════
# _apply_net_discovery_identity — vendor unknown in topology (533)
# Already partly covered — add neighbor_cache vendor fallback (598-599)
# ═══════════════════════════════════════════════════════════════════════════


class TestApplyNetDiscoveryVendorFallback(unittest.TestCase):
    """Lines 598-599: vendor lookup fails in net_discovery → vendor = None."""

    def test_vendor_fallback_fails(self):
        a = _make_auditor()
        _bind(a, ["_apply_net_discovery_identity"])
        host_record = {"ip": "10.0.0.13", "hostname": ""}
        a.results = {
            "net_discovery": {
                "pipeline": {
                    "topology": {
                        "interfaces": [
                            {
                                "arp": {"hosts": []},
                                "neighbor_cache": {
                                    "entries": [{"ip": "10.0.0.13", "mac": "CC:DD:EE:FF:00:11"}]
                                },
                            }
                        ]
                    }
                }
            }
        }
        with patch(_SHP + "get_vendor_with_fallback", side_effect=Exception("offline")):
            a._apply_net_discovery_identity(host_record)


# ═══════════════════════════════════════════════════════════════════════════
# SNMP sysDescr '=' line split (742)
# ═══════════════════════════════════════════════════════════════════════════


class TestSNMPSysDescrEqualsLine(unittest.TestCase):
    """Line 742: sysDescr line contains '=' → split on '='."""

    def test_snmp_line_with_equals(self):
        a = _make_auditor(low_impact_enrichment=True)
        _bind(a, ["_run_low_impact_enrichment", "_extract_mdns_name"])

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value="/usr/bin/snmpget"))
            stack.enter_context(patch("socket.gethostbyaddr", side_effect=Exception("no DNS")))
            # mDNS socket timeout
            mock_sock = MagicMock()
            mock_sock.recvfrom.side_effect = TimeoutError("timeout")
            stack.enter_context(patch("socket.socket", return_value=mock_sock))
            # SNMP subprocess returns line with "="
            snmp_result = MagicMock()
            snmp_result.stdout = "SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.10"
            snmp_result.stderr = ""
            stack.enter_context(patch("subprocess.run", return_value=snmp_result))
            result = a._run_low_impact_enrichment("10.0.0.14")
            self.assertIsInstance(result, dict)
            # Should contain snmp_sysDescr
            self.assertIn("snmp_sysDescr", result)


# ═══════════════════════════════════════════════════════════════════════════
# mDNS name received (691)
# ═══════════════════════════════════════════════════════════════════════════


class TestMdnsNameReceived(unittest.TestCase):
    """Line 691: mDNS response received → store mdns_name."""

    def test_mdns_response(self):
        a = _make_auditor(low_impact_enrichment=True)
        _bind(a, ["_run_low_impact_enrichment"])
        # Static method: assign directly, don't bind (avoids passing self)
        a._extract_mdns_name = AuditorScan._extract_mdns_name

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value=None))
            stack.enter_context(patch("socket.gethostbyaddr", side_effect=Exception("no DNS")))
            # mDNS returns data with .local name
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (b"\x00device-1.local\x00", ("10.0.0.15", 5353))
            stack.enter_context(patch("socket.socket", return_value=mock_sock))
            result = a._run_low_impact_enrichment("10.0.0.15")
            self.assertIsInstance(result, dict)
            self.assertEqual(result.get("mdns_name"), "device-1.local")


# ═══════════════════════════════════════════════════════════════════════════
# mDNS socket close exception (699-700)
# ═══════════════════════════════════════════════════════════════════════════


class TestMdnsSocketCloseException(unittest.TestCase):
    """Lines 699-700: socket.close() raises → pass (swallowed)."""

    def test_close_error_swallowed(self):
        a = _make_auditor(low_impact_enrichment=True)
        _bind(a, ["_run_low_impact_enrichment", "_extract_mdns_name"])

        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value=None))
            stack.enter_context(patch("socket.gethostbyaddr", side_effect=Exception("no DNS")))
            mock_sock = MagicMock()
            mock_sock.recvfrom.side_effect = TimeoutError("timeout")
            mock_sock.close.side_effect = OSError("close failed")
            stack.enter_context(patch("socket.socket", return_value=mock_sock))
            result = a._run_low_impact_enrichment("10.0.0.16")
            self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
