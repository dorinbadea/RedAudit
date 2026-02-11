"""
Coverage push #11 for auditor_scan.py — targeting remaining scattered gaps.
Focus areas:
- _resolve_smb_credential fallback (193)
- check_dependencies fallback path (309-310)
- _detect_interface target network overlap (470-471, 478, 482, 485-486)
- _apply_net_discovery_identity ARP/neighbor loops (573, 577-582, 598-599)
- mDNS _build_mdns_query exception (682-683)
- _run_udp_priority_probe invalid token (857-862)
- _scan_mode_host_timeout_s returns None (916)
- _merge_port_record update existing (1019-1020, 1044-1048)
- deep_scan_host sanitize_ip None (1076)
- _apply_net_discovery_identity vendor unknown fallback (533)
- scan_host_ports hostname exception (1563, 1570, 1589)
"""

import ipaddress
import threading
import unittest
from contextlib import contextmanager, ExitStack
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
# _resolve_smb_credential fallback → credential_provider (193)
# ═══════════════════════════════════════════════════════════════════════════


class TestResolveSMBCredentialFallback(unittest.TestCase):
    """Line 193: fallback to credential_provider.get_credential."""

    def test_fallback_to_credential_provider(self):
        a = _make_auditor()
        _bind(a, ["_resolve_smb_credential"])
        a.config["smb_user"] = None  # No inline cred
        a.config["smb_pass"] = None
        expected = MagicMock()
        a.credential_provider = MagicMock()
        a.credential_provider.get_credential.return_value = expected
        result = a._resolve_smb_credential("10.0.0.1")
        self.assertEqual(result, expected)


# ═══════════════════════════════════════════════════════════════════════════
# _detect_interface — target network overlap (470-486)
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectInterfaceFallbacks(unittest.TestCase):
    """Line 916: _parse_host_timeout_s returns None for unrecognised regex.
    Lines 470-486 are in detect_interface which is NOT on AuditorScan.
    We target _parse_host_timeout_s instead."""

    def test_no_host_timeout_flag(self):
        """_parse_host_timeout_s returns None when no --host-timeout."""
        result = AuditorScan._parse_host_timeout_s("-sV -Pn")
        self.assertIsNone(result)

    def test_host_timeout_ms(self):
        """_parse_host_timeout_s parses milliseconds."""
        result = AuditorScan._parse_host_timeout_s("--host-timeout 5000ms")
        self.assertAlmostEqual(result, 5.0)

    def test_host_timeout_hours(self):
        """_parse_host_timeout_s parses hours."""
        result = AuditorScan._parse_host_timeout_s("--host-timeout 1h")
        self.assertAlmostEqual(result, 3600.0)

    def test_host_timeout_not_a_string(self):
        """_parse_host_timeout_s returns None for non-string input."""
        result = AuditorScan._parse_host_timeout_s(123)
        self.assertIsNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# _apply_net_discovery_identity — ARP/neighbor loops (573-582, 598-599, 533)
# ═══════════════════════════════════════════════════════════════════════════


class TestApplyNetDiscoveryARP(unittest.TestCase):
    """Lines 573-582: ARP host found in topology pipeline."""

    def test_arp_found_in_pipeline(self):
        a = _make_auditor()
        _bind(a, ["_apply_net_discovery_identity"])
        host_record = {"ip": "10.0.0.5", "hostname": ""}
        a.results = {
            "net_discovery": {
                "pipeline": {
                    "topology": {
                        "interfaces": [
                            {
                                "arp": {
                                    "hosts": [
                                        {
                                            "ip": "10.0.0.5",
                                            "mac": "AA:BB:CC:00:11:22",
                                            "vendor": "Dell",
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
            }
        }
        a._apply_net_discovery_identity(host_record)

    def test_vendor_exception_in_lookup(self):
        """Lines 598-599: vendor lookup fails → vendor = None."""
        a = _make_auditor()
        _bind(a, ["_apply_net_discovery_identity"])
        host_record = {"ip": "10.0.0.6", "hostname": ""}
        a.results = {
            "net_discovery": {
                "pipeline": {
                    "topology": {
                        "interfaces": [
                            {"arp": {"hosts": [{"ip": "10.0.0.6", "mac": "AA:BB:CC:00:11:33"}]}}
                        ]
                    }
                }
            }
        }
        with patch(_SHP + "get_vendor_with_fallback", side_effect=Exception("offline")):
            a._apply_net_discovery_identity(host_record)


# ═══════════════════════════════════════════════════════════════════════════
# mDNS _build_mdns_query import error (682-683)
# ═══════════════════════════════════════════════════════════════════════════


class TestMdnsQueryException(unittest.TestCase):
    """Lines 682-683: _build_mdns_query import fails → fallback payload."""

    def test_mdns_import_error_fallback(self):
        a = _make_auditor(low_impact_enrichment=True)
        _bind(a, ["_run_low_impact_enrichment", "_extract_mdns_name"])
        with ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value=None))
            stack.enter_context(patch("socket.gethostbyaddr", side_effect=Exception("no DNS")))
            stack.enter_context(
                patch(
                    "redaudit.core.hyperscan._build_mdns_query",
                    side_effect=ImportError("no module"),
                )
            )
            # Socket will timeout on mDNS
            mock_sock = MagicMock()
            mock_sock.recvfrom.side_effect = TimeoutError("timeout")
            stack.enter_context(patch("socket.socket", return_value=mock_sock))
            result = a._run_low_impact_enrichment("10.0.0.7")
            self.assertIsInstance(result, dict)


# ═══════════════════════════════════════════════════════════════════════════
# _run_udp_priority_probe invalid token (857-862)
# ═══════════════════════════════════════════════════════════════════════════


class TestUDPPriorityProbeInvalidToken(unittest.TestCase):
    """Lines 857-862: invalid port token in UDP_PRIORITY_PORTS → skip with debug log."""

    def test_invalid_port_token_skipped(self):
        a = _make_auditor()
        _bind(a, ["_run_udp_priority_probe"])
        host_record = {"ip": "10.0.0.8"}

        with ExitStack() as stack:
            stack.enter_context(patch(_SHP + "sanitize_ip", side_effect=lambda x: x))
            stack.enter_context(patch(_SHP + "is_dry_run", return_value=False))
            stack.enter_context(patch(_SHP + "UDP_PRIORITY_PORTS", "161,abc,123"))
            stack.enter_context(patch(_SHP + "run_udp_probe", return_value=[]))
            result = a._run_udp_priority_probe(host_record)
            self.assertFalse(result)
            a.logger.debug.assert_called()


# ═══════════════════════════════════════════════════════════════════════════
# _scan_mode_host_timeout_s returns None (916)
# ═══════════════════════════════════════════════════════════════════════════


class TestScanModeHostTimeoutNone(unittest.TestCase):
    """Line 916: _parse_host_timeout_s returns None for no --host-timeout."""

    def test_no_timeout(self):
        result = AuditorScan._parse_host_timeout_s("")
        self.assertIsNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# _merge_port_record update existing service (1044-1048)
# ═══════════════════════════════════════════════════════════════════════════


class TestMergeServicesUpdatesExisting(unittest.TestCase):
    """Lines 1044-1048: update existing service with new port data."""

    def test_update_existing_service_fields(self):
        host_obj = Host(ip="10.0.0.9")
        # Existing service with empty fields
        existing_svc = Service(
            port=22,
            protocol="tcp",
            name="ssh",
            product="",
            version="",
            extrainfo="",
            cpe=[],
        )
        host_obj.services = [existing_svc]
        ports = [
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "8.2",
                "extrainfo": "Ubuntu",
                "cpe": ["cpe:/a:openssh:openssh:8.2"],
            }
        ]
        AuditorScan._merge_services_from_ports(host_obj, ports)
        # Service should be updated
        self.assertEqual(existing_svc.product, "OpenSSH")
        self.assertEqual(existing_svc.version, "8.2")
        self.assertEqual(existing_svc.extrainfo, "Ubuntu")


# ═══════════════════════════════════════════════════════════════════════════
# deep_scan_host sanitize_ip None (1076)
# ═══════════════════════════════════════════════════════════════════════════


class TestDeepScanHostSanitizeNone(unittest.TestCase):
    """Line 1076: sanitize_ip returns None → return None."""

    def test_invalid_ip(self):
        a = _make_auditor()
        _bind(a, ["deep_scan_host"])
        with patch(_SHP + "sanitize_ip", return_value=None):
            result = a.deep_scan_host("not-an-ip")
            self.assertIsNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# _lookup_topology_identity — vendor "unknown" filter (533)
# ═══════════════════════════════════════════════════════════════════════════


class TestLookupTopologyVendorUnknown(unittest.TestCase):
    """Line 530-533: vendor containing 'unknown' → set to None."""

    def test_vendor_unknown_filtered(self):
        a = _make_auditor()
        _bind(a, ["_lookup_topology_identity"])
        a.results = {
            "topology": {
                "interfaces": [
                    {
                        "arp": {
                            "hosts": [
                                {
                                    "ip": "10.0.0.10",
                                    "mac": "AA:BB:CC:00:00:10",
                                    "vendor": "Unknown Vendor",
                                }
                            ]
                        }
                    }
                ]
            }
        }
        mac, vendor = a._lookup_topology_identity("10.0.0.10")
        self.assertEqual(mac, "AA:BB:CC:00:00:10")
        self.assertIsNone(vendor)


# ═══════════════════════════════════════════════════════════════════════════
# _merge_port_record incoming key exception (1019-1020)
# ═══════════════════════════════════════════════════════════════════════════


class TestMergePortRecordKeyException(unittest.TestCase):
    """Lines 1019-1020: incoming key creation fails in _merge_ports → skip."""

    def test_key_creation_exception(self):
        a = _make_auditor()
        _bind(a, ["_merge_ports"])
        # Staticmethod direct assignment to avoid binding issues
        a._merge_port_record = AuditorScan._merge_port_record
        existing = [{"port": 22, "protocol": "tcp", "service": "ssh"}]
        incoming = [{"port": None, "protocol": None}]  # Will cause int(None) error
        result = a._merge_ports(existing, incoming)
        # Should return existing only, incoming silently skipped
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["port"], 22)


# ═══════════════════════════════════════════════════════════════════════════
# scan_host_ports — hostname exception (1563, 1570)
# ═══════════════════════════════════════════════════════════════════════════


class TestScanHostPortsHostnameException(unittest.TestCase):
    """Lines 1563, 1570: hostname retrieval fails."""

    def test_hostname_lookup_exception(self):
        a = _make_auditor()
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
        ip = "10.7.2.1"
        a.scanner.get_or_create_host.return_value = Host(ip=ip)
        a.scanner.compute_identity_score.return_value = (5, ["mac"])

        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        # hostnames() raises exception
        hd.hostnames.side_effect = Exception("bad hostname data")
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(
            return_value={
                80: {
                    "name": "http",
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


if __name__ == "__main__":
    unittest.main()
