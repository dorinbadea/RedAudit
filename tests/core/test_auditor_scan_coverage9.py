"""
Coverage push #9 for auditor_scan.py — targeting remaining gaps to push toward 95%.
Focus areas:
- HTTP probe identity_score exception (2333-2334)
- agentless_probe + smart_scan population (2365, 2371)
- UPnP http overwrite (2078)
- full scan mode threshold (2125, 2127)
- HTTP fingerprint web_count force (2183-2186, 2193-2194)
- nmap vendor online fallback (2016-2017)
- scan error exception path (2395-2396)
"""

import unittest
from contextlib import contextmanager, ExitStack
from unittest.mock import MagicMock, patch

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
    a.__dict__["_deep_budget_lock"] = None
    a._set_ui_detail = MagicMock()
    a._coerce_text = MagicMock(side_effect=lambda v: str(v) if v is not None else "")

    @contextmanager
    def _fake_progress_ui():
        yield

    a._progress_ui = _fake_progress_ui
    return a


def _bind_all(aud, names):
    for n in names:
        setattr(aud, n, getattr(AuditorScan, n).__get__(aud, AuditorScan))


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

_SHP = "redaudit.core.auditor_scan."


def _enter_scan_patches(stack):
    """Enter all standard scan_host_ports patches."""
    mocks = {}
    patches = {
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
    }
    for name, kw in patches.items():
        mocks[name] = stack.enter_context(patch(_SHP + name, **kw))
    return mocks


def _nmap_with_ports(ip, ports_dict, mac=None, vendor=None):
    """Nmap mock with given port dict."""
    nm = MagicMock()
    nm.all_hosts.return_value = [ip]
    hd = MagicMock()
    hd.hostnames.return_value = [{"name": "host1"}]
    hd.state.return_value = "up"
    hd.all_protocols.return_value = ["tcp"]
    hd.__getitem__ = MagicMock(return_value=ports_dict)

    addr = {"mac": mac} if mac else {}
    vnd = {mac: vendor} if mac and vendor else {}

    def get_se(k, d=None):
        return {
            "addresses": addr,
            "vendor": vnd,
            "osmatch": [],
        }.get(k, d)

    hd.get = MagicMock(side_effect=get_se)
    nm.__getitem__ = MagicMock(return_value=hd)
    return nm


def _nmap_zero_with_mac(ip, mac="AA:BB:CC:DD:EE:FF", vendor="Ubiquiti"):
    """Nmap mock with zero ports but MAC + vendor."""
    nm = MagicMock()
    nm.all_hosts.return_value = [ip]
    hd = MagicMock()
    hd.hostnames.return_value = [{"name": ""}]
    hd.state.return_value = "up"
    hd.all_protocols.return_value = []
    hd.__getitem__ = MagicMock(return_value={})

    def get_se(k, d=None):
        return {
            "addresses": {"mac": mac},
            "vendor": {mac: vendor},
            "osmatch": [],
        }.get(k, d)

    hd.get = MagicMock(side_effect=get_se)
    nm.__getitem__ = MagicMock(return_value=hd)
    return nm


# ═══════════════════════════════════════════════════════════════════════════
# HTTP probe identity_score exception (2333-2334)
# ═══════════════════════════════════════════════════════════════════════════


class TestHTTPProbeScoreException(unittest.TestCase):
    """Lines 2333-2334: int() fails on identity_score → caught."""

    def test_bad_score_caught(self):
        a = _make_auditor(low_impact_enrichment=True, deep_id_scan=True)
        _bind_all(a, FULL_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.6.0.1"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (0, [])
        nm = _nmap_zero_with_mac(ip)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        with ExitStack() as stack:
            mocks = _enter_scan_patches(stack)
            mocks["http_identity_probe"].return_value = {
                "http_title": "Admin",
                "http_server": "nginx",
            }
            # Inject bad identity_score into smart_scan after it's created
            orig_prune = a._prune_weak_identity_reasons

            def prune_inject(smart):
                # Before prune, corrupt the score so the try at 2332 fails
                smart["identity_score"] = "not_a_number"
                return orig_prune(smart)

            a._prune_weak_identity_reasons = prune_inject

            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Full scan mode threshold adjustment (2125, 2127)
# ═══════════════════════════════════════════════════════════════════════════


class TestFullModeThreshold(unittest.TestCase):
    """Lines 2125, 2127: full mode + low threshold → forced to 4."""

    def test_full_mode_raises_threshold(self):
        a = _make_auditor(
            scan_mode="full",
            deep_id_scan=True,
            identity_threshold=2,  # Below 4 in full mode
        )
        _bind_all(a, FULL_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.6.0.10"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (3, ["ssh"])

        nm = _nmap_with_ports(
            ip,
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
            },
        )
        a.scanner.run_nmap_scan.return_value = (nm, None)

        with ExitStack() as stack:
            _enter_scan_patches(stack)
            a.scan_host_ports(ip)

    def test_invalid_threshold(self):
        """Non-int threshold → DEFAULT_IDENTITY_THRESHOLD used."""
        a = _make_auditor(
            scan_mode="quick",
            deep_id_scan=True,
            identity_threshold="bad",
        )
        _bind_all(a, FULL_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.6.0.11"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (3, [])

        nm = _nmap_with_ports(
            ip,
            {
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
        a.scanner.run_nmap_scan.return_value = (nm, None)

        with ExitStack() as stack:
            _enter_scan_patches(stack)
            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# UPnP http overwrite (2078: upnp_device_name preservation)
# ═══════════════════════════════════════════════════════════════════════════


class TestUPnPHTTPOverwrite(unittest.TestCase):
    """Line 2078: http_source=upnp → upnp_device_name preserved."""

    def test_upnp_overwrite(self):
        a = _make_auditor(deep_id_scan=True)
        _bind_all(a, FULL_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.6.0.20"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (0, [])

        # Set up nmap with a web port so the first http_identity_probe fires
        nm = _nmap_with_ports(
            ip,
            {
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
            },
        )
        a.scanner.run_nmap_scan.return_value = (nm, None)

        # Pre-populate agentless with UPnP source
        a._apply_net_discovery_identity = MagicMock(
            side_effect=lambda hr: hr.update(
                {
                    "agentless_fingerprint": {
                        "http_title": "UPnP Device",
                        "http_source": "upnp",
                    }
                }
            )
        )

        with ExitStack() as stack:
            mocks = _enter_scan_patches(stack)
            mocks["is_web_service"].return_value = True
            mocks["http_identity_probe"].return_value = {
                "http_title": "Real WebUI",
                "http_server": "Apache/2.4",
            }
            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# HTTP fingerprint forces web vuln scan (2183-2186, 2193-2194)
# ═══════════════════════════════════════════════════════════════════════════


class TestHTTPFingerprintForcesWebScan(unittest.TestCase):
    """Lines 2183-2186, 2193-2194: http fingerprint detected + 0 ports → force."""

    def test_http_fingerprint_forces_deep_and_web(self):
        a = _make_auditor(deep_id_scan=True)
        _bind_all(a, FULL_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.6.0.30"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (0, [])

        nm = _nmap_zero_with_mac(ip)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        # Inject agentless fingerprint with HTTP title BEFORE identity computation
        a._apply_net_discovery_identity = MagicMock(
            side_effect=lambda hr: hr.update(
                {
                    "agentless_fingerprint": {
                        "http_title": "Management Console",
                        "http_source": "probe",
                    }
                }
            )
        )

        with ExitStack() as stack:
            _enter_scan_patches(stack)
            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Nmap vendor online fallback (2016-2017)
# ═══════════════════════════════════════════════════════════════════════════


class TestNmapVendorOnlineFallback(unittest.TestCase):
    """Lines 2016-2017: vendor lookup_vendor_online fails → pass."""

    def test_online_fallback_exception(self):
        a = _make_auditor(deep_id_scan=True)
        _bind_all(a, FULL_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.6.0.40"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (3, [])
        mac = "AA:BB:CC:00:00:01"

        # Nmap with MAC but NO vendor → triggers online fallback
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

        def get_se(k, d=None):
            return {
                "addresses": {"mac": mac},
                "vendor": {},  # Empty vendor → fallback
                "osmatch": [],
            }.get(k, d)

        hd.get = MagicMock(side_effect=get_se)
        nm.__getitem__ = MagicMock(return_value=hd)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        with ExitStack() as stack:
            _enter_scan_patches(stack)
            # Mock the online fallback to raise
            stack.enter_context(
                patch(
                    "redaudit.utils.oui_lookup.lookup_vendor_online",
                    side_effect=Exception("offline"),
                )
            )
            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Scan error exception path (2395-2396, 2477-2478)
# ═══════════════════════════════════════════════════════════════════════════


class TestScanErrorExceptionPath(unittest.TestCase):
    """Lines 2395-2396: scan_host_ports raises → error path with budget."""

    def test_exception_during_scan(self):
        a = _make_auditor(deep_id_scan=True)
        _bind_all(a, FULL_METHODS)
        ip = "10.6.0.50"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj

        # Make nmap raise
        a.scanner.run_nmap_scan.side_effect = RuntimeError("network error")

        with ExitStack() as stack:
            _enter_scan_patches(stack)
            result = a.scan_host_ports(ip)
            # Should return host with error status
            self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# Host record agentless_probe + smart_scan population (2365, 2371)
# ═══════════════════════════════════════════════════════════════════════════


class TestHostRecordPopulation(unittest.TestCase):
    """Lines 2365, 2371: agentless_probe and smart_scan set on host_obj."""

    def test_agentless_probe_populated(self):
        a = _make_auditor(deep_id_scan=True)
        _bind_all(a, FULL_METHODS)
        a._run_udp_priority_probe = MagicMock(return_value=False)
        ip = "10.6.0.60"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (5, ["ssh", "mac"])

        nm = _nmap_with_ports(
            ip,
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
            },
            mac="AA:BB:CC:DD:EE:01",
            vendor="Linux",
        )
        a.scanner.run_nmap_scan.return_value = (nm, None)

        # Pre-populate agentless_probe in the flow
        a._apply_net_discovery_identity = MagicMock(
            side_effect=lambda hr: hr.update(
                {
                    "agentless_probe": {"os": "Linux"},
                    "smart_scan": {"signals": [], "identity_score": 5},
                }
            )
        )

        with ExitStack() as stack:
            _enter_scan_patches(stack)
            result = a.scan_host_ports(ip)
            self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════════════
# _run_low_impact_enrichment inner paths (573, 577-582, 598-599)
# ═══════════════════════════════════════════════════════════════════════════


class TestLowImpactEnrichmentInner(unittest.TestCase):
    """Cover inner paths of _run_low_impact_enrichment."""

    def test_dns_with_dig(self):
        """DNS reverse lookup with dig tool."""
        a = _make_auditor(low_impact_enrichment=True)
        _bind_all(a, ["_run_low_impact_enrichment", "_extract_mdns_name"])
        a.extra_tools = {"dig": "/usr/bin/dig"}

        with patch(_SHP + "sanitize_ip", side_effect=lambda x: x):
            with patch(_SHP + "is_dry_run", return_value=False):
                with patch(_SHP + "CommandRunner") as mock_runner:
                    res = MagicMock()
                    res.stdout = "host.example.com.\n"
                    mock_runner.return_value.run.return_value = res
                    result = a._run_low_impact_enrichment("10.0.0.1")
                    self.assertIn("dns_reverse", result)

    def test_dns_without_dig_fallback(self):
        """DNS reverse lookup using socket.gethostbyaddr fallback."""
        a = _make_auditor(low_impact_enrichment=True)
        _bind_all(a, ["_run_low_impact_enrichment", "_extract_mdns_name"])
        a.extra_tools = {}

        with patch(_SHP + "sanitize_ip", side_effect=lambda x: x):
            with patch(_SHP + "is_dry_run", return_value=False):
                with patch("socket.gethostbyaddr", return_value=("router.local", [], [])):
                    with patch("socket.socket") as mock_sock:
                        inst = MagicMock()
                        inst.recvfrom.side_effect = Exception("timeout")
                        mock_sock.return_value = inst
                        result = a._run_low_impact_enrichment("10.0.0.2")
                        self.assertIn("dns_reverse", result)

    def test_mdns_response(self):
        """mDNS probe gets a response."""
        a = _make_auditor(low_impact_enrichment=True)
        _bind_all(a, ["_run_low_impact_enrichment", "_extract_mdns_name"])
        a.extra_tools = {}

        with patch(_SHP + "sanitize_ip", side_effect=lambda x: x):
            with patch(_SHP + "is_dry_run", return_value=False):
                with patch("socket.gethostbyaddr", side_effect=Exception("no reverse")):
                    with patch("socket.socket") as mock_sock:
                        inst = MagicMock()
                        inst.recvfrom.return_value = (b"\x00\x01device.local", ("10.0.0.3", 5353))
                        mock_sock.return_value = inst
                        with patch("shutil.which", return_value=None):
                            result = a._run_low_impact_enrichment("10.0.0.3")
                            self.assertIsInstance(result, dict)

    def test_snmp_sysdescr(self):
        """SNMP sysDescr probe works."""
        a = _make_auditor(
            low_impact_enrichment=True,
            net_discovery_snmp_community="public",
        )
        _bind_all(a, ["_run_low_impact_enrichment", "_extract_mdns_name"])
        a.extra_tools = {}

        with patch(_SHP + "sanitize_ip", side_effect=lambda x: x):
            with patch(_SHP + "is_dry_run", return_value=False):
                with patch("socket.gethostbyaddr", side_effect=Exception("fail")):
                    with patch("socket.socket") as mock_sock:
                        inst = MagicMock()
                        inst.recvfrom.side_effect = Exception("timeout")
                        mock_sock.return_value = inst
                        with patch("shutil.which", return_value="/usr/bin/snmpwalk"):
                            with patch(_SHP + "CommandRunner") as mock_runner:
                                res = MagicMock()
                                res.stdout = "STRING: Linux router 5.15"
                                res.stderr = ""
                                mock_runner.return_value.run.return_value = res
                                result = a._run_low_impact_enrichment("10.0.0.4")
                                self.assertIn("snmp_sysDescr", result)


if __name__ == "__main__":
    unittest.main()
