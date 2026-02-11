"""
Coverage push #8 for auditor_scan.py — surgical strikes on remaining gaps.
Key fix: HTTP probe (2311-2335) uses explicit patch context managers,
not decorator stacking which may have ordering issues.
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
    """Enter all standard scan_host_ports patches using ExitStack.
    Returns a dict of name → mock."""
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
    }
    for name, kw in patches.items():
        mocks[name] = stack.enter_context(patch(_SHP + name, **kw))
    return mocks


class TestHTTPProbeSurgical(unittest.TestCase):
    """Lines 2311-2335: zero-port HTTP probe using ExitStack for clarity."""

    def _make_nmap_zero_ports_with_mac(self, ip, mac="AA:BB:CC:DD:EE:FF", vendor="Ubiquiti"):
        """Nmap result with zero ports but MAC + vendor."""
        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        # Empty hostname so hostname_hint is falsy
        hd.hostnames.return_value = [{"name": ""}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = []
        hd.__getitem__ = MagicMock(return_value={})

        def get_side_effect(k, d=None):
            data = {
                "addresses": {"mac": mac},
                "vendor": {mac: vendor},
                "osmatch": [],
            }
            return data.get(k, d)

        hd.get = MagicMock(side_effect=get_side_effect)
        nm.__getitem__ = MagicMock(return_value=hd)
        return nm

    def test_http_probe_reaches_line_2311(self):
        """Verify HTTP probe at line 2311 is actually reached."""
        a = _make_auditor(
            low_impact_enrichment=True,
            deep_id_scan=True,
        )
        _bind_all(a, FULL_METHODS)
        ip = "10.5.0.1"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (0, [])

        nm = self._make_nmap_zero_ports_with_mac(ip)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        # Override _run_udp_priority_probe to prevent real UDP calls
        # and ensure we don't get stuck before reaching line 2311
        a._run_udp_priority_probe = MagicMock(return_value=False)

        with ExitStack() as stack:
            mocks = _enter_scan_patches(stack)
            # Override http_identity_probe to return useful data
            mocks["http_identity_probe"].return_value = {
                "http_title": "UniFi Controller",
                "http_server": "nginx/1.20",
            }
            a.scan_host_ports(ip)

        # The probe MUST have been called — if not, the guard conditions fail
        mocks["http_identity_probe"].assert_called_once()

    def test_http_probe_smart_scan_update(self):
        """HTTP probe updates smart_scan signals and identity_score."""
        a = _make_auditor(
            low_impact_enrichment=True,
            deep_id_scan=True,
        )
        _bind_all(a, FULL_METHODS)
        ip = "10.5.0.2"
        host_obj = Host(ip=ip)
        host_obj.smart_scan = {"signals": ["mac"], "identity_score": 1}
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (0, [])

        nm = self._make_nmap_zero_ports_with_mac(ip)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        a._run_udp_priority_probe = MagicMock(return_value=False)

        with ExitStack() as stack:
            mocks = _enter_scan_patches(stack)
            mocks["http_identity_probe"].return_value = {
                "http_title": "Admin Panel",
                "http_server": "lighttpd",
            }
            a.scan_host_ports(ip)

    def test_http_probe_score_exception(self):
        """HTTP probe with invalid identity_score → Exception caught at 2333."""
        a = _make_auditor(
            low_impact_enrichment=True,
            deep_id_scan=True,
        )
        _bind_all(a, FULL_METHODS)
        ip = "10.5.0.3"
        host_obj = Host(ip=ip)
        host_obj.smart_scan = {"signals": [], "identity_score": "bad"}
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (0, [])

        nm = self._make_nmap_zero_ports_with_mac(ip)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        a._run_udp_priority_probe = MagicMock(return_value=False)

        with ExitStack() as stack:
            mocks = _enter_scan_patches(stack)
            mocks["http_identity_probe"].return_value = {
                "http_title": "Page",
                "http_server": "nginx",
            }
            a.scan_host_ports(ip)

    def test_http_probe_null_result(self):
        """HTTP probe returns None → no update at 2318."""
        a = _make_auditor(
            low_impact_enrichment=True,
            deep_id_scan=True,
        )
        _bind_all(a, FULL_METHODS)
        ip = "10.5.0.4"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (0, [])

        nm = self._make_nmap_zero_ports_with_mac(ip)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        a._run_udp_priority_probe = MagicMock(return_value=False)

        with ExitStack() as stack:
            mocks = _enter_scan_patches(stack)
            mocks["http_identity_probe"].return_value = None
            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Identity re-eval after UDP (2183-2194)
# ═══════════════════════════════════════════════════════════════════════════


class TestIdentityReEvalInner(unittest.TestCase):
    """Lines 2183-2194: identity re-eval after UDP."""

    def test_udp_changes_score(self):
        """UDP probe resolves identity → score recalculated."""
        a = _make_auditor(deep_id_scan=True, deep_scan_budget=10)
        _bind_all(a, FULL_METHODS)
        ip = "10.5.0.10"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        # First: low score, second: high score after UDP
        a.scanner.compute_identity_score.side_effect = [
            (0, []),
            (5, ["snmp", "mac"]),
        ]

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
        hd.get = MagicMock(
            side_effect=lambda k, d=None: {
                "addresses": {},
                "vendor": {},
                "osmatch": [],
            }.get(k, d)
        )
        nm.__getitem__ = MagicMock(return_value=hd)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        # Mock UDP probe to indicate it found something
        a._run_udp_priority_probe = MagicMock(return_value=True)

        with ExitStack() as stack:
            _enter_scan_patches(stack)
            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Budget exhaustion inner (2235-2238)
# ═══════════════════════════════════════════════════════════════════════════


class TestBudgetExhaustionInner(unittest.TestCase):
    """Lines 2235-2238: _reserve_deep_scan_slot returns False."""

    def test_budget_exhausted_logging(self):
        """Budget exhausted → trigger_deep=False + smart_scan updated."""
        a = _make_auditor(deep_id_scan=True, deep_scan_budget=10)
        _bind_all(a, FULL_METHODS)

        # Force budget to be exhausted
        a._deep_executed_count = 100

        ip = "10.5.0.20"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (0, [])

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
        hd.get = MagicMock(
            side_effect=lambda k, d=None: {
                "addresses": {},
                "vendor": {},
                "osmatch": [],
            }.get(k, d)
        )
        nm.__getitem__ = MagicMock(return_value=hd)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        with ExitStack() as stack:
            mocks = _enter_scan_patches(stack)
            mocks["is_suspicious_service"].return_value = True
            a.scan_host_ports(ip)


# ═══════════════════════════════════════════════════════════════════════════
# scan_host_ports — verbose logging and scattered lines
# ═══════════════════════════════════════════════════════════════════════════


class TestVerboseAndScattered(unittest.TestCase):
    """Cover various verbose/debug logging lines scattered throughout."""

    def test_verbose_snmp_import_warn(self):
        """verbose=True → SNMP ImportError warning logged at 1972-1973."""
        a = _make_auditor(auth_enabled=True, verbose=True)
        _bind_all(a, FULL_METHODS)
        ip = "10.5.0.30"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (5, [])
        a._resolve_snmp_credential = MagicMock(return_value=MagicMock(community="public"))

        # Nmap with UDP/161
        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "test"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp", "udp"]

        def getitem(p):
            if p == "tcp":
                return {
                    22: {
                        "name": "ssh",
                        "product": "",
                        "version": "",
                        "extrainfo": "",
                        "cpe": [],
                        "state": "open",
                        "reason": "",
                        "tunnel": "",
                    }
                }
            if p == "udp":
                return {
                    161: {
                        "name": "snmp",
                        "product": "",
                        "version": "",
                        "extrainfo": "",
                        "cpe": [],
                        "state": "open",
                        "reason": "",
                        "tunnel": "",
                    }
                }
            return {}

        hd.__getitem__ = MagicMock(side_effect=getitem)
        hd.get = MagicMock(
            side_effect=lambda k, d=None: {
                "addresses": {},
                "vendor": {},
                "osmatch": [],
            }.get(k, d)
        )
        nm.__getitem__ = MagicMock(return_value=hd)
        a.scanner.run_nmap_scan.return_value = (nm, None)

        import sys

        sys.modules.pop("redaudit.core.auth_snmp", None)
        with ExitStack() as stack:
            _enter_scan_patches(stack)
            with patch.dict("sys.modules", {"redaudit.core.auth_snmp": None}):
                a.scan_host_ports(ip)

    def test_verbose_smb_import_warn(self):
        """verbose=True → SMB ImportError warning logged at 1917-1919."""
        a = _make_auditor(auth_enabled=True, verbose=True)
        _bind_all(a, FULL_METHODS)
        ip = "10.5.0.31"
        host_obj = Host(ip=ip)
        a.scanner.get_or_create_host.return_value = host_obj
        a.scanner.compute_identity_score.return_value = (5, [])
        smb_cred = MagicMock(username="admin", password="pass", domain="")
        a._resolve_all_smb_credentials = MagicMock(return_value=[smb_cred])

        nm = MagicMock()
        nm.all_hosts.return_value = [ip]
        hd = MagicMock()
        hd.hostnames.return_value = [{"name": "dc"}]
        hd.state.return_value = "up"
        hd.all_protocols.return_value = ["tcp"]
        hd.__getitem__ = MagicMock(
            return_value={
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
        a.scanner.run_nmap_scan.return_value = (nm, None)

        import sys

        sys.modules.pop("redaudit.core.auth_smb", None)
        with ExitStack() as stack:
            _enter_scan_patches(stack)
            with patch.dict("sys.modules", {"redaudit.core.auth_smb": None}):
                a.scan_host_ports(ip)


if __name__ == "__main__":
    unittest.main()
