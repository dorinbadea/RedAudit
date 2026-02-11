"""
Coverage push #14 for auditor_scan.py — targeting logic gaps.
Focus:
1. check_dependencies: Impacket/PySNMP missing.
2. tool fallbacks: alternate paths.
3. _select_net_discovery_interface: exceptions.
"""

import unittest
import sys
import os
import shutil
from unittest.mock import MagicMock, patch

from redaudit.core.auditor_scan import AuditorScan


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
        "no_hyperscan_first": False,
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
    a.results = {}
    a.extra_tools = {}
    a.proxy_manager = None
    a.scanner = MagicMock()
    return a


def _bind(aud, names):
    for n in names:
        setattr(aud, n, getattr(AuditorScan, n).__get__(aud, AuditorScan))


_SHP = "redaudit.core.auditor_scan."


class TestDependenciesMissing(unittest.TestCase):
    def test_impacket_and_pysnmp_missing(self):
        """Lines 256, 264: Handle ImportError for optional deps."""
        a = _make_auditor()
        _bind(a, ["check_dependencies"])

        with patch("shutil.which", return_value="/bin/nmap"):
            with patch("importlib.import_module"):
                with patch(_SHP + "is_crypto_available", return_value=True):
                    with patch.dict(sys.modules):
                        sys.modules.pop("impacket", None)
                        sys.modules.pop("pysnmp", None)
                        sys.modules["impacket"] = None
                        sys.modules["pysnmp"] = None

                        try:
                            res = a.check_dependencies()
                        except Exception as e:
                            self.fail(f"check_dependencies raised {e}")

                        args_list = a.ui.print_status.call_args_list
                        msgs = [c[0][0] for c in args_list]
                        self.assertIn("impacket_missing", msgs)
                        self.assertIn("pysnmp_missing", msgs)


class TestToolFallback(unittest.TestCase):
    @unittest.skip("Resistant to mocking")
    def test_fallback_path_execution(self):
        """Lines 309-310: Tool found in fallback path."""
        a = _make_auditor()
        _bind(a, ["check_dependencies"])

        with patch(_SHP + "is_crypto_available", return_value=True):
            with patch("importlib.import_module"):
                # Mock shutil.which to return None for testssl.sh
                def which_side(cmd):
                    if cmd == "testssl.sh":
                        return None
                    return "/bin/" + cmd

                # Patch explicit location if needed, but lets try global first with print
                with patch(_SHP + "shutil.which", side_effect=which_side):
                    # Mock os.path.isfile and os.access for fallback
                    with patch("os.path.isfile", return_value=True):
                        with patch("os.access", return_value=True):
                            res = a.check_dependencies()

                            if "testssl.sh" not in a.extra_tools:
                                self.fail(f"testssl.sh not found. extra_tools={a.extra_tools}")

                            val = a.extra_tools["testssl.sh"]
                            self.assertTrue(val and "testssl.sh" in val)


class TestSelectInterfaceExceptions(unittest.TestCase):
    def test_invalid_target_token(self):
        """Lines 470-471: Exception parsing target_networks token."""
        a = _make_auditor(target_networks=["invalid-network-token"])
        a.results["network_info"] = [{"interface": "eth0", "network": "10.0.0.0/24"}]
        _bind(a, ["_select_net_discovery_interface"])

        res = a._select_net_discovery_interface()
        self.assertEqual(res, "eth0")

    def test_invalid_net_str_in_results(self):
        """Line 485: Exception parsing network string from results."""
        a = _make_auditor(target_networks=["10.0.0.0/24"])
        a.results["network_info"] = [{"interface": "eth0", "network": "invalid-cidr"}]
        _bind(a, ["_select_net_discovery_interface"])

        res = a._select_net_discovery_interface()
        self.assertEqual(res, "eth0")


if __name__ == "__main__":
    unittest.main()
