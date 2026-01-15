#!/usr/bin/env python3
"""
Regression tests for v4.6.33 fixes.
Verifies timeouts and localization updates.
"""

import inspect
import unittest
from unittest.mock import MagicMock, patch

from redaudit.core import net_discovery, hyperscan
from redaudit.utils import i18n


class TestV4_6_33_Regression(unittest.TestCase):

    def test_net_discovery_timeouts_defaults(self):
        """Verify reduced timeouts for Net Discovery protocols (was 30s, now 15s)."""
        # Check function signatures directly for default values
        sig_fping = inspect.signature(net_discovery.fping_sweep)
        self.assertEqual(
            sig_fping.parameters["timeout_s"].default, 15, "fping_sweep timeout should be 15s"
        )

        sig_netbios = inspect.signature(net_discovery.netbios_discover)
        self.assertEqual(
            sig_netbios.parameters["timeout_s"].default,
            15,
            "netbios_discover timeout should be 15s",
        )

        sig_arp = inspect.signature(net_discovery.arp_scan_active)
        self.assertEqual(
            sig_arp.parameters["timeout_s"].default, 15, "arp_scan_active timeout should be 15s"
        )

    def test_hyperscan_timeout_default(self):
        """Verify increased timeout for HyperScan (was 0.5s, now 1.5s)."""
        sig_hs = inspect.signature(hyperscan.hyperscan_full_port_sweep)
        self.assertEqual(
            sig_hs.parameters["timeout"].default,
            1.5,
            "hyperscan_full_port_sweep timeout should be 1.5s",
        )

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_net_discovery_calls_with_correct_timeout(self, mock_which, mock_run):
        """Verify that the functions actually pass the 15s timeout to the runner."""
        mock_which.return_value = "/bin/true"
        mock_run.return_value = (0, "", "")

        # Test fping
        net_discovery.fping_sweep("127.0.0.1")
        # Check call arguments of _run_cmd
        # Signature: _run_cmd(args, timeout_s, logger=None)
        args, _ = mock_run.call_args
        self.assertEqual(args[1], 15, "fping_sweep should pass timeout_s=15 to _run_cmd")

    @patch("redaudit.core.hyperscan.get_text")
    @patch("redaudit.core.hyperscan.detect_preferred_language")
    def test_hyperscan_udp_localization(self, mock_lang, mock_get_text):
        """Verify that UDP probes use localized strings."""
        mock_lang.return_value = "es"
        mock_get_text.side_effect = lambda key, lang, *args: (
            f"Sondas UDP ({args[0]})" if key == "udp_probes_progress" else key
        )

        # Trigger the logic that calls get_text
        # We need to call a function that triggers the "UDP probes" progress update.
        # This is inside hyperscan_full_discovery -> ...
        # But hyperscan_full_discovery is complex.
        # Let's check hyperscan.py to see where `udp_probes_progress` is used.
        # It is used in hyperscan_full_discovery inside the internal _net_progress calls loop.

        # We'll mock the dependencies to isolate the loop logic
        with patch("redaudit.core.hyperscan.hyperscan_arp_aggressive", return_value=[]):
            with patch(
                "redaudit.core.hyperscan.hyperscan_udp_broadcast", return_value=[]
            ) as mock_udp_cast:
                with patch("redaudit.core.hyperscan.hyperscan_tcp_sweep_sync", return_value={}):
                    hyperscan.hyperscan_full_discovery(
                        ["192.168.1.0/24"], include_arp=False, include_udp=True, include_tcp=False
                    )

        # Verify get_text was called with the correct key
        mock_get_text.assert_any_call("udp_probes_progress", "es", "192.168.1.0/24")

    def test_i18n_translation_keys(self):
        """Verify existence of new translation keys in i18n.py."""
        from redaudit.utils.i18n import TRANSLATIONS

        # Check Spanish
        es = TRANSLATIONS["es"]
        self.assertIn("udp_probes_progress", es)
        self.assertEqual(es["udp_probes_progress"], "Sondas UDP ({})")

        # Check "Fichero" update (random spot check)
        self.assertIn("nvd_option_config", es)
        self.assertIn("fichero", es["nvd_option_config"])

        # Check English
        en = TRANSLATIONS["en"]
        self.assertIn("udp_probes_progress", en)
        self.assertIn("parallel", en["hyperscan_start"])  # Check sequential -> parallel fix


if __name__ == "__main__":
    unittest.main()
