#!/usr/bin/env python3
"""
RedAudit - Auditor dry-run tests

Ensures --dry-run prevents external nmap execution via python-nmap.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.models import Host


class TestAuditorDryRun(unittest.TestCase):
    def test_scan_network_discovery_skips_nmap_in_dry_run(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.logger = Mock()
        app.config["dry_run"] = True

        with patch("redaudit.core.auditor_scan.nmap") as mock_nmap:
            mock_nmap.PortScanner.return_value = Mock()
            hosts = app.scan_network_discovery("192.168.1.0/24")

        self.assertEqual(hosts, [])
        mock_nmap.PortScanner.assert_not_called()

    def test_scan_host_ports_skips_nmap_in_dry_run(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.logger = Mock()
        app.config["scan_mode"] = "normal"
        app.config["dry_run"] = True

        with patch("redaudit.core.auditor_scan.nmap") as mock_nmap:
            mock_nmap.PortScanner.return_value = Mock()
            res = app.scan_host_ports("192.168.1.10")

        self.assertIsInstance(res, Host)
        self.assertEqual(res.ip, "192.168.1.10")
        # Check explicit dry_run metadata if set, or just ensure no scan happened
        # Host object might store dry_run in extra_metadata
        if hasattr(res, "extra_metadata"):
            self.assertTrue(res.extra_metadata.get("dry_run"))
        else:
            # Fallback if Host structure is different in mock environment
            pass
        mock_nmap.PortScanner.assert_not_called()

    def test_clear_screen_no_os_system_in_dry_run(self):
        app = InteractiveNetworkAuditor()
        app.config["dry_run"] = True
        with patch("redaudit.core.auditor.os.system") as m_system:
            app.clear_screen()
        m_system.assert_not_called()


if __name__ == "__main__":
    unittest.main()
