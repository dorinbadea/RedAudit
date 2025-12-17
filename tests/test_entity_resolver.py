#!/usr/bin/env python3
"""
RedAudit - Tests for entity_resolver module
v2.9 Entity Resolution for multi-interface hosts
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.entity_resolver import (
    normalize_hostname,
    extract_identity_fingerprint,
    create_unified_asset,
    guess_asset_type,
    reconcile_assets,
)


class TestEntityResolver(unittest.TestCase):
    """Tests for entity resolution and asset reconciliation."""

    def test_normalize_hostname_simple(self):
        """Test basic hostname normalization."""
        self.assertEqual(normalize_hostname("MSI-Laptop"), "msi-laptop")
        self.assertEqual(normalize_hostname("  Test  "), "test")

    def test_normalize_hostname_domain_suffix(self):
        """Test hostname normalization with domain suffixes."""
        self.assertEqual(normalize_hostname("mypc.fritz.box"), "mypc")
        self.assertEqual(normalize_hostname("server.local"), "server")
        self.assertEqual(normalize_hostname("device.lan"), "device")

    def test_normalize_hostname_empty(self):
        """Test empty hostname handling."""
        self.assertEqual(normalize_hostname(""), "")
        self.assertEqual(normalize_hostname(None), "")

    def test_extract_fingerprint_from_hostname(self):
        """Test identity extraction from hostname."""
        host = {"hostname": "msi.fritz.box", "ip": "192.168.1.10"}
        result = extract_identity_fingerprint(host)
        self.assertEqual(result, "msi")

    def test_extract_fingerprint_no_identity(self):
        """Test that None is returned when no identity found."""
        host = {"ip": "192.168.1.10", "hostname": ""}
        result = extract_identity_fingerprint(host)
        self.assertIsNone(result)

    def test_extract_fingerprint_from_dns_reverse(self):
        """Test identity extraction from DNS reverse lookup."""
        host = {"ip": "192.168.1.10", "hostname": "", "dns": {"reverse": ["server.local"]}}
        result = extract_identity_fingerprint(host)
        self.assertEqual(result, "server")

    def test_guess_asset_type_router(self):
        """Test router type detection."""
        host = {"hostname": "fritz.box", "ports": []}
        self.assertEqual(guess_asset_type(host), "router")

    def test_guess_asset_type_workstation(self):
        """Test workstation type detection."""
        host = {"hostname": "msi-laptop", "ports": [], "deep_scan": {}}
        self.assertEqual(guess_asset_type(host), "workstation")

    def test_guess_asset_type_mobile(self):
        """Test mobile device detection."""
        host = {"hostname": "iphone", "ports": []}
        self.assertEqual(guess_asset_type(host), "mobile")

    def test_create_unified_single_host(self):
        """Test unified asset creation for single host."""
        host = {
            "ip": "192.168.1.10",
            "hostname": "test-host",
            "status": "up",
            "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
        }
        result = create_unified_asset([host])

        self.assertEqual(result["asset_name"], "test-host")
        self.assertEqual(len(result["interfaces"]), 1)
        self.assertEqual(result["interfaces"][0]["ip"], "192.168.1.10")
        self.assertEqual(len(result["consolidated_ports"]), 1)

    def test_create_unified_multi_interface(self):
        """Test unified asset creation for multi-interface host."""
        hosts = [
            {
                "ip": "192.168.1.10",
                "hostname": "msi.fritz.box",
                "status": "up",
                "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
                "deep_scan": {"mac_address": "D8:43:AE:00:00:01", "vendor": "Micro-Star"},
            },
            {
                "ip": "192.168.1.15",
                "hostname": "msi.fritz.box",
                "status": "up",
                "ports": [{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
                "deep_scan": {"mac_address": "10:91:D1:00:00:02", "vendor": "Intel Corporate"},
            },
        ]
        result = create_unified_asset(hosts)

        # Should merge into single asset with 2 interfaces
        self.assertEqual(len(result["interfaces"]), 2)
        self.assertEqual(len(result["source_ips"]), 2)
        # Should consolidate ports (2 unique ports)
        self.assertEqual(len(result["consolidated_ports"]), 2)
        # Should have interface count
        self.assertEqual(result["interface_count"], 2)

    def test_reconcile_groups_by_hostname(self):
        """Test that reconcile groups hosts by hostname."""
        hosts = [
            {"ip": "192.168.1.10", "hostname": "device-a.fritz.box", "ports": []},
            {"ip": "192.168.1.11", "hostname": "device-b.fritz.box", "ports": []},
            {"ip": "192.168.1.12", "hostname": "device-a.fritz.box", "ports": []},  # Same as first
        ]

        result = reconcile_assets(hosts)

        # Should have 2 unified assets (device-a with 2 interfaces, device-b with 1)
        self.assertEqual(len(result), 2)

        # Find device-a and check it has 2 source IPs
        device_a = next((a for a in result if "device-a" in a.get("asset_name", "")), None)
        self.assertIsNotNone(device_a)
        self.assertEqual(len(device_a["source_ips"]), 2)

    def test_reconcile_empty_list(self):
        """Test reconcile with empty list."""
        result = reconcile_assets([])
        self.assertEqual(result, [])

    def test_reconcile_ungrouped_hosts(self):
        """Test that hosts without identity stay separate."""
        hosts = [
            {"ip": "192.168.1.10", "hostname": "", "ports": []},
            {"ip": "192.168.1.11", "hostname": "", "ports": []},
        ]

        result = reconcile_assets(hosts)

        # Each should be its own asset
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
