#!/usr/bin/env python3
"""
RedAudit - Tests for entity_resolver module
v2.9 Entity Resolution for multi-interface hosts
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.entity_resolver import (
    normalize_hostname,
    extract_identity_fingerprint,
    create_unified_asset,
    guess_asset_type,
    _derive_asset_name,
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
        host = {"hostname": "router.local", "ports": []}
        self.assertEqual(guess_asset_type(host), "router")

    def test_guess_asset_type_workstation(self):
        """Test workstation type detection."""
        host = {"hostname": "msi-laptop", "ports": [], "deep_scan": {}}
        self.assertEqual(guess_asset_type(host), "workstation")

    def test_guess_asset_type_mobile(self):
        """Test mobile device detection."""
        host = {"hostname": "iphone", "ports": []}
        self.assertEqual(guess_asset_type(host), "mobile")

    def test_guess_asset_type_switch_from_http_title(self):
        """Test switch detection from agentless HTTP title hints."""
        host = {
            "hostname": "",
            "ports": [],
            "deep_scan": {"vendor": "Zyxel Communications"},
            "agentless_fingerprint": {"http_title": "GS1200-5"},
        }
        self.assertEqual(guess_asset_type(host), "switch")

    def test_guess_asset_type_router_from_http_title_keywords(self):
        """Test router detection from generic HTTP title keywords."""
        host = {
            "hostname": "",
            "ports": [],
            "agentless_fingerprint": {"http_title": "Home Gateway Login"},
        }
        self.assertEqual(guess_asset_type(host), "router")

    def test_guess_asset_type_router_from_default_gateway_flag(self):
        """Test router detection from default gateway flag."""
        host = {"hostname": "", "ports": [], "is_default_gateway": True}
        self.assertEqual(guess_asset_type(host), "router")

    def test_guess_asset_type_media_from_cast(self):
        """Test media device detection from cast service fingerprints."""
        host = {
            "hostname": "",
            "ports": [
                {"port": 8008, "service": "http", "product": "Google Chromecast httpd"},
                {"port": 8009, "service": "castv2", "product": "Ninja Sphere Chromecast driver"},
            ],
            "deep_scan": {"os_detected": "Android 10 - 12 (Linux 4.14 - 4.19)"},
        }
        self.assertEqual(guess_asset_type(host), "media")

    def test_guess_asset_type_media_over_router_hint(self):
        """Media signals should override generic router hints."""
        host = {
            "hostname": "",
            "ports": [
                {"port": 8008, "service": "http", "product": "Google Chromecast httpd"},
                {"port": 8009, "service": "castv2", "product": "Ninja Sphere Chromecast driver"},
            ],
            "device_type_hints": ["router"],
            "deep_scan": {"vendor": "Sagemcom Broadband SAS"},
        }
        self.assertEqual(guess_asset_type(host), "media")

    def test_guess_asset_type_server_from_juice_shop_title(self):
        """Web apps with known titles should resolve to server."""
        host = {
            "hostname": "",
            "ports": [{"port": 3000, "service": "http"}],
            "agentless_fingerprint": {"http_title": "OWASP Juice Shop"},
        }
        self.assertEqual(guess_asset_type(host), "server")

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

    def test_create_unified_single_host_uses_agentless_title(self):
        """Test unified asset uses HTTP title when hostname is missing."""
        host = {
            "ip": "192.168.1.20",
            "hostname": "",
            "status": "up",
            "ports": [],
            "deep_scan": {"vendor": "Zyxel Communications"},
            "agentless_fingerprint": {"http_title": "GS1200-5"},
        }
        result = create_unified_asset([host])

        self.assertEqual(result["asset_name"], "Zyxel Communications GS1200-5")

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


def test_create_unified_asset_vendor_fallback():
    host = {
        "ip": "1.2.3.4",
        "deep_scan": {
            "mac_address": "00:11:22:33:44:55",
            "vendor": "Some Strange Vendor Name That is Long",
        },
    }
    asset = create_unified_asset([host, host])
    assert asset["interfaces"][0]["type"] == "Some Strange Vendor "


def test_guess_asset_type_android_fallback():
    host = {"hostname": "android-device", "ports": []}
    assert guess_asset_type(host) == "mobile"


def test_guess_asset_type_agentless_types():
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "switch"}}) == "switch"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "printer"}}) == "printer"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "smart_tv"}}) == "media"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "media"}}) == "media"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "iot"}}) == "iot"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "smart_device"}}) == "iot"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "nas"}}) == "server"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "bmc"}}) == "server"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "hypervisor"}}) == "server"


def test_guess_asset_type_iot_hint():
    host = {"device_type_hints": ["iot"]}
    assert guess_asset_type(host) == "iot"


def test_guess_asset_type_switch_hint():
    host = {"agentless_fingerprint": {"http_title": "Managed Switch"}}
    assert guess_asset_type(host) == "switch"


def test_guess_asset_type_os_fingerprints():
    assert guess_asset_type({"os_detected": "Android 10"}) == "mobile"
    assert guess_asset_type({"os_detected": "iOS 14"}) == "mobile"
    assert guess_asset_type({"os_detected": "iPhone OS"}) == "mobile"


def test_guess_asset_type_vendor_patterns():
    assert guess_asset_type({"deep_scan": {"vendor": "Apple Inc."}}) == "workstation"
    assert guess_asset_type({"deep_scan": {"vendor": "Tuya Smart"}}) == "iot"
    assert guess_asset_type({"deep_scan": {"vendor": "Google LLC"}}) == "smart_device"


def test_guess_asset_type_port_patterns():
    assert guess_asset_type({"ports": [{"port": 80}]}) == "iot"
    assert (
        guess_asset_type({"ports": [{"port": 80}, {"port": 443}, {"port": 22}, {"port": 21}]})
        == "server"
    )


def test_derive_asset_name_no_vendor():
    host = {"agentless_fingerprint": {"http_title": "Some Title"}}
    assert _derive_asset_name(host) == "Some Title"


def test_reconcile_assets_logging():
    host1 = {"ip": "1.2.3.4", "hostname": "host-a"}
    host2 = {"ip": "1.2.3.5", "hostname": "host-a"}
    logger = MagicMock()
    unified = reconcile_assets([host1, host2], logger=logger)
    assert len(unified) == 1
    logger.info.assert_called()


def test_guess_asset_type_workstation_msi_intel():
    """Test Workstation detection for common PC vendors (MSI, Intel, Dell)."""
    assert guess_asset_type({"deep_scan": {"vendor": "Micro-Star International"}}) == "workstation"
    assert guess_asset_type({"deep_scan": {"vendor": "Intel Corp"}}) == "workstation"
    assert guess_asset_type({"deep_scan": {"vendor": "Dell Inc."}}) == "workstation"
    assert guess_asset_type({"deep_scan": {"vendor": "HP Inc."}}) == "workstation"
