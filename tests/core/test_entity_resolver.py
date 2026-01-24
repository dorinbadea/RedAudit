#!/usr/bin/env python3
"""
RedAudit - Tests for entity_resolver module
v2.9 Entity Resolution for multi-interface hosts
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.entity_resolver import (
    normalize_hostname,
    extract_identity_fingerprint,
    determine_interface_type,
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

    def test_reconcile_complex_group(self):
        hosts = [
            {
                "ip": "10.0.0.1",
                "hostname": "host-a",
                "deep_scan": {"mac_address": "AA:BB:CC:00:00:01"},
            },
            {
                "ip": "10.0.0.2",
                "hostname": "host-a",
                "deep_scan": {"mac_address": "AA:BB:CC:00:00:01"},
            },
        ]
        assets = reconcile_assets(hosts)
        self.assertEqual(len(assets), 1)
        self.assertEqual(len(assets[0]["interfaces"]), 2)

    def test_extract_identity_fingerprint_deep_scan_nb(self):
        # Case: NetBIOS name in command output
        host = {"deep_scan": {"commands": [{"stdout": "NetBIOS name: MY-HOST-NAME"}]}}
        self.assertEqual(extract_identity_fingerprint(host), "my-host-name")
        # Case: Computer name
        host = {"deep_scan": {"commands": [{"stdout": "Computer name: COMP-NAME-123"}]}}
        self.assertEqual(extract_identity_fingerprint(host), "comp-name-123")

    def test_extract_identity_fingerprint_dns_fallback(self):
        # DNS reverse fallback
        host = {"dns": {"reverse": ["reverse.local"]}}
        self.assertEqual(extract_identity_fingerprint(host), "reverse")
        # phase0 fallback
        host = {"phase0_enrichment": {"dns_reverse": "phase0.local"}}
        self.assertEqual(extract_identity_fingerprint(host), "phase0")

    def test_determine_interface_type_branches(self):
        # Virtual
        self.assertEqual(determine_interface_type("02:42:AC:11:22:33", ""), "Virtual")
        # Ethernet
        self.assertEqual(determine_interface_type("00:1B:21:AA:BB:CC", ""), "Ethernet")
        # WiFi
        self.assertEqual(determine_interface_type("AC:22:0B:00:11:22", ""), "WiFi")
        # Unknown MAC
        self.assertEqual(determine_interface_type("11:22:33:44:55:66", ""), "Unknown")

    def test_guess_asset_type_vpn_heuristics(self):
        # Heuristic 1: MAC match with gateway
        host = {
            "ip": "10.0.0.5",
            "_gateway_ip": "10.0.0.1",
            "_gateway_mac": "AA:BB:CC:DD:EE:FF",
            "deep_scan": {"mac_address": "AA:BB:CC:DD:EE:FF"},
        }
        self.assertEqual(guess_asset_type(host), "vpn")
        # Heuristic 2: VPN ports
        host = {"ports": [{"port": 1194, "protocol": "udp"}]}
        self.assertEqual(guess_asset_type(host), "vpn")
        # Heuristic 4: Firewall vendor + web ports
        host = {"deep_scan": {"vendor": "Fortinet"}, "ports": [{"port": 443}]}
        self.assertEqual(guess_asset_type(host), "firewall")

    def test_guess_asset_type_media_extra(self):
        # Media signal via ports 8008
        host = {"ports": [{"port": 8008}]}
        self.assertEqual(guess_asset_type(host), "media")

    def test_guess_asset_type_os_extra(self):
        # Trigger 'server' by using port 22
        host = {"ports": [{"port": 22}]}
        self.assertEqual(guess_asset_type(host), "server")

    def test_hostname_regex_branch(self):
        # We need to mock load_device_hostname_hints to return a regex hint
        with patch("redaudit.core.entity_resolver.load_device_hostname_hints") as mock_hints:
            mock_hints.return_value = [{"device_type": "printer", "hostname_regex": [r"prn-.*"]}]
            host = {"hostname": "prn-office-1"}
            self.assertEqual(guess_asset_type(host), "printer")

    def test_reconcile_logging_branch(self):
        # Trigger the log branch in reconcile_assets
        # Mocking log objects
        from unittest.mock import MagicMock

        mock_logger = MagicMock()
        # To trigger multi_interface_count > 0, we need two hosts with SAME fingerprint
        hosts = [
            {"ip": "10.0.0.1", "hostname": "same-host"},
            {"ip": "10.0.0.2", "hostname": "same-host"},
        ]
        reconcile_assets(hosts, logger=mock_logger)
        # Check if info was called (multi_interface_count > 0 uses info, not debug)
        self.assertTrue(mock_logger.info.called)

    def test_create_unified_asset_empty_list(self):
        self.assertEqual(create_unified_asset([]), {})

    def test_guess_asset_type_iot_branch(self):
        # Trigger 'iot' via short ports list + 80/443
        host = {"ports": [{"port": 80}]}  # len is 1
        self.assertEqual(guess_asset_type(host), "iot")

    def test_guess_asset_type_samsung_media(self):
        # Samsung without mobile indicators = media
        host = {"deep_scan": {"vendor": "Samsung"}, "hostname": "some-samsung-device"}
        self.assertEqual(guess_asset_type(host), "media")

    def test_guess_asset_type_agentless_ap(self):
        host = {"agentless_fingerprint": {"device_type": "ap"}}
        self.assertEqual(guess_asset_type(host), "router")

    def test_guess_asset_type_hints_iot(self):
        host = {"device_type_hints": ["iot_lighting"]}
        self.assertEqual(guess_asset_type(host), "iot")

    def test_determine_interface_type_ethernet(self):
        # Ethernet prefix
        self.assertEqual(determine_interface_type("00:0C:29:11:22:33", ""), "Virtual")
        self.assertEqual(determine_interface_type("00:1B:21:11:22:33", ""), "Ethernet")


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


def test_guess_asset_type_hostname_regex_error_ignored():
    host = {"hostname": "vpn-host", "ports": []}
    hints = [{"device_type": "vpn", "hostname_regex": ["["]}]
    with patch("redaudit.core.entity_resolver.load_device_hostname_hints", return_value=hints):
        assert guess_asset_type(host) == "unknown"


def test_guess_asset_type_media_signal_from_http_title():
    host = {"agentless_fingerprint": {"http_title": "Chromecast"}}
    assert guess_asset_type(host) == "media"


def test_guess_asset_type_vpn_vendor_ports():
    host = {
        "deep_scan": {"vendor": "Cisco"},
        "ports": [{"port": 500}, {"port": 21}, {"port": 22}, {"port": 23}],
    }
    assert guess_asset_type(host) == "vpn"


def test_guess_asset_type_mobile_media_override():
    host = {"hostname": "mobile-tv", "agentless_fingerprint": {"http_title": "ssdp"}}
    hints = [
        {
            "device_type": "mobile",
            "hostname_keywords": ["mobile"],
            "hostname_keywords_media_override": ["tv"],
        }
    ]
    with patch("redaudit.core.entity_resolver.load_device_hostname_hints", return_value=hints):
        assert guess_asset_type(host) == "media"


def test_guess_asset_type_smart_tv_hostname():
    host = {"hostname": "livingroom-tv"}
    hints = [{"device_type": "smart_tv", "hostname_keywords": ["tv"]}]
    with patch("redaudit.core.entity_resolver.load_device_hostname_hints", return_value=hints):
        assert guess_asset_type(host) == "media"


def test_guess_asset_type_device_type_hints_branches():
    assert guess_asset_type({"device_type_hints": ["router"]}) == "router"
    assert guess_asset_type({"device_type_hints": ["printer"]}) == "printer"
    assert guess_asset_type({"device_type_hints": ["mobile"]}) == "mobile"
    assert guess_asset_type({"device_type_hints": ["smart_tv"]}) == "media"
    assert guess_asset_type({"device_type_hints": ["hypervisor"]}) == "server"


def test_guess_asset_type_vendor_sercomm_media_and_router():
    host_media = {"deep_scan": {"vendor": "Sercomm"}, "ports": [{"port": 8008}]}
    assert guess_asset_type(host_media) == "media"

    host_router = {"deep_scan": {"vendor": "Sercomm"}, "ports": []}
    assert guess_asset_type(host_router) == "router"


def test_guess_asset_type_ports_server_branch():
    host = {"ports": [{"port": 80}, {"port": 443}, {"port": 8080}, {"port": 8443}]}
    assert guess_asset_type(host) == "server"
