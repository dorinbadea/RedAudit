"""Tests for vendor hints module and MAC enrichment."""

from redaudit.utils.vendor_hints import (
    infer_vendor_from_hostname,
    get_best_vendor,
)


class TestVendorHints:
    """Tests for vendor hints utility functions."""

    def test_infer_vendor_from_hostname_msi(self):
        """MSI hostname pattern should return MSI (guess)."""
        assert infer_vendor_from_hostname("msi-Vector-GP78HX.fritz.box") == "MSI (guess)"
        assert infer_vendor_from_hostname("MSI-Laptop") == "MSI (guess)"
        assert infer_vendor_from_hostname("msi_desktop") == "MSI (guess)"

    def test_infer_vendor_from_hostname_apple(self):
        """Apple device hostnames should return Apple (guess)."""
        assert infer_vendor_from_hostname("iPhone-DE-12345") == "Apple (guess)"
        assert infer_vendor_from_hostname("name-with-iphone") == "Apple (guess)"
        assert infer_vendor_from_hostname("iPad-Pro") == "Apple (guess)"
        assert infer_vendor_from_hostname("MacBook-Air") == "Apple (guess)"
        assert infer_vendor_from_hostname("iMac-Work") == "Apple (guess)"

    def test_infer_vendor_from_hostname_fritz(self):
        """FRITZ!Box hostnames should return AVM (guess)."""
        assert infer_vendor_from_hostname("fritz.box") == "AVM (guess)"
        # Note: msi-Vector.fritz.box matches MSI first (first match wins)
        assert infer_vendor_from_hostname("msi-Vector.fritz.box") == "MSI (guess)"
        assert infer_vendor_from_hostname("fritzbox-gateway") == "AVM (guess)"
        assert infer_vendor_from_hostname("router.fritz.box") == "AVM (guess)"

    def test_infer_vendor_from_hostname_wiz(self):
        """WiZ bulb hostnames should return WiZ (guess)."""
        assert infer_vendor_from_hostname("wiz-bulb-123") == "WiZ (guess)"
        assert infer_vendor_from_hostname("wiz_light") == "WiZ (guess)"
        assert infer_vendor_from_hostname("living-room.wiz") == "WiZ (guess)"

    def test_infer_vendor_from_hostname_various(self):
        """Test various device patterns."""
        assert infer_vendor_from_hostname("synology-nas") == "Synology (guess)"
        assert infer_vendor_from_hostname("diskstation") == "Synology (guess)"
        assert infer_vendor_from_hostname("qnap-ts453") == "QNAP (guess)"
        assert infer_vendor_from_hostname("samsung-tv") == "Samsung (guess)"
        assert infer_vendor_from_hostname("hp-printer") == "HP (guess)"
        assert infer_vendor_from_hostname("raspberry-pi-4") == "Raspberry Pi (guess)"

    def test_infer_vendor_from_hostname_no_match(self):
        """Hostnames without known patterns should return None."""
        assert infer_vendor_from_hostname("desktop-abc123") is None
        assert infer_vendor_from_hostname("192-168-1-1") is None
        assert infer_vendor_from_hostname("server01") is None
        assert infer_vendor_from_hostname("") is None
        assert infer_vendor_from_hostname("-") is None
        assert infer_vendor_from_hostname(None) is None

    def test_get_best_vendor_prefers_mac_vendor(self):
        """MAC vendor should be preferred over hostname guess."""
        assert get_best_vendor("Intel Corporation", "msi-Vector") == "Intel Corporation"
        assert get_best_vendor("AVM GmbH", "fritz.box") == "AVM GmbH"

    def test_get_best_vendor_skips_unknown(self):
        """Unknown MAC vendors should fall back to hostname guess."""
        assert get_best_vendor("(Unknown)", "msi-Vector") == "MSI (guess)"
        assert get_best_vendor("Unknown: locally administered", "iPhone") == "Apple (guess)"
        assert get_best_vendor("unknown", "fritz.box") == "AVM (guess)"

    def test_get_best_vendor_fallback(self):
        """Should fall back to hostname guess when no MAC vendor."""
        assert get_best_vendor(None, "msi-Vector") == "MSI (guess)"
        assert get_best_vendor("", "iPhone-xxx") == "Apple (guess)"

    def test_get_best_vendor_allow_guess_false(self):
        """When allow_guess=False, should not use hostname fallback."""
        assert get_best_vendor(None, "msi-Vector", allow_guess=False) is None
        assert get_best_vendor("(Unknown)", "iPhone", allow_guess=False) is None

    def test_get_best_vendor_no_vendor(self):
        """When no vendor available, should return None."""
        assert get_best_vendor(None, "unknown-host") is None
        assert get_best_vendor("", "") is None


class TestMacEnrichmentFromTopology:
    """Tests for MAC enrichment from topology neighbor_cache."""

    def test_apply_net_discovery_identity_uses_neighbor_cache(self):
        """MAC should be enriched from topology neighbor_cache when arp_hosts missing."""
        from unittest.mock import MagicMock
        from redaudit.core.auditor_scan import AuditorScan

        # Create mock auditor
        auditor = MagicMock(spec=AuditorScan)
        auditor.results = {
            "net_discovery": {},  # No arp_hosts data
            "pipeline": {
                "topology": {
                    "interfaces": [
                        {
                            "interface": "eth0",
                            "neighbor_cache": {
                                "entries": [
                                    {
                                        "ip": "192.168.1.100",
                                        "mac": "aa:bb:cc:dd:ee:ff",
                                        "state": "REACHABLE",
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        }

        host_record = {"ip": "192.168.1.100"}

        # Call the method (need to use the real implementation)
        AuditorScan._apply_net_discovery_identity(auditor, host_record)

        # Verify MAC was enriched
        deep_scan = host_record.get("deep_scan", {})
        assert deep_scan.get("mac_address") == "aa:bb:cc:dd:ee:ff"

    def test_apply_net_discovery_identity_prefers_arp_hosts(self):
        """arp_hosts should be preferred over neighbor_cache."""
        from unittest.mock import MagicMock
        from redaudit.core.auditor_scan import AuditorScan

        auditor = MagicMock(spec=AuditorScan)
        auditor.results = {
            "net_discovery": {
                "arp_hosts": [
                    {"ip": "192.168.1.100", "mac": "11:22:33:44:55:66", "vendor": "Acme Inc"}
                ]
            },
            "pipeline": {
                "topology": {
                    "interfaces": [
                        {
                            "neighbor_cache": {
                                "entries": [{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}]
                            }
                        }
                    ]
                }
            },
        }

        host_record = {"ip": "192.168.1.100"}

        AuditorScan._apply_net_discovery_identity(auditor, host_record)

        deep_scan = host_record.get("deep_scan", {})
        # Should use arp_hosts MAC, not neighbor_cache
        assert deep_scan.get("mac_address") == "11:22:33:44:55:66"
        assert deep_scan.get("vendor") == "Acme Inc"
