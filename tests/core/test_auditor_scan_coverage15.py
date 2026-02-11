"""
Coverage push #15 for auditor_scan.py — targeting deep nested logic.
Focus:
1. _apply_net_discovery_identity: nested topology/interfaces fallback.
2. _extract_mdns_name: exception handling.
3. _lookup_topology_identity: vendor filtering.
"""

import unittest
from unittest.mock import MagicMock

from redaudit.core.auditor_scan import AuditorScan


def _make_auditor(**overrides):
    a = MagicMock()
    a.config = {
        "scan_mode": "quick",
        "deep_id_scan": True,
    }
    a.config.update(overrides)
    a.logger = MagicMock()
    a.ui = MagicMock()
    a.results = {}
    a.scanner = MagicMock()
    return a


def _bind(aud, names):
    for n in names:
        setattr(aud, n, getattr(AuditorScan, n).__get__(aud, AuditorScan))


class TestApplyNetDiscoveryIdentity(unittest.TestCase):
    def test_apply_identity_from_topology_interface_arp(self):
        """Lines 571-580: Extract MAC/Vendor from topology interfaces."""
        a = _make_auditor()
        _bind(a, ["_apply_net_discovery_identity"])

        # Structure: results["pipeline"]["topology"]["interfaces"][0]["arp"]["hosts"][0]
        a.results = {
            "pipeline": {
                "topology": {
                    "interfaces": [
                        {
                            "arp": {
                                "hosts": [
                                    {
                                        "ip": "10.0.0.1",
                                        "mac": "AA:BB:CC:DD:EE:FF",
                                        "vendor": "Cisco",
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }

        host_rec = {"ip": "10.0.0.1"}
        a._apply_net_discovery_identity(host_rec)

        deep = host_rec.get("deep_scan", {})
        self.assertEqual(deep.get("mac_address"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(deep.get("vendor"), "Cisco")

    def test_apply_identity_from_topology_neighbor_cache(self):
        """Lines 584-587: Extract MAC from neighbor_cache fallback."""
        a = _make_auditor()
        _bind(a, ["_apply_net_discovery_identity"])

        # Structure: results["pipeline"]["topology"]["interfaces"][0]["neighbor_cache"]["entries"][0]
        a.results = {
            "pipeline": {
                "topology": {
                    "interfaces": [
                        {
                            "neighbor_cache": {
                                "entries": [{"ip": "10.0.0.1", "mac": "11:22:33:44:55:66"}]
                            }
                        }
                    ]
                }
            }
        }

        host_rec = {"ip": "10.0.0.1"}
        a._apply_net_discovery_identity(host_rec)

        deep = host_rec.get("deep_scan", {})
        self.assertEqual(deep.get("mac_address"), "11:22:33:44:55:66")


class TestExtractMdnsException(unittest.TestCase):
    def test_extract_mdns_exception(self):
        """Lines 756-758: Handle decode exception."""
        a = _make_auditor()
        _bind(a, ["_extract_mdns_name"])

        # Pass non-bytes object that mocks decode to raise Exception
        bad_obj = MagicMock()
        bad_obj.decode.side_effect = Exception("Decode failed")

        # Call static method from class to avoid incorrect binding
        res = AuditorScan._extract_mdns_name(bad_obj)
        self.assertEqual(res, "")


class TestLookupTopologyIdentity(unittest.TestCase):
    def test_lookup_topology_unknown_vendor(self):
        """Line 530: Filter 'unknown' vendor."""
        a = _make_auditor()
        _bind(a, ["_lookup_topology_identity"])

        a.results = {
            "topology": {
                "interfaces": [
                    {
                        "arp": {
                            "hosts": [
                                {"ip": "10.0.0.1", "mac": "AA:BB:CC", "vendor": "Unknown Vendor"}
                            ]
                        }
                    }
                ]
            }
        }

        mac, vendor = a._lookup_topology_identity("10.0.0.1")
        self.assertEqual(mac, "AA:BB:CC")
        self.assertIsNone(vendor)


if __name__ == "__main__":
    unittest.main()
