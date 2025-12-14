#!/usr/bin/env python3
"""
RedAudit - Topology Discovery Tests
Copyright (C) 2025  Dorin Badea
GPLv3 License

Unit tests for redaudit/core/topology.py (best-effort topology discovery).
"""

import os
import sys
import json
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.topology import discover_topology


class TestTopologyDiscovery(unittest.TestCase):
    def test_discover_topology_parses_outputs(self):
        route_out = "\n".join(
            [
                "default via 192.168.1.1 dev eth0 proto dhcp metric 100",
                "10.0.0.0/8 via 192.168.1.254 dev eth0 metric 200",
                "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100",
            ]
        )

        arp_out = "\n".join(
            [
                "Interface: eth0, datalink type: EN10MB (Ethernet)",
                "Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)",
                "192.168.1.1\tAA:BB:CC:DD:EE:FF\tExampleVendor",
                "Ending arp-scan 1.10.0: 256 hosts scanned in 2.000 seconds (1.28 hosts/sec). 1 responded",
            ]
        )

        neigh_out = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"

        ip_link_out = "\n".join(
            [
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000",
                "    link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff",
                "    vlan protocol 802.1Q id 10 <REORDER_HDR>",
            ]
        )

        tcpdump_vlan_out = "12:34:56.789012 vlan 20, p 0, ethertype IPv4, length 60: 192.168.1.2 > 192.168.1.255: UDP\n"

        lldp_json_obj = {
            "lldp": {
                "interface": {
                    "eth0": {
                        "chassis": {
                            "name": "sw1",
                            "descr": "Example Switch",
                            "mgmt-ip": "192.168.1.2",
                            "id": {"value": "aa:bb:cc:dd:ee:ff"},
                        },
                        "port": {
                            "id": {"value": "Gi1/0/1"},
                            "descr": "Uplink",
                        },
                    }
                }
            }
        }
        lldp_out = json.dumps(lldp_json_obj)

        tcpdump_cdp_out = "\n".join(
            [
                "12:00:00.000000 aa:bb:cc:dd:ee:01 > 01:00:0c:cc:cc:cc, ethertype Unknown (0x2000), length 102: CDP",
                "12:00:01.000000 aa:bb:cc:dd:ee:01 > 01:00:0c:cc:cc:cc, ethertype Unknown (0x2000), length 102: CDP",
            ]
        )

        def fake_which(name: str):
            return f"/usr/bin/{name}"

        def fake_run_cmd(args, timeout_s, logger=None):
            if args == ["ip", "route", "show"]:
                return 0, route_out, ""
            if args == ["lldpctl", "-f", "json"]:
                return 0, lldp_out, ""
            if args[:4] == ["arp-scan", "--localnet", "--interface", "eth0"]:
                return 0, arp_out, ""
            if args == ["ip", "neigh", "show", "dev", "eth0"]:
                return 0, neigh_out, ""
            if args == ["ip", "-d", "link", "show", "dev", "eth0"]:
                return 0, ip_link_out, ""
            if args[:6] == ["tcpdump", "-nn", "-e", "-i", "eth0", "-c"] and args[-1] == "vlan":
                return 0, tcpdump_vlan_out, ""
            if (
                args[:6] == ["tcpdump", "-nn", "-e", "-i", "eth0", "-c"]
                and args[-1] == "01:00:0c:cc:cc:cc"
            ):
                return 0, tcpdump_cdp_out, ""
            return 1, "", "unexpected command"

        network_info = [
            {
                "interface": "eth0",
                "ip": "192.168.1.100",
                "network": "192.168.1.0/24",
                "hosts_estimated": 256,
            }
        ]

        with patch("redaudit.core.topology.shutil.which", side_effect=fake_which):
            with patch("redaudit.core.topology._run_cmd", side_effect=fake_run_cmd):
                topo = discover_topology(
                    target_networks=["192.168.1.0/24"],
                    network_info=network_info,
                    extra_tools={"tcpdump": "/usr/bin/tcpdump"},
                )

        self.assertTrue(topo.get("enabled"))
        self.assertIn("generated_at", topo)
        self.assertEqual(topo.get("default_gateway", {}).get("ip"), "192.168.1.1")

        self.assertEqual(topo.get("candidate_networks"), ["10.0.0.0/8"])

        interfaces = topo.get("interfaces") or []
        self.assertEqual(len(interfaces), 1)
        iface0 = interfaces[0]
        self.assertEqual(iface0.get("interface"), "eth0")

        vlan_ids = (iface0.get("vlan") or {}).get("ids") or []
        self.assertIn(10, vlan_ids)
        self.assertIn(20, vlan_ids)

        arp_hosts = (iface0.get("arp") or {}).get("hosts") or []
        self.assertEqual(len(arp_hosts), 1)
        self.assertEqual(arp_hosts[0].get("ip"), "192.168.1.1")
        self.assertEqual(arp_hosts[0].get("mac"), "aa:bb:cc:dd:ee:ff")

        lldp_neighbors = (iface0.get("lldp") or {}).get("neighbors") or []
        self.assertEqual(len(lldp_neighbors), 1)
        self.assertEqual((lldp_neighbors[0].get("chassis") or {}).get("name"), "sw1")

        cdp_obs = (iface0.get("cdp") or {}).get("observations") or []
        self.assertTrue(cdp_obs)

    def test_discover_topology_handles_missing_tools(self):
        with patch("redaudit.core.topology.shutil.which", return_value=None):
            topo = discover_topology(target_networks=[], network_info=[], extra_tools={})

        self.assertTrue(topo.get("enabled"))
        self.assertEqual(topo.get("tools", {}).get("ip"), False)
        self.assertIsInstance(topo.get("errors"), list)


if __name__ == "__main__":
    unittest.main()
