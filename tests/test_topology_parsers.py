#!/usr/bin/env python3
"""
Extra coverage for topology parsing helpers.
"""

from redaudit.core import topology


def test_parse_ip_route_and_default_gateway():
    output = "\n".join(
        [
            "default via 192.168.1.1 dev eth0 proto dhcp metric 100",
            "10.0.0.0/8 via 192.168.1.254 dev eth0 metric 200",
            "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100",
        ]
    )
    routes = topology._parse_ip_route(output)
    assert routes[0]["dst"] == "default"
    assert routes[0]["via"] == "192.168.1.1"
    gw = topology._extract_default_gateway(routes)
    assert gw["ip"] == "192.168.1.1"
    assert gw["interface"] == "eth0"


def test_parse_arp_scan_and_ip_neigh():
    arp_out = "\n".join(
        [
            "Interface: eth0, datalink type: EN10MB (Ethernet)",
            "192.168.1.1\tAA:BB:CC:DD:EE:FF\tExampleVendor",
        ]
    )
    hosts = topology._parse_arp_scan(arp_out)
    assert hosts[0]["ip"] == "192.168.1.1"
    assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    neigh_out = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
    neigh = topology._parse_ip_neigh(neigh_out)
    assert neigh[0]["ip"] == "192.168.1.1"
    assert neigh[0]["dev"] == "eth0"
    assert neigh[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_parse_vlan_ids():
    ip_link_out = "vlan protocol 802.1Q id 10 <REORDER_HDR>"
    assert topology._parse_vlan_ids_from_ip_link(ip_link_out) == [10]

    tcpdump_out = "12:34:56.789012 vlan 20, p 0, ethertype IPv4"
    assert topology._parse_vlan_ids_from_tcpdump(tcpdump_out) == [20]


def test_extract_lldp_neighbors_and_networks():
    lldp = {
        "lldp": {
            "interface": {
                "eth0": {
                    "chassis": {"name": "sw1", "mgmt-ip": "192.168.1.2", "id": {"value": "aa"}},
                    "port": {"id": {"value": "Gi1/0/1"}},
                }
            }
        }
    }
    neighbors = topology._extract_lldp_neighbors(lldp, "eth0")
    assert neighbors[0]["chassis"]["name"] == "sw1"
    assert neighbors[0]["port"]["id"] == "Gi1/0/1"

    routes = [{"dst": "10.0.0.0/8"}, {"dst": "default"}, {"dst": "192.168.1.0/24"}]
    nets = topology._networks_from_route_table(routes)
    assert nets == ["10.0.0.0/8", "192.168.1.0/24"]
