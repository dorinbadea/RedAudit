"""
Tests for topology.py to push coverage to 90%+.
Targets uncovered lines: 34-45, 53, 65-66, 73-74, 78-79, 83-84, 108, 113, 125, 134-140, etc.
"""

from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.topology import (
    _parse_ip_route,
    _extract_default_gateway,
    _parse_arp_scan,
    _parse_ip_neigh,
    _parse_vlan_ids_from_ip_link,
    _parse_vlan_ids_from_tcpdump,
    _extract_lldp_neighbors,
    _networks_from_route_table,
)


# -------------------------------------------------------------------------
# _parse_ip_route Tests (lines 48-87)
# -------------------------------------------------------------------------


def test_parse_ip_route_default_with_via():
    """Test _parse_ip_route parses default route with via."""
    stdout = "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
    routes = _parse_ip_route(stdout)
    assert len(routes) == 1
    assert routes[0]["dst"] == "default"
    assert routes[0]["via"] == "192.168.1.1"
    assert routes[0]["dev"] == "eth0"
    assert routes[0]["metric"] == 100


def test_parse_ip_route_network_with_src():
    """Test _parse_ip_route parses network route with src."""
    stdout = "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100"
    routes = _parse_ip_route(stdout)
    assert len(routes) == 1
    assert routes[0]["dst"] == "192.168.1.0/24"
    assert routes[0]["dev"] == "eth0"
    assert routes[0]["src"] == "192.168.1.100"


def test_parse_ip_route_empty_line():
    """Test _parse_ip_route skips empty lines."""
    stdout = "\n  \ndefault via 192.168.1.1 dev eth0\n"
    routes = _parse_ip_route(stdout)
    assert len(routes) == 1


def test_parse_ip_route_missing_via():
    """Test _parse_ip_route handles default without via."""
    stdout = "default dev eth0"
    routes = _parse_ip_route(stdout)
    assert len(routes) == 1
    assert routes[0]["dst"] == "default"
    assert "via" not in routes[0]


def test_parse_ip_route_via_index_error():
    """Test _parse_ip_route handles via at end of line."""
    stdout = "default via"  # Missing gateway after via
    routes = _parse_ip_route(stdout)
    assert len(routes) == 1
    assert "via" not in routes[0]


def test_parse_ip_route_dev_index_error():
    """Test _parse_ip_route handles dev at end of line."""
    stdout = "192.168.1.0/24 dev"
    routes = _parse_ip_route(stdout)
    assert len(routes) == 1
    assert "dev" not in routes[0]


def test_parse_ip_route_src_index_error():
    """Test _parse_ip_route handles src at end of line."""
    stdout = "192.168.1.0/24 dev eth0 src"
    routes = _parse_ip_route(stdout)
    assert len(routes) == 1
    assert "src" not in routes[0]


def test_parse_ip_route_metric_invalid():
    """Test _parse_ip_route handles invalid metric value."""
    stdout = "default via 192.168.1.1 metric abc"
    routes = _parse_ip_route(stdout)
    assert len(routes) == 1
    assert "metric" not in routes[0]


# -------------------------------------------------------------------------
# _parse_arp_scan Tests (lines 101-117)
# -------------------------------------------------------------------------


def test_parse_arp_scan_valid():
    """Test _parse_arp_scan parses valid output."""
    stdout = """Interface: eth0, type: EN10MB
192.168.1.1\t00:11:22:33:44:55\tCisco Systems
192.168.1.2\taa:bb:cc:dd:ee:ff\tTP-Link Technologies
"""
    hosts = _parse_arp_scan(stdout)
    assert len(hosts) == 2
    assert hosts[0]["ip"] == "192.168.1.1"
    assert hosts[0]["mac"] == "00:11:22:33:44:55"
    assert hosts[0]["vendor"] == "Cisco Systems"


def test_parse_arp_scan_skip_headers():
    """Test _parse_arp_scan skips header lines."""
    stdout = """Interface: eth0
Starting arp-scan 1.9
192.168.1.1\t00:11:22:33:44:55\tRouter
Ending arp-scan
"""
    hosts = _parse_arp_scan(stdout)
    assert len(hosts) == 1


def test_parse_arp_scan_skip_warnings():
    """Test _parse_arp_scan skips warning lines."""
    stdout = """WARNING: Cannot connect to socket
#Comment line
packets received
192.168.1.1\t00:11:22:33:44:55\tDevice
"""
    hosts = _parse_arp_scan(stdout)
    assert len(hosts) == 1


def test_parse_arp_scan_invalid_format():
    """Test _parse_arp_scan skips invalid format lines."""
    stdout = """192.168.1.1 invalid format
192.168.1.2\t00:11:22:33:44:55\tValid Device
"""
    hosts = _parse_arp_scan(stdout)
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "192.168.1.2"


# -------------------------------------------------------------------------
# _parse_ip_neigh Tests (lines 120-145)
# -------------------------------------------------------------------------


def test_parse_ip_neigh_valid():
    """Test _parse_ip_neigh parses valid output."""
    stdout = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    neigh = _parse_ip_neigh(stdout)
    assert len(neigh) == 1
    assert neigh[0]["ip"] == "192.168.1.1"
    assert neigh[0]["dev"] == "eth0"
    assert neigh[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert neigh[0]["state"] == "REACHABLE"


def test_parse_ip_neigh_empty_line():
    """Test _parse_ip_neigh skips empty lines."""
    stdout = "\n192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n  \n"
    neigh = _parse_ip_neigh(stdout)
    assert len(neigh) == 1


def test_parse_ip_neigh_dev_index_error():
    """Test _parse_ip_neigh handles dev at end of line."""
    stdout = "192.168.1.1 dev"
    neigh = _parse_ip_neigh(stdout)
    assert len(neigh) == 1
    assert "dev" not in neigh[0] or neigh[0].get("dev") is None


def test_parse_ip_neigh_lladdr_index_error():
    """Test _parse_ip_neigh handles lladdr at end of line."""
    stdout = "192.168.1.1 dev eth0 lladdr"
    neigh = _parse_ip_neigh(stdout)
    assert len(neigh) == 1
    assert "mac" not in neigh[0] or neigh[0].get("mac") is None


# -------------------------------------------------------------------------
# _parse_vlan_ids Tests (lines 148-175)
# -------------------------------------------------------------------------


def test_parse_vlan_ids_from_ip_link():
    """Test _parse_vlan_ids_from_ip_link parses VLAN IDs."""
    stdout = "eth0.100: vlan id 100 protocol 802.1Q"
    vlan_ids = _parse_vlan_ids_from_ip_link(stdout)
    assert 100 in vlan_ids


def test_parse_vlan_ids_from_ip_link_multiple():
    """Test _parse_vlan_ids_from_ip_link parses multiple VLANs."""
    stdout = """eth0.100: vlan id 100
eth0.200: vlan protocol 802.1Q id 200"""
    vlan_ids = _parse_vlan_ids_from_ip_link(stdout)
    assert 100 in vlan_ids
    assert 200 in vlan_ids


def test_parse_vlan_ids_from_ip_link_invalid():
    """Test _parse_vlan_ids_from_ip_link handles invalid ID."""
    stdout = "vlan id 5000"  # Out of range
    vlan_ids = _parse_vlan_ids_from_ip_link(stdout)
    assert 5000 not in vlan_ids


def test_parse_vlan_ids_from_ip_link_exception():
    """Test _parse_vlan_ids_from_ip_link skip non-numeric."""
    stdout = "vlan id abc"
    vlan_ids = _parse_vlan_ids_from_ip_link(stdout)
    assert vlan_ids == []


def test_parse_vlan_ids_from_tcpdump():
    """Test _parse_vlan_ids_from_tcpdump parses VLANs from traffic."""
    stdout = "12:00:00.000000 eth0, length 64, vlan 100, 802.1Q"
    vlan_ids = _parse_vlan_ids_from_tcpdump(stdout)
    assert 100 in vlan_ids


def test_parse_vlan_ids_from_tcpdump_out_of_range():
    """Test _parse_vlan_ids_from_tcpdump ignores out of range."""
    stdout = "vlan 9999"
    vlan_ids = _parse_vlan_ids_from_tcpdump(stdout)
    assert 9999 not in vlan_ids


def test_parse_vlan_ids_from_tcpdump_exception():
    """Test _parse_vlan_ids_from_tcpdump handles parse exception."""
    stdout = "vlan xyz"
    vlan_ids = _parse_vlan_ids_from_tcpdump(stdout)
    assert vlan_ids == []


# -------------------------------------------------------------------------
# _extract_lldp_neighbors Tests (lines 178-226)
# -------------------------------------------------------------------------


def test_extract_lldp_neighbors_valid():
    """Test _extract_lldp_neighbors extracts neighbor info."""
    lldp_json = {
        "lldp": {
            "interface": {
                "eth0": {
                    "chassis": {
                        "name": "switch01",
                        "descr": "Cisco Switch",
                        "mgmt-ip": "192.168.1.1",
                        "id": {"value": "aa:bb:cc:dd:ee:ff"},
                    },
                    "port": {
                        "id": {"value": "Gi0/1"},
                        "descr": "Port 1",
                    },
                }
            }
        }
    }
    neighbors = _extract_lldp_neighbors(lldp_json, "eth0")
    assert len(neighbors) == 1
    assert neighbors[0]["chassis"]["name"] == "switch01"
    assert neighbors[0]["port"]["id"] == "Gi0/1"


def test_extract_lldp_neighbors_list_format():
    """Test _extract_lldp_neighbors handles list format."""
    lldp_json = {
        "lldp": {
            "interface": {
                "eth0": [
                    {
                        "chassis": {"name": "switch01"},
                        "port": {"id": {"value": "Gi0/1"}},
                    },
                    {
                        "chassis": {"name": "switch02"},
                        "port": {"id": {"value": "Gi0/2"}},
                    },
                ]
            }
        }
    }
    neighbors = _extract_lldp_neighbors(lldp_json, "eth0")
    assert len(neighbors) == 2


def test_extract_lldp_neighbors_missing_interface():
    """Test _extract_lldp_neighbors returns empty for missing interface."""
    lldp_json = {"lldp": {"interface": {"eth1": {}}}}
    neighbors = _extract_lldp_neighbors(lldp_json, "eth0")
    assert neighbors == []


def test_extract_lldp_neighbors_empty_entry():
    """Test _extract_lldp_neighbors filters empty entries."""
    lldp_json = {
        "lldp": {
            "interface": {
                "eth0": {
                    "chassis": {},
                    "port": {},
                }
            }
        }
    }
    neighbors = _extract_lldp_neighbors(lldp_json, "eth0")
    assert neighbors == []


def test_extract_lldp_neighbors_exception():
    """Test _extract_lldp_neighbors handles malformed JSON."""
    lldp_json = {"lldp": None}
    neighbors = _extract_lldp_neighbors(lldp_json, "eth0")
    assert neighbors == []


# -------------------------------------------------------------------------
# _networks_from_route_table Tests (lines 229-249)
# -------------------------------------------------------------------------


def test_networks_from_route_table_valid():
    """Test _networks_from_route_table extracts networks."""
    routes = [
        {"dst": "default", "via": "192.168.1.1"},
        {"dst": "192.168.1.0/24"},
        {"dst": "10.0.0.0/8"},
    ]
    nets = _networks_from_route_table(routes)
    assert "192.168.1.0/24" in nets
    assert "10.0.0.0/8" in nets


def test_networks_from_route_table_skips_default():
    """Test _networks_from_route_table skips default route."""
    routes = [{"dst": "default", "via": "192.168.1.1"}]
    nets = _networks_from_route_table(routes)
    assert nets == []


def test_networks_from_route_table_skips_no_cidr():
    """Test _networks_from_route_table skips routes without CIDR."""
    routes = [{"dst": "192.168.1.1"}]  # No /prefix
    nets = _networks_from_route_table(routes)
    assert nets == []


def test_networks_from_route_table_invalid_network():
    """Test _networks_from_route_table skips invalid networks."""
    routes = [{"dst": "invalid/24"}]
    nets = _networks_from_route_table(routes)
    assert nets == []


def test_networks_from_route_table_deduplicates():
    """Test _networks_from_route_table deduplicates networks."""
    routes = [
        {"dst": "192.168.1.0/24"},
        {"dst": "192.168.1.0/24"},
    ]
    nets = _networks_from_route_table(routes)
    assert nets == ["192.168.1.0/24"]


# -------------------------------------------------------------------------
# _extract_default_gateway Tests (lines 90-98)
# -------------------------------------------------------------------------


def test_extract_default_gateway():
    """Test _extract_default_gateway extracts gateway info."""
    routes = [
        {"dst": "default", "via": "192.168.1.1", "dev": "eth0", "metric": 100},
    ]
    gw = _extract_default_gateway(routes)
    assert gw["ip"] == "192.168.1.1"
    assert gw["interface"] == "eth0"
    assert gw["metric"] == 100


def test_extract_default_gateway_none():
    """Test _extract_default_gateway returns None when no default."""
    routes = [{"dst": "192.168.1.0/24"}]
    gw = _extract_default_gateway(routes)
    assert gw is None


# -------------------------------------------------------------------------
# Additional edge case tests
# -------------------------------------------------------------------------


def test_parse_ip_route_none_stdout():
    """Test _parse_ip_route handles None input."""
    routes = _parse_ip_route(None)
    assert routes == []


def test_parse_arp_scan_none_stdout():
    """Test _parse_arp_scan handles None input."""
    hosts = _parse_arp_scan(None)
    assert hosts == []


def test_parse_ip_neigh_none_stdout():
    """Test _parse_ip_neigh handles None input."""
    neigh = _parse_ip_neigh(None)
    assert neigh == []


def test_parse_vlan_ids_from_ip_link_none():
    """Test _parse_vlan_ids_from_ip_link handles None."""
    vlan_ids = _parse_vlan_ids_from_ip_link(None)
    assert vlan_ids == []


def test_parse_vlan_ids_from_tcpdump_none():
    """Test _parse_vlan_ids_from_tcpdump handles None."""
    vlan_ids = _parse_vlan_ids_from_tcpdump(None)
    assert vlan_ids == []
