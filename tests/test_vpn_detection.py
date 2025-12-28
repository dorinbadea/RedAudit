#!/usr/bin/env python3
"""
Tests for VPN interface detection heuristics.
v3.9.6: Tests the three VPN detection patterns in entity_resolver.guess_asset_type()
"""

import pytest

from redaudit.core.entity_resolver import guess_asset_type


class TestVPNDetection:
    """Test VPN interface detection heuristics."""

    def test_same_mac_as_gateway_different_ip(self):
        """Heuristic 1: Same MAC as gateway + different IP = VPN virtual IP."""
        host = {
            "ip": "192.168.178.201",
            "_gateway_ip": "192.168.178.1",
            "_gateway_mac": "d4:24:dd:07:7c:c5",
            "deep_scan": {"mac_address": "d4:24:dd:07:7c:c5"},
            "ports": [],
        }
        assert guess_asset_type(host) == "vpn"

    def test_same_mac_same_ip_is_router(self):
        """Gateway itself should be router, not VPN."""
        host = {
            "ip": "192.168.178.1",
            "_gateway_ip": "192.168.178.1",
            "_gateway_mac": "d4:24:dd:07:7c:c5",
            "deep_scan": {"mac_address": "d4:24:dd:07:7c:c5"},
            "ports": [],
            "is_default_gateway": True,
        }
        # Gateway is classified as router first
        assert guess_asset_type(host) == "router"

    def test_different_mac_not_vpn(self):
        """Different MAC should not trigger VPN detection."""
        host = {
            "ip": "192.168.178.50",
            "_gateway_ip": "192.168.178.1",
            "_gateway_mac": "d4:24:dd:07:7c:c5",
            "deep_scan": {"mac_address": "aa:bb:cc:dd:ee:ff"},
            "ports": [],
        }
        # Should not be VPN
        assert guess_asset_type(host) != "vpn"

    def test_vpn_service_ports_ipsec(self):
        """Heuristic 2: IPSec ports (500, 4500)."""
        host = {
            "ip": "10.0.0.1",
            "hostname": "",
            "ports": [
                {"port": 500, "protocol": "udp", "service": "isakmp"},
                {"port": 4500, "protocol": "udp", "service": "ipsec-nat-t"},
            ],
            "deep_scan": {},
        }
        assert guess_asset_type(host) == "vpn"

    def test_vpn_service_ports_openvpn(self):
        """Heuristic 2: OpenVPN port (1194)."""
        host = {
            "ip": "10.0.0.2",
            "hostname": "",
            "ports": [{"port": 1194, "protocol": "udp", "service": "openvpn"}],
            "deep_scan": {},
        }
        assert guess_asset_type(host) == "vpn"

    def test_vpn_service_ports_wireguard(self):
        """Heuristic 2: WireGuard port (51820)."""
        host = {
            "ip": "10.0.0.3",
            "hostname": "",
            "ports": [{"port": 51820, "protocol": "udp", "service": "wireguard"}],
            "deep_scan": {},
        }
        assert guess_asset_type(host) == "vpn"

    def test_vpn_hostname_patterns(self):
        """Heuristic 3: VPN hostname patterns."""
        patterns = ["vpn.example.com", "ipsec-gateway", "wireguard-server", "tunnel001"]
        for hostname in patterns:
            host = {
                "ip": "10.0.0.10",
                "hostname": hostname,
                "ports": [],
                "deep_scan": {},
            }
            assert guess_asset_type(host) == "vpn", f"Failed for hostname: {hostname}"

    def test_openvpn_in_hostname(self):
        """Heuristic 3: OpenVPN in hostname."""
        host = {
            "ip": "10.0.0.11",
            "hostname": "openvpn-server.local",
            "ports": [],
            "deep_scan": {},
        }
        assert guess_asset_type(host) == "vpn"

    def test_vpn_ports_with_many_other_ports_not_vpn(self):
        """VPN ports with many other ports = likely not a dedicated VPN endpoint."""
        host = {
            "ip": "10.0.0.20",
            "hostname": "",
            "ports": [
                {"port": 500, "protocol": "udp"},
                {"port": 4500, "protocol": "udp"},
                {"port": 22, "protocol": "tcp"},
                {"port": 25, "protocol": "tcp"},
                {"port": 110, "protocol": "tcp"},
                {"port": 143, "protocol": "tcp"},
            ],
            "deep_scan": {},
        }
        # Too many non-VPN ports, should not be classified as VPN
        assert guess_asset_type(host) != "vpn"

    def test_mac_format_normalization(self):
        """Test MAC address format normalization (dashes vs colons)."""
        host = {
            "ip": "192.168.178.201",
            "_gateway_ip": "192.168.178.1",
            "_gateway_mac": "D4-24-DD-07-7C-C5",  # Windows format with dashes
            "deep_scan": {"mac_address": "d4:24:dd:07:7c:c5"},  # Linux format with colons
            "ports": [],
        }
        assert guess_asset_type(host) == "vpn"
