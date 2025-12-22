#!/usr/bin/env python3
"""
RedAudit - Network Module Tests
Tests for network detection functionality.
"""

import sys
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.network import (
    detect_interface_type,
    detect_networks_fallback,
    detect_networks_netifaces,
    detect_all_networks,
    find_interface_for_ip,
    get_neighbor_mac,
)


class TestNetworkDetection(unittest.TestCase):
    """Tests for network detection module."""

    def test_detect_interface_type_ethernet(self):
        """Test Ethernet interface detection."""
        self.assertEqual(detect_interface_type("eth0"), "Ethernet")
        self.assertEqual(detect_interface_type("enp0s3"), "Ethernet")
        self.assertEqual(detect_interface_type("eno1"), "Ethernet")

    def test_detect_interface_type_wifi(self):
        """Test Wi-Fi interface detection."""
        self.assertEqual(detect_interface_type("wlan0"), "Wi-Fi")
        self.assertEqual(detect_interface_type("wlp2s0"), "Wi-Fi")

    def test_detect_interface_type_vpn(self):
        """Test VPN interface detection."""
        self.assertEqual(detect_interface_type("tun0"), "VPN")
        self.assertEqual(detect_interface_type("tap0"), "VPN")

    def test_detect_interface_type_other(self):
        """Test unknown interface detection."""
        self.assertEqual(detect_interface_type("docker0"), "Other")
        self.assertEqual(detect_interface_type("br-abc123"), "Other")
        self.assertEqual(detect_interface_type("lo"), "Other")

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_detect_networks_fallback(self, mock_run):
        """Test fallback network detection via ip command."""
        # v3.0: Function now calls both IPv4 and IPv6 commands
        mock_run.side_effect = [
            Mock(  # IPv4 call
                stdout="2: eth0    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n"
                "3: wlan0   inet 10.0.0.50/16 brd 10.0.255.255 scope global wlan0\n",
                stderr="",
                returncode=0,
            ),
            Mock(stdout="", stderr="", returncode=0),  # IPv6 call
        ]

        nets = detect_networks_fallback()

        self.assertEqual(len(nets), 2)
        self.assertEqual(nets[0]["interface"], "eth0")
        self.assertEqual(nets[0]["ip"], "192.168.1.100")
        self.assertEqual(nets[0]["type"], "Ethernet")
        self.assertEqual(nets[1]["interface"], "wlan0")
        self.assertEqual(nets[1]["type"], "Wi-Fi")

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_detect_networks_fallback_excludes_docker(self, mock_run):
        """Test that Docker interfaces are excluded."""
        mock_run.side_effect = [
            Mock(  # IPv4 call
                stdout="2: eth0    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n"
                "3: docker0 inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n",
                stderr="",
                returncode=0,
            ),
            Mock(stdout="", stderr="", returncode=0),  # IPv6 call
        ]

        nets = detect_networks_fallback()

        self.assertEqual(len(nets), 1)
        self.assertEqual(nets[0]["interface"], "eth0")

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_detect_networks_fallback_empty(self, mock_run):
        """Test fallback with no valid networks."""
        mock_run.side_effect = [
            Mock(stdout="", stderr="", returncode=0),
            Mock(stdout="", stderr="", returncode=0),
        ]

        nets = detect_networks_fallback()

        self.assertEqual(len(nets), 0)

    def test_detect_networks_netifaces_ipv4_ipv6(self):
        class _DummyNetifaces:
            AF_INET = 2
            AF_INET6 = 10

            @staticmethod
            def interfaces():
                return ["eth0", "wlan0", "lo"]

            @staticmethod
            def ifaddresses(iface):
                if iface == "eth0":
                    return {
                        _DummyNetifaces.AF_INET: [
                            {"addr": "192.168.1.10", "netmask": "255.255.255.0"}
                        ],
                        _DummyNetifaces.AF_INET6: [{"addr": "fe80::1"}],
                    }
                if iface == "wlan0":
                    return {
                        _DummyNetifaces.AF_INET6: [
                            {"addr": "2001:db8::1%wlan0", "netmask": "64"}
                        ]
                    }
                return {}

        with patch.dict(sys.modules, {"netifaces": _DummyNetifaces}):
            nets = detect_networks_netifaces(include_ipv6=True)

        self.assertEqual(len(nets), 2)
        versions = {entry["ip_version"] for entry in nets}
        self.assertEqual(versions, {4, 6})

    def test_detect_networks_netifaces_ipv4_only(self):
        class _DummyNetifaces:
            AF_INET = 2
            AF_INET6 = 10

            @staticmethod
            def interfaces():
                return ["eth0"]

            @staticmethod
            def ifaddresses(_iface):
                return {
                    _DummyNetifaces.AF_INET: [
                        {"addr": "10.0.0.5", "netmask": "255.255.255.0"}
                    ],
                    _DummyNetifaces.AF_INET6: [{"addr": "2001:db8::2", "netmask": "64"}],
                }

        with patch.dict(sys.modules, {"netifaces": _DummyNetifaces}):
            nets = detect_networks_netifaces(include_ipv6=False)

        self.assertEqual(len(nets), 1)
        self.assertEqual(nets[0]["ip_version"], 4)

    def test_detect_networks_netifaces_missing(self):
        real_import = __import__

        def _fake_import(name, *args, **kwargs):
            if name == "netifaces":
                raise ImportError("missing")
            return real_import(name, *args, **kwargs)

        messages = []

        def _printer(msg, level=None):
            messages.append((msg, level))

        with patch("builtins.__import__", side_effect=_fake_import):
            nets = detect_networks_netifaces(print_fn=_printer)

        self.assertEqual(nets, [])
        self.assertTrue(messages)
        self.assertEqual(messages[0][1], "WARNING")

    def test_find_interface_for_ip_found(self):
        """Test finding interface for a known IP."""
        networks = [
            {"interface": "eth0", "network": "192.168.1.0/24"},
            {"interface": "wlan0", "network": "10.0.0.0/16"},
        ]

        result = find_interface_for_ip("192.168.1.50", networks)
        self.assertEqual(result, "eth0")

        result = find_interface_for_ip("10.0.5.100", networks)
        self.assertEqual(result, "wlan0")

    def test_find_interface_for_ip_not_found(self):
        """Test finding interface for unknown IP."""
        networks = [
            {"interface": "eth0", "network": "192.168.1.0/24"},
        ]

        result = find_interface_for_ip("172.16.0.1", networks)
        self.assertIsNone(result)

    def test_find_interface_for_ip_invalid(self):
        """Test finding interface with invalid IP."""
        networks = [{"interface": "eth0", "network": "192.168.1.0/24"}]

        result = find_interface_for_ip("not-an-ip", networks)
        self.assertIsNone(result)

    def test_get_neighbor_mac_parses_output(self):
        output = "10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        with patch("redaudit.core.network.CommandRunner") as mock_runner:
            mock_runner.return_value.run.return_value = SimpleNamespace(
                stdout=output, stderr=""
            )
            self.assertEqual(get_neighbor_mac("10.0.0.1"), "aa:bb:cc:dd:ee:ff")

    def test_get_neighbor_mac_returns_none_on_empty(self):
        with patch("redaudit.core.network.CommandRunner") as mock_runner:
            mock_runner.return_value.run.return_value = SimpleNamespace(stdout="", stderr="")
            self.assertIsNone(get_neighbor_mac("10.0.0.1"))

    def test_get_neighbor_mac_invalid_input(self):
        self.assertIsNone(get_neighbor_mac(""))
        self.assertIsNone(get_neighbor_mac(None))


if __name__ == "__main__":
    unittest.main()
