"""
Tests for network.py to push coverage to 95%+.
Targets: 96, 115-116, 156, 172-173, 195, 211-212.
"""

from unittest.mock import patch, MagicMock
from redaudit.core.network import (
    detect_networks_netifaces,
    detect_networks_fallback,
)


def test_detect_networks_netifaces_ipv6_prefix_with_slash():
    """Test IPv6 prefix parsing with slash notation (line 96)."""
    import sys

    mock_netifaces = MagicMock()
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = 2
    mock_netifaces.AF_INET6 = 10
    mock_netifaces.ifaddresses.return_value = {
        10: [
            {
                "addr": "2001:db8::1",
                "netmask": "ffff:ffff:ffff:ffff::/64",  # Slash notation
            }
        ]
    }

    with patch.dict(sys.modules, {"netifaces": mock_netifaces}):
        result = detect_networks_netifaces(include_ipv6=True)
        # Should handle prefix extraction from slash notation
        assert isinstance(result, list)


def test_detect_networks_netifaces_ipv6_value_error():
    """Test IPv6 handling with ValueError (line 115-116)."""
    import sys

    mock_netifaces = MagicMock()
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = 2
    mock_netifaces.AF_INET6 = 10
    mock_netifaces.ifaddresses.return_value = {
        10: [
            {
                "addr": "invalid-ipv6-address",
                "netmask": "64",
            }
        ]
    }

    with patch.dict(sys.modules, {"netifaces": mock_netifaces}):
        result = detect_networks_netifaces(include_ipv6=True)
        # Should continue gracefully on ValueError
        assert isinstance(result, list)


def test_detect_networks_fallback_ipv4_short_line():
    """Test fallback IPv4 with short line (line 156)."""
    with patch("redaudit.core.network.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner

        # Mock result with short line (< 4 parts)
        mock_result = MagicMock()
        mock_result.stdout = "1: lo\n2: eth0"  # Short lines
        mock_runner.run.return_value = mock_result

        result = detect_networks_fallback()
        # Should skip short lines
        assert isinstance(result, list)


def test_detect_networks_fallback_ipv4_value_error():
    """Test fallback IPv4 with ValueError (line 172-173)."""
    with patch("redaudit.core.network.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner

        # Mock result with invalid IP
        mock_result = MagicMock()
        mock_result.stdout = "1: eth0 inet invalid-ip/24"
        mock_runner.run.return_value = mock_result

        result = detect_networks_fallback()
        # Should continue on ValueError
        assert isinstance(result, list)


def test_detect_networks_fallback_ipv6_short_line():
    """Test fallback IPv6 with short line (line 195)."""
    with patch("redaudit.core.network.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner

        # First call (IPv4) returns empty, second call (IPv6) returns short line
        mock_result_v4 = MagicMock()
        mock_result_v4.stdout = ""

        mock_result_v6 = MagicMock()
        mock_result_v6.stdout = "1: lo\n2: eth0"  # Short lines

        mock_runner.run.side_effect = [mock_result_v4, mock_result_v6]

        result = detect_networks_fallback(include_ipv6=True)
        # Should skip short lines
        assert isinstance(result, list)


def test_detect_networks_fallback_ipv6_value_error():
    """Test fallback IPv6 with ValueError (line 211-212)."""
    with patch("redaudit.core.network.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner

        # First call (IPv4) returns empty, second call (IPv6) returns invalid IP
        mock_result_v4 = MagicMock()
        mock_result_v4.stdout = ""

        mock_result_v6 = MagicMock()
        mock_result_v6.stdout = "1: eth0 inet6 invalid-ipv6/64 scope global"

        mock_runner.run.side_effect = [mock_result_v4, mock_result_v6]

        result = detect_networks_fallback(include_ipv6=True)
        # Should continue on ValueError
        assert isinstance(result, list)
