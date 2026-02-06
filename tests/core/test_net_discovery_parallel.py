import pytest
from unittest.mock import MagicMock, patch
import time
from redaudit.core.net_discovery import discover_networks


# Mock the discovery functions to simulate delay and return dummy data
@pytest.fixture
def mock_discovery_tools():
    with (
        patch("redaudit.core.net_discovery.dhcp_discover") as mock_dhcp,
        patch("redaudit.core.net_discovery.fping_sweep") as mock_fping,
        patch("redaudit.core.net_discovery.netbios_discover") as mock_nb,
        patch("redaudit.core.net_discovery.arp_scan_active") as mock_arp,
        patch("redaudit.core.net_discovery.mdns_discover") as mock_mdns,
        patch("redaudit.core.net_discovery.upnp_discover") as mock_upnp,
        patch("redaudit.core.net_discovery.shutil.which") as mock_which,
    ):

        # Setup mocks
        mock_which.return_value = "/bin/true"  # Tools exist

        # Simulate work with small delays
        def slow_dhcp(*args, **kwargs):
            time.sleep(0.1)
            return {"servers": [{"ip": "1.1.1.1"}], "error": None}

        mock_dhcp.side_effect = slow_dhcp

        def slow_fping(*args, **kwargs):
            time.sleep(0.1)
            return {"alive_hosts": ["1.1.1.2"], "error": None}

        mock_fping.side_effect = slow_fping

        def slow_arp(*args, **kwargs):
            time.sleep(0.1)
            return {"hosts": [{"ip": "1.1.1.3"}], "l2_warnings": 0, "error": None}

        mock_arp.side_effect = slow_arp

        yield {"dhcp": mock_dhcp, "fping": mock_fping, "arp": mock_arp}


def test_parallel_execution_speed(mock_discovery_tools):
    """Verify that execution time is roughly max(protocol_time) not sum(protocol_time)"""
    start = time.time()

    # Run discovery with 3 slow protocols (0.1s each)
    # Sequential ~ 0.3s
    # Parallel ~ 0.1s + overhead
    result = discover_networks(
        target_networks=["192.168.1.0/24"], protocols=["dhcp", "fping", "arp"], logger=MagicMock()
    )

    duration = time.time() - start

    # Should be faster than serial sum (0.3s)
    # We allow some overhead buffer, but 0.25s is safe upper bound for 0.1s tasks
    assert duration < 0.25, f"Execution took {duration}s, expected parallel speed (<0.25s)"

    # Verify results merged correctly
    assert result["dhcp_servers"][0]["ip"] == "1.1.1.1"
    assert "1.1.1.2" in result["alive_hosts"]
    assert result["arp_hosts"][0]["ip"] == "1.1.1.3"


def test_result_aggregation(mock_discovery_tools):
    """Verify thread-safe result merging"""
    result = discover_networks(
        target_networks=["192.168.1.0/24"],
        protocols=["dhcp", "fping", "arp", "mdns", "upnp"],
        logger=MagicMock(),
    )

    # Check keys exist and data is valid
    assert "dhcp_servers" in result
    assert "alive_hosts" in result
    assert "arp_hosts" in result
    assert "mdns_services" in result
    assert "upnp_devices" in result
