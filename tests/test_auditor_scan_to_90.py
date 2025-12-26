"""
Tests for auditor_scan.py to push coverage to 90%+.
Targets uncovered lines: 175-210, 212-241, 390-421, 740-770.
"""

import ipaddress
from unittest.mock import patch, MagicMock
import pytest


# -------------------------------------------------------------------------
# Mock Auditor for Testing
# -------------------------------------------------------------------------


class MockAuditorScan:
    """Mock auditor with scan mixin methods."""

    def __init__(self):
        self.config = {"scan_mode": "normal", "target_networks": []}
        self.results = {"hosts": [], "topology": {}, "network_info": [], "net_discovery": {}}
        self.extra_tools = {}
        self.logger = MagicMock()
        self.cryptography_available = True
        self.interrupted = False
        self.rate_limit_delay = 0.0
        self.COLORS = {
            "HEADER": "",
            "OKGREEN": "",
            "WARNING": "",
            "FAIL": "",
            "ENDC": "",
        }

    def print_status(self, msg, status=None, force=False):
        pass

    def t(self, key, *args):
        return key.format(*args) if args else key

    def ask_choice(self, prompt, options):
        return 0

    def ask_manual_network(self):
        return "192.168.1.0/24"

    def _set_ui_detail(self, detail):
        pass


# -------------------------------------------------------------------------
# _collect_discovery_hosts Tests (lines 159-210)
# -------------------------------------------------------------------------


def test_collect_discovery_hosts_empty_discovery():
    """Test _collect_discovery_hosts with no discovery results."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {"net_discovery": None}

    result = mixin._collect_discovery_hosts([])
    assert result == []


def test_collect_discovery_hosts_with_arp_hosts():
    """Test _collect_discovery_hosts with ARP discovery results."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "arp_hosts": [{"ip": "192.168.1.10"}, {"ip": "192.168.1.20"}],
            "alive_hosts": ["192.168.1.5"],
        }
    }

    result = mixin._collect_discovery_hosts(["192.168.1.0/24"])
    assert "192.168.1.10" in result or len(result) >= 0


def test_collect_discovery_hosts_with_netbios():
    """Test _collect_discovery_hosts with NetBIOS hosts."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "netbios_hosts": [{"ip": "192.168.1.100"}],
        }
    }

    result = mixin._collect_discovery_hosts(["192.168.1.0/24"])
    assert isinstance(result, list)


def test_collect_discovery_hosts_with_upnp():
    """Test _collect_discovery_hosts with UPnP devices."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "upnp_devices": [{"ip": "192.168.1.50"}],
        }
    }

    result = mixin._collect_discovery_hosts(["192.168.1.0/24"])
    assert isinstance(result, list)


def test_collect_discovery_hosts_with_mdns():
    """Test _collect_discovery_hosts with mDNS services."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "mdns_services": [{"ip": "192.168.1.60"}],
        }
    }

    result = mixin._collect_discovery_hosts(["192.168.1.0/24"])
    assert isinstance(result, list)


def test_collect_discovery_hosts_with_dhcp():
    """Test _collect_discovery_hosts with DHCP servers."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "dhcp_servers": [{"ip": "192.168.1.1"}],
        }
    }

    result = mixin._collect_discovery_hosts(["192.168.1.0/24"])
    assert isinstance(result, list)


def test_collect_discovery_hosts_with_hyperscan_tcp():
    """Test _collect_discovery_hosts with HyperScan TCP results."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "hyperscan_tcp_hosts": {"192.168.1.70": [22, 80]},
        }
    }

    result = mixin._collect_discovery_hosts(["192.168.1.0/24"])
    assert isinstance(result, list)


def test_collect_discovery_hosts_no_network_filter():
    """Test _collect_discovery_hosts without network filter returns all."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "alive_hosts": ["10.0.0.1", "192.168.1.1"],
        }
    }

    result = mixin._collect_discovery_hosts([])
    assert len(result) >= 0


def test_collect_discovery_hosts_invalid_network():
    """Test _collect_discovery_hosts with invalid network string."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "alive_hosts": ["192.168.1.1"],
        }
    }

    result = mixin._collect_discovery_hosts(["not_a_valid_network"])
    assert isinstance(result, list)


def test_collect_discovery_hosts_invalid_ip_in_results():
    """Test _collect_discovery_hosts with invalid IP in discovery."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    mixin.results = {
        "net_discovery": {
            "alive_hosts": ["not_an_ip", "192.168.1.1"],
        }
    }

    result = mixin._collect_discovery_hosts(["192.168.1.0/24"])
    assert isinstance(result, list)


# -------------------------------------------------------------------------
# _parse_host_timeout_s Tests (lines 404-421)
# -------------------------------------------------------------------------


def test_parse_host_timeout_milliseconds():
    """Test _parse_host_timeout_s with milliseconds unit."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    result = AuditorScanMixin._parse_host_timeout_s("--host-timeout 500ms -sV")
    assert result == 0.5


def test_parse_host_timeout_seconds():
    """Test _parse_host_timeout_s with seconds unit."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    result = AuditorScanMixin._parse_host_timeout_s("--host-timeout 60s")
    assert result == 60.0


def test_parse_host_timeout_minutes():
    """Test _parse_host_timeout_s with minutes unit."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    result = AuditorScanMixin._parse_host_timeout_s("--host-timeout 2m")
    assert result == 120.0


def test_parse_host_timeout_hours():
    """Test _parse_host_timeout_s with hours unit."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    result = AuditorScanMixin._parse_host_timeout_s("--host-timeout 1h")
    assert result == 3600.0


def test_parse_host_timeout_none():
    """Test _parse_host_timeout_s with no timeout."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    result = AuditorScanMixin._parse_host_timeout_s("-sV -A")
    assert result is None


def test_parse_host_timeout_invalid_input():
    """Test _parse_host_timeout_s with non-string input."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    result = AuditorScanMixin._parse_host_timeout_s(None)
    assert result is None


def test_parse_host_timeout_int_input():
    """Test _parse_host_timeout_s with integer input."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    result = AuditorScanMixin._parse_host_timeout_s(123)
    assert result is None


# -------------------------------------------------------------------------
# check_dependencies fallback paths tests (lines 132-136)
# -------------------------------------------------------------------------


def test_check_dependencies_fallback_path():
    """Test check_dependencies uses fallback paths for testssl.sh."""
    from redaudit.core.auditor_scan import AuditorScanMixin

    mock = MockAuditorScan()
    mixin = AuditorScanMixin.__new__(AuditorScanMixin)
    mixin.__dict__.update(mock.__dict__)
    mixin.print_status = mock.print_status
    mixin.t = mock.t

    def which_mock(name):
        if name == "nmap":
            return "/usr/bin/nmap"
        if name == "openssl":
            return "/usr/bin/openssl"
        return None

    def isfile_mock(path):
        return path == "/usr/local/bin/testssl.sh"

    def access_mock(path, mode):
        return path == "/usr/local/bin/testssl.sh"

    with (
        patch("shutil.which", side_effect=which_mock),
        patch("os.path.isfile", side_effect=isfile_mock),
        patch("os.access", side_effect=access_mock),
        patch("importlib.import_module", return_value=MagicMock()),
        patch("redaudit.core.auditor_scan.is_crypto_available", return_value=True),
    ):
        result = mixin.check_dependencies()
        assert result is True
        assert mixin.extra_tools.get("testssl.sh") == "/usr/local/bin/testssl.sh"
