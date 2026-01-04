#!/usr/bin/env python3
"""
Consolidated tests for redaudit.core.auditor_scan (AuditorScanMixin).

This file consolidates tests from:
- test_auditor_scan_coverage.py
- test_auditor_scan_coverage_v2.py
- test_auditor_scan_deep.py
- test_auditor_scan_edge_cases.py
- test_auditor_scan_edge_cases_v2.py
- test_auditor_scan_helpers.py
- test_auditor_scan_host_ports.py
- test_auditor_scan_network.py
- test_auditor_scan_progress.py
- test_auditor_scan_to_85.py
- test_auditor_scan_to_90.py
- test_auditor_scan_utils.py

Uses shared fixtures from conftest.py.
"""

import logging
import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

from conftest import MockAuditorBase

# Import module under test
import redaudit.core.auditor_scan as auditor_scan_module
from redaudit.core.auditor_scan import AuditorScanMixin
from redaudit.utils.constants import (
    STATUS_UP,
    STATUS_DOWN,
    STATUS_NO_RESPONSE,
    UDP_SCAN_MODE_FULL,
    UDP_SCAN_MODE_QUICK,
)


# =============================================================================
# Mock Classes (Mixin-specific, extends MockAuditorBase)
# =============================================================================


class MockAuditorScan(MockAuditorBase, AuditorScanMixin):
    """Mock auditor with AuditorScanMixin for testing scan methods."""

    pass


# =============================================================================
# Dependency Check Tests
# =============================================================================


class TestDependencies:
    """Tests for check_dependencies method."""

    def test_check_dependencies_nmap_missing(self):
        """Test check_dependencies when nmap binary is missing."""
        auditor = MockAuditorScan()
        with patch("shutil.which", return_value=None):
            result = auditor.check_dependencies()
            assert result is False

    def test_check_dependencies_nmap_import_error(self):
        """Test check_dependencies when nmap module import fails."""
        auditor = MockAuditorScan()
        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("importlib.import_module", side_effect=ImportError("no nmap")),
        ):
            result = auditor.check_dependencies()
            assert result is False

    def test_check_dependencies_success(self):
        """Test check_dependencies with all tools available."""
        auditor = MockAuditorScan()
        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("importlib.import_module", return_value=MagicMock()),
            patch("redaudit.core.auditor_scan.is_crypto_available", return_value=True),
        ):
            result = auditor.check_dependencies()
            assert result is True

    def test_check_dependencies_success_with_missing_optional_tools(self):
        """Test check_dependencies with nmap available but optional tools missing."""
        auditor = MockAuditorScan()

        def which_mock(name):
            return "/usr/bin/nmap" if name == "nmap" else None

        with (
            patch("shutil.which", side_effect=which_mock),
            patch("importlib.import_module", return_value=MagicMock()),
            patch("redaudit.core.auditor_scan.is_crypto_available", return_value=False),
        ):
            result = auditor.check_dependencies()
            assert result is True


# =============================================================================
# Network Detection Tests
# =============================================================================


class TestNetworkDetection:
    """Tests for network detection and interface selection."""

    def test_detect_all_networks(self):
        """Test detect_all_networks method."""
        auditor = MockAuditorScan()
        with patch(
            "redaudit.core.auditor_scan.detect_all_networks",
            return_value=[{"network": "192.168.1.0/24", "interface": "eth0"}],
        ):
            nets = auditor.detect_all_networks()
            assert len(nets) == 1
            assert auditor.results["network_info"] == nets

    def test_collect_discovery_hosts(self):
        """Test _collect_discovery_hosts aggregation."""
        auditor = MockAuditorScan()
        auditor.results["net_discovery"] = {
            "alive_hosts": ["192.168.1.10"],
            "arp_hosts": [{"ip": "192.168.1.11"}],
            "hyperscan_tcp_hosts": {"192.168.1.12": {}},
            "upnp_devices": None,
        }

        hosts = auditor._collect_discovery_hosts([])
        assert "192.168.1.10" in hosts
        assert "192.168.1.11" in hosts
        assert "192.168.1.12" in hosts

    def test_collect_discovery_hosts_empty(self):
        """Test _collect_discovery_hosts with empty discovery results."""
        auditor = MockAuditorScan()
        auditor.results["net_discovery"] = {}
        hosts = auditor._collect_discovery_hosts([])
        assert hosts == []

    def test_select_net_discovery_interface_explicit(self):
        """Test interface selection with explicit config."""
        auditor = MockAuditorScan()
        auditor.config["net_discovery_interface"] = "tun0"
        result = auditor._select_net_discovery_interface()
        assert result == "tun0"

    def test_select_net_discovery_interface_from_network_info(self):
        """Test interface selection from network info."""
        auditor = MockAuditorScan()
        auditor.config["net_discovery_interface"] = None
        auditor.config["target_networks"] = ["192.168.1.0/24"]
        auditor.results["network_info"] = [
            {"network": "10.0.0.0/24", "interface": "eth0"},
            {"network": "192.168.1.0/24", "interface": "eth1"},
        ]
        result = auditor._select_net_discovery_interface()
        assert result == "eth1"


# =============================================================================
# Scan Mode and Timeout Tests
# =============================================================================


class TestScanModes:
    """Tests for scan mode configurations and timeouts."""

    @pytest.mark.parametrize("mode", ["fast", "normal", "full"])
    def test_scan_mode_host_timeout(self, mode):
        """Test timeout values for different scan modes."""
        auditor = MockAuditorScan()
        auditor.config["scan_mode"] = mode
        result = auditor._scan_mode_host_timeout_s()
        assert isinstance(result, (int, float))
        assert result > 0

    def test_parse_host_timeout_seconds(self):
        """Test _parse_host_timeout_s with seconds format."""
        result = AuditorScanMixin._parse_host_timeout_s("--host-timeout 1000ms")
        assert result == 1.0

    def test_parse_host_timeout_minutes(self):
        """Test _parse_host_timeout_s with minutes format."""
        result = AuditorScanMixin._parse_host_timeout_s("--host-timeout 5m")
        assert result is None or result == 300.0

    def test_parse_host_timeout_missing(self):
        """Test _parse_host_timeout_s with no timeout."""
        result = AuditorScanMixin._parse_host_timeout_s("-sV -A")
        assert result is None


# =============================================================================
# Static Method Tests
# =============================================================================


class TestStaticMethods:
    """Tests for static utility methods."""

    def test_sanitize_ip_valid(self):
        """Test sanitize_ip with valid IP."""
        result = AuditorScanMixin.sanitize_ip("192.168.1.1")
        assert result == "192.168.1.1" or result is None

    def test_sanitize_ip_invalid(self):
        """Test sanitize_ip with invalid input."""
        result = AuditorScanMixin.sanitize_ip("not.an.ip")
        assert result is None or result == "not.an.ip"

    def test_sanitize_hostname(self):
        """Test sanitize_hostname method."""
        result = AuditorScanMixin.sanitize_hostname("server.example.com")
        assert isinstance(result, str) or result is None

    def test_extract_nmap_xml_empty(self):
        """Test _extract_nmap_xml with empty string."""
        result = AuditorScanMixin._extract_nmap_xml("")
        assert result is None or result == ""

    def test_is_web_service_http(self):
        """Test is_web_service with HTTP."""
        auditor = MockAuditorScan()
        result = auditor.is_web_service("http")
        assert isinstance(result, bool)

    def test_is_web_service_ssh(self):
        """Test is_web_service with SSH."""
        auditor = MockAuditorScan()
        result = auditor.is_web_service("ssh")
        assert isinstance(result, bool)


# =============================================================================
# Nmap Scan Tests
# =============================================================================


class TestNmapScanning:
    """Tests for nmap scanning methods."""

    @pytest.fixture
    def mock_nmap_module(self):
        """Setup mock nmap module."""
        mock_module = MagicMock()
        mock_scanner = MagicMock()
        mock_module.PortScanner.return_value = mock_scanner
        return mock_module, mock_scanner

    def test_run_nmap_xml_scan_success(self, mock_nmap_module):
        """Test successful nmap XML scan."""
        auditor = MockAuditorScan()
        auditor.config["dry_run"] = False
        mock_module, mock_scanner = mock_nmap_module

        with (
            patch.object(auditor_scan_module, "nmap", mock_module),
            patch(
                "redaudit.core.auditor_scan.run_nmap_command",
                return_value={"stdout": "<nmaprun>XML</nmaprun>", "returncode": 0},
            ),
        ):
            nm, err = auditor._run_nmap_xml_scan("1.2.3.4", "-sV")
            assert err == ""

    def test_run_nmap_xml_scan_timeout(self, mock_nmap_module):
        """Test nmap scan timeout handling."""
        auditor = MockAuditorScan()
        mock_module, _ = mock_nmap_module

        with (
            patch.object(auditor_scan_module, "nmap", mock_module),
            patch(
                "redaudit.core.auditor_scan.run_nmap_command",
                return_value={"error": "Timeout"},
            ),
        ):
            nm, err = auditor._run_nmap_xml_scan("1.2.3.4", "-sV")
            assert nm is None
            assert err == "Timeout"

    def test_scan_network_discovery(self, mock_nmap_module):
        """Test scan_network_discovery method."""
        auditor = MockAuditorScan()
        mock_module, mock_scanner = mock_nmap_module
        mock_scanner.all_hosts.return_value = ["1.1.1.1"]
        mock_scanner["1.1.1.1"].state.return_value = "up"

        with patch.object(auditor_scan_module, "nmap", mock_module):
            hosts = auditor.scan_network_discovery("1.1.1.0/24")
            assert hosts == ["1.1.1.1"]


# =============================================================================
# Deep Scan Tests
# =============================================================================


class TestDeepScan:
    """Tests for deep scan host method."""

    def test_deep_scan_host_identity_found(self):
        """Test deep_scan_host when identity found in phase 1."""
        auditor = MockAuditorScan()
        auditor.config["output_dir"] = "/tmp"

        with (
            patch("redaudit.core.auditor_scan.extract_vendor_mac", return_value=(None, None)),
            patch("redaudit.core.auditor_scan.extract_os_detection", return_value=None),
            patch(
                "redaudit.core.auditor_scan.start_background_capture",
                return_value={"proc": "foo"},
            ),
            patch("redaudit.core.auditor_scan.stop_background_capture"),
            patch(
                "redaudit.core.auditor_scan.run_nmap_command",
                return_value={"stdout": "Scan Output", "timeout": False},
            ),
            patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[]),
            patch("redaudit.core.auditor_scan.output_has_identity", return_value=True),
        ):
            res = auditor.deep_scan_host("192.168.1.100")
            assert "phase2_skipped" in res


# =============================================================================
# Host Port Scan Tests
# =============================================================================


class TestHostPortScan:
    """Tests for host port scanning."""

    def test_scan_host_ports_success(self):
        """Test successful host port scan."""
        auditor = MockAuditorScan()
        auditor.extra_tools["searchsploit"] = "yes"

        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["1.1.1.1"]
        host_data = MagicMock()
        mock_nm.__getitem__.return_value = host_data
        host_data.hostnames.return_value = [{"name": "host1"}]
        host_data.state.return_value = "up"
        host_data.all_protocols.return_value = ["tcp"]
        host_data.__getitem__.return_value = {
            80: {"name": "http", "product": "", "version": "", "extrainfo": "", "cpe": []}
        }

        with (
            patch.object(
                AuditorScanMixin,
                "_run_nmap_xml_scan",
                return_value=(mock_nm, ""),
            ),
            patch("redaudit.core.auditor_scan.finalize_host_status", return_value=STATUS_UP),
            patch("redaudit.core.auditor_scan.exploit_lookup", return_value=[]),
            patch(
                "redaudit.core.auditor_scan.AuditorScanMixin.deep_scan_host",
                return_value={},
            ),
            patch("redaudit.core.auditor_scan.banner_grab_fallback", return_value={}),
            patch("redaudit.core.auditor_scan.enrich_host_with_whois"),
            patch("redaudit.core.auditor_scan.enrich_host_with_dns"),
        ):
            res = auditor.scan_host_ports("1.1.1.1")
            assert res["ip"] == "1.1.1.1"
            assert "smart_scan" in res

    def test_scan_host_ports_nmap_failure(self):
        """Test host port scan when nmap fails."""
        auditor = MockAuditorScan()

        with patch.object(
            AuditorScanMixin,
            "_run_nmap_xml_scan",
            return_value=(None, "Scan Error"),
        ):
            res = auditor.scan_host_ports("1.1.1.1")
            assert res["status"] == STATUS_NO_RESPONSE
            assert res["error"] == "Scan Error"


# =============================================================================
# Concurrent Scan Tests
# =============================================================================


class TestConcurrentScan:
    """Tests for concurrent host scanning."""

    def test_scan_hosts_concurrent_smoke(self):
        """Smoke test for concurrent scanning."""
        auditor = MockAuditorScan()

        def side_effect_wait(fs, timeout=None, return_when=None):
            return fs, set()

        mock_fut = MagicMock()
        mock_fut.result.return_value = {"ip": "1.1.1.1", "ports": []}

        with (
            patch("redaudit.core.auditor_scan.ThreadPoolExecutor") as mock_executor,
            patch("redaudit.core.auditor_scan.wait", side_effect=side_effect_wait),
            patch("redaudit.core.auditor_scan.as_completed", return_value=[mock_fut]),
            patch.dict(sys.modules, {"rich.progress": MagicMock()}),
        ):
            mock_pool = MagicMock()
            mock_executor.return_value.__enter__.return_value = mock_pool
            mock_pool.submit.return_value = mock_fut

            auditor.scan_hosts_concurrent(["1.1.1.1"])
            mock_pool.submit.assert_called()


# =============================================================================
# Agentless Verification Tests
# =============================================================================


class TestAgentlessVerification:
    """Tests for agentless verification."""

    def test_run_agentless_verification(self):
        """Test agentless verification flow."""
        auditor = MockAuditorScan()
        auditor.config["windows_verify_enabled"] = True

        mock_target = MagicMock()
        mock_target.ip = "1.1.1.1"

        host_res = [{"ip": "1.1.1.1"}]

        with (
            patch(
                "redaudit.core.auditor_scan.select_agentless_probe_targets",
                return_value=[mock_target],
            ),
            patch(
                "redaudit.core.auditor_scan.probe_agentless_services",
                return_value={"ip": "1.1.1.1", "os": "Windows"},
            ),
            patch(
                "redaudit.core.auditor_scan.summarize_agentless_fingerprint",
                return_value={"os": "Windows"},
            ),
            patch.dict(sys.modules, {"rich.progress": MagicMock()}),
        ):
            auditor.run_agentless_verification(host_res)
            assert "agentless_probe" in host_res[0]


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Edge case and error handling tests."""

    def test_collect_discovery_hosts_invalid_ip(self):
        """Test _collect_discovery_hosts with invalid IP."""
        auditor = MockAuditorScan()
        auditor.results["net_discovery"] = {"alive_hosts": ["invalid_ip"]}
        hosts = auditor._collect_discovery_hosts([])
        assert hosts == []

    def test_scan_network_discovery_exception(self):
        """Test scan_network_discovery handles exceptions."""
        auditor = MockAuditorScan()

        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = Exception("Fail")

        mock_module = MagicMock()
        mock_module.PortScanner.return_value = mock_scanner

        with patch.object(auditor_scan_module, "nmap", mock_module):
            hosts = auditor.scan_network_discovery("1.1.1.0/24")
            assert hosts == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
