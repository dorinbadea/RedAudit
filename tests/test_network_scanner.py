#!/usr/bin/env python3
"""
Tests for NetworkScanner - Phase 3 Architecture Refactoring.
"""

from unittest.mock import MagicMock

import pytest

from redaudit.core.config_context import ConfigurationContext
from redaudit.core.network_scanner import NetworkScanner, create_network_scanner
from redaudit.core.ui_manager import UIManager


@pytest.fixture
def scanner():
    """Create NetworkScanner with default config."""
    config = ConfigurationContext()
    ui = UIManager()
    return NetworkScanner(config=config, ui=ui)


class TestNetworkScannerCreation:
    """Test NetworkScanner instantiation."""

    def test_default_creation(self, scanner):
        """Test NetworkScanner with dependencies."""
        assert scanner.config is not None
        assert scanner.ui is not None
        assert scanner.interrupted is False

    def test_with_logger(self):
        """Test NetworkScanner with logger."""
        config = ConfigurationContext()
        ui = UIManager()
        logger = MagicMock()
        scanner = NetworkScanner(config, ui, logger)
        assert scanner.logger is logger

    def test_factory_function(self):
        """Test create_network_scanner factory."""
        config = ConfigurationContext()
        ui = UIManager()
        scanner = create_network_scanner(config, ui)
        assert isinstance(scanner, NetworkScanner)


class TestIdentityScoring:
    """Test identity scoring logic."""

    def test_empty_host(self, scanner):
        """Test scoring for empty host record."""
        score, reasons = scanner.compute_identity_score({})
        assert score == 0
        assert reasons == []

    def test_mac_only(self, scanner):
        """Test scoring with MAC address."""
        host = {"mac": "AA:BB:CC:DD:EE:FF"}
        score, reasons = scanner.compute_identity_score(host)
        assert score >= 10
        assert "mac_present" in reasons

    def test_mac_with_vendor(self, scanner):
        """Test scoring with MAC and vendor."""
        host = {"mac": "AA:BB:CC:DD:EE:FF", "vendor": "Cisco"}
        score, reasons = scanner.compute_identity_score(host)
        assert score >= 25
        assert "mac_present" in reasons
        assert any("vendor:" in r for r in reasons)

    def test_strong_hostname(self, scanner):
        """Test scoring with strong hostname."""
        host = {"hostname": "server01.corp.local"}
        score, reasons = scanner.compute_identity_score(host)
        assert score >= 20
        assert "hostname_strong" in reasons

    def test_weak_hostname(self, scanner):
        """Test scoring with weak hostname."""
        host = {"hostname": "dhcp-192-168-1-100"}
        score, reasons = scanner.compute_identity_score(host)
        assert "hostname_weak" in reasons

    def test_multiple_ports(self, scanner):
        """Test scoring with multiple open ports."""
        host = {
            "ports": [
                {"port": 22, "state": "open"},
                {"port": 80, "state": "open"},
                {"port": 443, "state": "open"},
                {"port": 8080, "state": "open"},
                {"port": 3389, "state": "open"},
            ]
        }
        score, reasons = scanner.compute_identity_score(host)
        assert score >= 15
        assert any("ports:" in r for r in reasons)

    def test_version_info(self, scanner):
        """Test scoring with version info."""
        host = {
            "ports": [
                {"port": 22, "state": "open", "version": "OpenSSH 8.0"},
            ]
        }
        score, reasons = scanner.compute_identity_score(host)
        assert "version_info" in reasons

    def test_os_detection(self, scanner):
        """Test scoring with OS detection."""
        host = {"os_detection": "Linux 5.x"}
        score, reasons = scanner.compute_identity_score(host)
        assert score >= 15
        assert "os_detected" in reasons

    def test_full_host_record(self, scanner):
        """Test scoring with complete host record."""
        host = {
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Dell",
            "hostname": "workstation01.corp.local",
            "os_detection": "Windows 10",
            "ports": [
                {"port": 135, "state": "open", "version": "Microsoft RPC"},
                {"port": 445, "state": "open"},
            ],
            "smart_scan": {"classification": "workstation"},
        }
        score, reasons = scanner.compute_identity_score(host)
        # Should have high score with all this data
        assert score >= 50


class TestDeepScanDecision:
    """Test deep scan trigger logic."""

    def test_low_identity_triggers(self, scanner):
        """Test low identity triggers deep scan."""
        should, reason = scanner.should_trigger_deep_scan(
            total_ports=3,
            any_version=True,
            suspicious=False,
            device_type_hints=[],
            identity_score=30,
            identity_threshold=50,
        )
        assert should is True
        assert "low_identity" in reason

    def test_suspicious_triggers(self, scanner):
        """Test suspicious service triggers deep scan."""
        should, reason = scanner.should_trigger_deep_scan(
            total_ports=3,
            any_version=True,
            suspicious=True,
            device_type_hints=[],
            identity_score=80,
        )
        assert should is True
        assert "suspicious" in reason

    def test_no_version_triggers(self, scanner):
        """Test no version info triggers deep scan."""
        should, reason = scanner.should_trigger_deep_scan(
            total_ports=1,
            any_version=False,
            suspicious=False,
            device_type_hints=[],
            identity_score=80,
        )
        assert should is True
        assert "no_version" in reason

    def test_iot_device_triggers(self, scanner):
        """Test IoT device type triggers deep scan."""
        should, reason = scanner.should_trigger_deep_scan(
            total_ports=3,
            any_version=True,
            suspicious=False,
            device_type_hints=["iot"],
            identity_score=80,
        )
        assert should is True
        assert "device_type" in reason

    def test_high_identity_no_trigger(self, scanner):
        """Test high identity doesn't trigger deep scan."""
        should, reason = scanner.should_trigger_deep_scan(
            total_ports=5,
            any_version=True,
            suspicious=False,
            device_type_hints=["server"],
            identity_score=90,
        )
        assert should is False
        assert reason == ""


class TestNetworkUtilities:
    """Test network utility functions."""

    def test_validate_ip_valid(self):
        """Test valid IP validation."""
        assert NetworkScanner.validate_ip("192.168.1.1") is True
        assert NetworkScanner.validate_ip("10.0.0.1") is True
        assert NetworkScanner.validate_ip("::1") is True

    def test_validate_ip_invalid(self):
        """Test invalid IP validation."""
        assert NetworkScanner.validate_ip("invalid") is False
        assert NetworkScanner.validate_ip("") is False
        assert NetworkScanner.validate_ip("999.999.999.999") is False

    def test_validate_cidr_valid(self):
        """Test valid CIDR validation."""
        assert NetworkScanner.validate_cidr("192.168.1.0/24") is True
        assert NetworkScanner.validate_cidr("10.0.0.0/8") is True

    def test_validate_cidr_invalid(self):
        """Test invalid CIDR validation."""
        assert NetworkScanner.validate_cidr("invalid") is False
        assert NetworkScanner.validate_cidr("") is False

    def test_sanitize_ip(self):
        """Test IP sanitization."""
        assert NetworkScanner.sanitize_ip("  192.168.1.1  ") == "192.168.1.1"
        assert NetworkScanner.sanitize_ip("invalid") == ""
        assert NetworkScanner.sanitize_ip("") == ""

    def test_sanitize_hostname(self):
        """Test hostname sanitization."""
        assert NetworkScanner.sanitize_hostname("server-01.local") == "server-01.local"
        assert NetworkScanner.sanitize_hostname("bad;chars") == "badchars"
        assert NetworkScanner.sanitize_hostname("") == ""

    def test_is_private_ip(self):
        """Test private IP detection."""
        assert NetworkScanner.is_private_ip("192.168.1.1") is True
        assert NetworkScanner.is_private_ip("10.0.0.1") is True
        assert NetworkScanner.is_private_ip("172.16.0.1") is True
        assert NetworkScanner.is_private_ip("8.8.8.8") is False

    def test_expand_cidr(self):
        """Test CIDR expansion."""
        ips = NetworkScanner.expand_cidr("192.168.1.0/30")
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_expand_cidr_limit(self):
        """Test CIDR expansion with limit."""
        ips = NetworkScanner.expand_cidr("10.0.0.0/8", max_hosts=10)
        assert len(ips) == 10


class TestHostHelpers:
    """Test host status helper functions."""

    def test_is_host_up(self):
        """Test host up detection."""
        assert NetworkScanner.is_host_up({"status": "up"}) is True
        assert NetworkScanner.is_host_up({"status": "UP"}) is True
        assert NetworkScanner.is_host_up({"status": "down"}) is False
        assert NetworkScanner.is_host_up({"status": ""}) is False
        assert NetworkScanner.is_host_up({}) is False

    def test_get_open_ports(self):
        """Test open port extraction."""
        host = {
            "ports": [
                {"port": 22, "state": "open"},
                {"port": 23, "state": "closed"},
                {"port": 80, "state": "open"},
            ]
        }
        ports = NetworkScanner.get_open_ports(host)
        assert ports == [22, 80]

    def test_has_web_ports(self):
        """Test web port detection."""
        web_host = {"ports": [{"port": 80, "state": "open"}]}
        assert NetworkScanner.has_web_ports(web_host) is True

        non_web = {"ports": [{"port": 22, "state": "open"}]}
        assert NetworkScanner.has_web_ports(non_web) is False

        empty = {"ports": []}
        assert NetworkScanner.has_web_ports(empty) is False
