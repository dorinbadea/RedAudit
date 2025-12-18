#!/usr/bin/env python3
"""
RedAudit - Scanner Edge Case Tests

Tests for scanner.py edge cases in parsing and validation functions.
Focus on improving coverage for low-coverage areas.
"""

import unittest
from unittest.mock import patch, MagicMock

from redaudit.core.scanner import (
    sanitize_ip,
    sanitize_hostname,
    is_web_service,
    is_suspicious_service,
    is_port_anomaly,
    is_ipv6,
    is_ipv6_network,
    extract_vendor_mac,
    extract_os_detection,
    get_nmap_arguments,
    get_nmap_arguments_for_target,
    output_has_identity,
)


class TestScannerSanitization(unittest.TestCase):
    """Edge case tests for IP/hostname sanitization."""

    def test_sanitize_ip_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        self.assertEqual(sanitize_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(sanitize_ip("  10.0.0.1  "), "10.0.0.1")
        self.assertEqual(sanitize_ip("0.0.0.0"), "0.0.0.0")
        self.assertEqual(sanitize_ip("255.255.255.255"), "255.255.255.255")

    def test_sanitize_ip_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        self.assertEqual(sanitize_ip("::1"), "::1")
        self.assertEqual(sanitize_ip("2001:db8::1"), "2001:db8::1")
        self.assertEqual(sanitize_ip("fe80::1"), "fe80::1")

    def test_sanitize_ip_invalid(self):
        """Test invalid IP inputs."""
        self.assertIsNone(sanitize_ip(None))
        self.assertIsNone(sanitize_ip(""))
        self.assertIsNone(sanitize_ip("   "))
        self.assertIsNone(sanitize_ip(123))
        self.assertIsNone(sanitize_ip(["192.168.1.1"]))
        self.assertIsNone(sanitize_ip("not-an-ip"))
        self.assertIsNone(sanitize_ip("192.168.1"))
        self.assertIsNone(sanitize_ip("999.999.999.999"))

    def test_sanitize_ip_too_long(self):
        """Test IP address exceeding max length."""
        long_ip = "192.168.1." + "1" * 1100
        self.assertIsNone(sanitize_ip(long_ip))

    def test_sanitize_hostname_valid(self):
        """Test valid hostnames."""
        self.assertEqual(sanitize_hostname("example.com"), "example.com")
        self.assertEqual(sanitize_hostname("my-server"), "my-server")
        self.assertEqual(sanitize_hostname("server01.local"), "server01.local")
        self.assertEqual(sanitize_hostname("  test.domain  "), "test.domain")

    def test_sanitize_hostname_invalid(self):
        """Test invalid hostname inputs."""
        self.assertIsNone(sanitize_hostname(None))
        self.assertIsNone(sanitize_hostname(""))
        self.assertIsNone(sanitize_hostname(123))
        self.assertIsNone(sanitize_hostname("host name"))  # Space not allowed
        self.assertIsNone(sanitize_hostname("host;name"))  # Special char
        self.assertIsNone(sanitize_hostname("host'name"))  # Quote

    def test_sanitize_hostname_too_long(self):
        """Test hostname exceeding max length."""
        long_hostname = "a" * 1100
        self.assertIsNone(sanitize_hostname(long_hostname))


class TestScannerServiceDetection(unittest.TestCase):
    """Tests for service type detection functions."""

    def test_is_web_service_exact_matches(self):
        """Test exact web service name matches."""
        self.assertTrue(is_web_service("http"))
        self.assertTrue(is_web_service("https"))
        self.assertTrue(is_web_service("www"))
        self.assertTrue(is_web_service("http-proxy"))
        self.assertTrue(is_web_service("ssl/http"))

    def test_is_web_service_keyword_matches(self):
        """Test keyword-based web service detection."""
        self.assertTrue(is_web_service("HTTP-Alt"))
        self.assertTrue(is_web_service("apache-httpd"))
        self.assertTrue(is_web_service("nginx-ssl"))
        self.assertTrue(is_web_service("web-admin"))

    def test_is_web_service_non_web(self):
        """Test non-web services."""
        self.assertFalse(is_web_service("ssh"))
        self.assertFalse(is_web_service("ftp"))
        self.assertFalse(is_web_service("mysql"))
        self.assertFalse(is_web_service(""))
        self.assertFalse(is_web_service(None))

    def test_is_suspicious_service(self):
        """Test suspicious service detection."""
        self.assertTrue(is_suspicious_service("socks5"))
        self.assertTrue(is_suspicious_service("tor"))
        self.assertTrue(is_suspicious_service("tcpwrapped"))
        self.assertTrue(is_suspicious_service("backdoor"))
        self.assertTrue(is_suspicious_service("meterpreter"))
        self.assertTrue(is_suspicious_service("cobalt-strike"))

    def test_is_suspicious_service_normal(self):
        """Test normal services not flagged as suspicious."""
        self.assertFalse(is_suspicious_service("http"))
        self.assertFalse(is_suspicious_service("ssh"))
        self.assertFalse(is_suspicious_service("mysql"))
        self.assertFalse(is_suspicious_service(""))
        self.assertFalse(is_suspicious_service(None))


class TestScannerPortAnomaly(unittest.TestCase):
    """Tests for port anomaly detection."""

    def test_is_port_anomaly_standard_services(self):
        """Test that standard services on their ports are NOT anomalies."""
        self.assertFalse(is_port_anomaly(22, "ssh"))
        self.assertFalse(is_port_anomaly(22, "openssh"))
        self.assertFalse(is_port_anomaly(80, "http"))
        self.assertFalse(is_port_anomaly(443, "https"))
        self.assertFalse(is_port_anomaly(443, "ssl"))
        self.assertFalse(is_port_anomaly(3306, "mysql"))

    def test_is_port_anomaly_unexpected_services(self):
        """Test that unexpected services on standard ports ARE anomalies."""
        self.assertTrue(is_port_anomaly(22, "http"))  # HTTP on SSH port
        self.assertTrue(is_port_anomaly(80, "ssh"))  # SSH on HTTP port
        self.assertTrue(is_port_anomaly(443, "ftp"))  # FTP on HTTPS port
        self.assertTrue(is_port_anomaly(22, "unknown"))  # Unknown on SSH port

    def test_is_port_anomaly_non_standard_ports(self):
        """Test that non-standard ports don't trigger anomaly."""
        # Ports NOT in STANDARD_PORT_SERVICES
        self.assertFalse(is_port_anomaly(9999, "anything"))
        self.assertFalse(is_port_anomaly(12345, "unknown"))
        self.assertFalse(is_port_anomaly(31337, "backdoor"))

    def test_is_port_anomaly_empty_service(self):
        """Test empty service name handling."""
        self.assertFalse(is_port_anomaly(22, ""))
        self.assertFalse(is_port_anomaly(22, None))


class TestScannerIPv6Detection(unittest.TestCase):
    """Tests for IPv6 detection functions."""

    def test_is_ipv6_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        self.assertTrue(is_ipv6("::1"))
        self.assertTrue(is_ipv6("2001:db8::1"))
        self.assertTrue(is_ipv6("fe80::1"))
        self.assertTrue(is_ipv6("::ffff:192.168.1.1"))

    def test_is_ipv6_ipv4(self):
        """Test IPv4 addresses return False."""
        self.assertFalse(is_ipv6("192.168.1.1"))
        self.assertFalse(is_ipv6("10.0.0.1"))
        self.assertFalse(is_ipv6("0.0.0.0"))

    def test_is_ipv6_invalid(self):
        """Test invalid inputs return False."""
        self.assertFalse(is_ipv6("not-an-ip"))
        self.assertFalse(is_ipv6(""))

    def test_is_ipv6_network(self):
        """Test IPv6 network CIDR detection."""
        self.assertTrue(is_ipv6_network("2001:db8::/32"))
        self.assertTrue(is_ipv6_network("fe80::/10"))
        self.assertFalse(is_ipv6_network("192.168.1.0/24"))
        self.assertFalse(is_ipv6_network("10.0.0.0/8"))
        self.assertFalse(is_ipv6_network("invalid"))


class TestScannerMACExtraction(unittest.TestCase):
    """Tests for MAC address and vendor extraction."""

    def test_extract_vendor_mac_standard_format(self):
        """Test standard Nmap MAC output format."""
        text = "MAC Address: 00:11:22:33:44:55 (Cisco Systems)"
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "00:11:22:33:44:55")
        self.assertEqual(vendor, "Cisco Systems")

    def test_extract_vendor_mac_lowercase(self):
        """Test lowercase MAC address."""
        text = "MAC Address: aa:bb:cc:dd:ee:ff (Unknown Vendor)"
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(vendor, "Unknown Vendor")

    def test_extract_vendor_mac_mixed_case(self):
        """Test mixed case MAC address."""
        text = "MAC Address: Aa:Bb:Cc:Dd:Ee:Ff (Apple, Inc.)"
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "Aa:Bb:Cc:Dd:Ee:Ff")
        self.assertEqual(vendor, "Apple, Inc.")

    def test_extract_vendor_mac_multiline(self):
        """Test extraction from multiline output."""
        text = """
        PORT   STATE SERVICE
        22/tcp open  ssh
        MAC Address: DE:AD:BE:EF:CA:FE (Test Vendor)
        """
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "DE:AD:BE:EF:CA:FE")
        self.assertEqual(vendor, "Test Vendor")

    def test_extract_vendor_mac_no_match(self):
        """Test output without MAC address."""
        text = "No MAC address found in this output"
        mac, vendor = extract_vendor_mac(text)
        self.assertIsNone(mac)
        self.assertIsNone(vendor)

    def test_extract_vendor_mac_empty_input(self):
        """Test empty/None input."""
        self.assertEqual(extract_vendor_mac(""), (None, None))
        self.assertEqual(extract_vendor_mac(None), (None, None))


class TestScannerOSDetection(unittest.TestCase):
    """Tests for OS detection extraction."""

    def test_extract_os_detection_os_details(self):
        """Test OS details pattern."""
        text = "OS details: Linux 3.2 - 4.9"
        result = extract_os_detection(text)
        self.assertEqual(result, "Linux 3.2 - 4.9")

    def test_extract_os_detection_running(self):
        """Test Running pattern."""
        text = "Running: Microsoft Windows 10"
        result = extract_os_detection(text)
        self.assertEqual(result, "Microsoft Windows 10")

    def test_extract_os_detection_cpe(self):
        """Test OS CPE pattern."""
        text = "OS CPE: cpe:/o:linux:linux_kernel:4.15"
        result = extract_os_detection(text)
        self.assertEqual(result, "linux:linux_kernel:4.15")

    def test_extract_os_detection_aggressive_guess(self):
        """Test aggressive OS guess pattern."""
        text = "Aggressive OS guesses: Linux 4.15 (95%), Windows 10 (80%)"
        result = extract_os_detection(text)
        self.assertEqual(result, "Linux 4.15 (95%)")

    def test_extract_os_detection_no_match(self):
        """Test output without OS info."""
        text = "PORT   STATE SERVICE\n22/tcp open  ssh"
        result = extract_os_detection(text)
        self.assertIsNone(result)

    def test_extract_os_detection_empty_input(self):
        """Test empty/None input."""
        self.assertIsNone(extract_os_detection(""))
        self.assertIsNone(extract_os_detection(None))

    def test_extract_os_detection_truncation(self):
        """Test long OS string truncation to 100 chars."""
        long_os = "A" * 200
        text = f"OS details: {long_os}"
        result = extract_os_detection(text)
        self.assertEqual(len(result), 100)


class TestScannerNmapArguments(unittest.TestCase):
    """Tests for Nmap argument generation."""

    def test_get_nmap_arguments_modes(self):
        """Test different scan modes."""
        args_rapid = get_nmap_arguments("rapido")
        self.assertIn("-sn", args_rapid)
        self.assertIn("--max-retries 1", args_rapid)

        args_normal = get_nmap_arguments("normal")
        self.assertIn("-F", args_normal)
        self.assertIn("-sV", args_normal)

        args_full = get_nmap_arguments("completo")
        self.assertIn("-p-", args_full)
        self.assertIn("-sC", args_full)
        self.assertIn("-A", args_full)

    def test_get_nmap_arguments_invalid_mode(self):
        """Test fallback for invalid mode."""
        args = get_nmap_arguments("invalid_mode")
        # Should return normal mode args
        self.assertIn("-F", args)

    def test_get_nmap_arguments_stealth(self):
        """Test stealth mode with custom timing."""
        config = {"nmap_timing": "T2"}
        args = get_nmap_arguments("normal", config)
        self.assertIn("-T2", args)

    def test_get_nmap_arguments_for_target_ipv4(self):
        """Test IPv4 target doesn't add -6 flag."""
        args = get_nmap_arguments_for_target("normal", "192.168.1.0/24")
        self.assertNotIn("-6", args)

    def test_get_nmap_arguments_for_target_ipv6(self):
        """Test IPv6 target adds -6 flag."""
        args = get_nmap_arguments_for_target("normal", "2001:db8::/32")
        self.assertIn("-6", args)


class TestScannerOutputHasIdentity(unittest.TestCase):
    """Tests for identity detection in scan output."""

    def test_output_has_identity_with_mac(self):
        """Test detection of MAC address."""
        records = [{"stdout": "MAC Address: 00:11:22:33:44:55 (Vendor)"}]
        self.assertTrue(output_has_identity(records))

    def test_output_has_identity_with_os_details(self):
        """Test detection of OS details."""
        records = [{"stdout": "OS details: Linux 4.x"}]
        self.assertTrue(output_has_identity(records))

    def test_output_has_identity_with_running(self):
        """Test detection of Running pattern."""
        records = [{"stdout": "Running: Windows Server 2019"}]
        self.assertTrue(output_has_identity(records))

    def test_output_has_identity_with_device_type(self):
        """Test detection of Device type."""
        records = [{"stdout": "Device type: router|switch"}]
        self.assertTrue(output_has_identity(records))

    def test_output_has_identity_empty(self):
        """Test empty records."""
        self.assertFalse(output_has_identity([]))
        self.assertFalse(output_has_identity([{"stdout": ""}]))
        self.assertFalse(output_has_identity([{"stdout": "PORT STATE SERVICE"}]))


if __name__ == "__main__":
    unittest.main()
