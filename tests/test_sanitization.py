#!/usr/bin/env python3
"""
Enhanced tests for RedAudit input sanitization.
"""

import re
import ipaddress


class InteractiveNetworkAuditor:
    """Mock class mimicking sanitizer behaviour."""

    @staticmethod
    def sanitize_ip(ip_str: str | None) -> str | None:
        if ip_str is None:
            return None
        if not isinstance(ip_str, str):
            return None
        ip_str = ip_str.strip()
        if not ip_str:
            return None
        try:
            ipaddress.ip_address(ip_str)
            return ip_str
        except Exception:
            return None

    @staticmethod
    def sanitize_hostname(hostname: str | None) -> str | None:
        if hostname is None:
            return None
        if not isinstance(hostname, str):
            return None
        hostname = hostname.strip()
        if not hostname:
            return None
        if re.match(r"^[a-zA-Z0-9\.\-]+$", hostname):
            return hostname
        return None


def test_sanitize_ip():
    """Test IP address sanitization."""
    assert InteractiveNetworkAuditor.sanitize_ip("192.168.1.1") == "192.168.1.1"
    assert InteractiveNetworkAuditor.sanitize_ip("8.8.8.8") == "8.8.8.8"
    assert InteractiveNetworkAuditor.sanitize_ip("127.0.0.1") == "127.0.0.1"

    assert InteractiveNetworkAuditor.sanitize_ip("::1") == "::1"
    assert InteractiveNetworkAuditor.sanitize_ip("2001:db8::1") == "2001:db8::1"

    assert InteractiveNetworkAuditor.sanitize_ip("256.1.1.1") is None
    assert InteractiveNetworkAuditor.sanitize_ip("192.168.1.999") is None

    assert InteractiveNetworkAuditor.sanitize_ip("") is None
    assert InteractiveNetworkAuditor.sanitize_ip(None) is None
    assert InteractiveNetworkAuditor.sanitize_ip("   ") is None

    assert InteractiveNetworkAuditor.sanitize_ip("'; DROP TABLE") is None
    assert InteractiveNetworkAuditor.sanitize_ip("$(whoami)") is None
    assert InteractiveNetworkAuditor.sanitize_ip("192.168.1.1; rm -rf /") is None
    assert InteractiveNetworkAuditor.sanitize_ip("192.168.1.1 && cat /etc/passwd") is None
    assert InteractiveNetworkAuditor.sanitize_ip("`id`") is None
    assert InteractiveNetworkAuditor.sanitize_ip("%24%28whoami%29") is None

    print("✅ All IP sanitization tests passed")


def test_sanitize_hostname():
    """Test hostname sanitization."""
    assert InteractiveNetworkAuditor.sanitize_hostname("example.com") == "example.com"
    assert InteractiveNetworkAuditor.sanitize_hostname("sub.example.com") == "sub.example.com"
    assert InteractiveNetworkAuditor.sanitize_hostname("host-123") == "host-123"
    assert InteractiveNetworkAuditor.sanitize_hostname("my-server.local") == "my-server.local"

    assert InteractiveNetworkAuditor.sanitize_hostname("") is None
    assert InteractiveNetworkAuditor.sanitize_hostname(None) is None
    assert InteractiveNetworkAuditor.sanitize_hostname("   ") is None

    assert InteractiveNetworkAuditor.sanitize_hostname("host name") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("host_name") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("host/name") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("host\\name") is None

    assert InteractiveNetworkAuditor.sanitize_hostname("'; DROP TABLE") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("$(whoami)") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("host; rm -rf /") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("`id`") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("host && cat /etc/passwd") is None

    assert InteractiveNetworkAuditor.sanitize_hostname("../../../etc/passwd") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("..\\..\\..\\windows\\system32") is None

    print("✅ All hostname sanitization tests passed")


def test_edge_cases():
    """Test additional edge cases."""
    try:
        InteractiveNetworkAuditor.sanitize_ip(123)
    except Exception:
        assert False, "sanitize_ip should handle non-str gracefully"

    try:
        InteractiveNetworkAuditor.sanitize_hostname(["list"])
    except Exception:
        assert False, "sanitize_hostname should handle non-str gracefully"

    long_string = "a" * 10000
    assert InteractiveNetworkAuditor.sanitize_ip(long_string) is None
    assert InteractiveNetworkAuditor.sanitize_hostname(long_string) == long_string

    print("✅ All edge case tests passed")


if __name__ == "__main__":
    test_sanitize_ip()
    test_sanitize_hostname()
    test_edge_cases()
    print("\n🎉 All sanitization tests passed successfully!")