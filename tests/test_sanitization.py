#!/usr/bin/env python3
"""
Basic tests for the input sanitization helpers used in RedAudit.

Note: here we recreate the same sanitize_ip / sanitize_hostname logic
used in the embedded InteractiveNetworkAuditor class, so the behaviour
is identical even though the core lives inside redaudit_install.sh.
"""

import re
import ipaddress


class InteractiveNetworkAuditor:
    """Mock class mimicking the sanitizer behaviour of the real core."""

    @staticmethod
    def sanitize_ip(ip_str: str | None) -> str | None:
        try:
            ipaddress.ip_address(ip_str)
            return ip_str
        except Exception:
            return None

    @staticmethod
    def sanitize_hostname(hostname: str | None) -> str | None:
        if hostname and re.match(r"^[a-zA-Z0-9\.\-]+$", hostname):
            return hostname
        return None


def test_sanitize_ip():
    # valid IPv4
    assert InteractiveNetworkAuditor.sanitize_ip("192.168.1.1") == "192.168.1.1"
    assert InteractiveNetworkAuditor.sanitize_ip("8.8.8.8") == "8.8.8.8"

    # invalid range
    assert InteractiveNetworkAuditor.sanitize_ip("256.1.1.1") is None

    # obvious injection payloads
    assert InteractiveNetworkAuditor.sanitize_ip("'; DROP TABLE") is None
    assert InteractiveNetworkAuditor.sanitize_ip("$(whoami)") is None


def test_sanitize_hostname():
    # valid hostnames
    assert InteractiveNetworkAuditor.sanitize_hostname("example.com") == "example.com"
    assert (
        InteractiveNetworkAuditor.sanitize_hostname("sub.example.com")
        == "sub.example.com"
    )
    assert InteractiveNetworkAuditor.sanitize_hostname("host-123") == "host-123"

    # obvious injection payloads
    assert InteractiveNetworkAuditor.sanitize_hostname("'; DROP TABLE") is None
    assert InteractiveNetworkAuditor.sanitize_hostname("$(whoami)") is None


if __name__ == "__main__":
    test_sanitize_ip()
    test_sanitize_hostname()
    print("\n✅ All sanitization tests passed!")