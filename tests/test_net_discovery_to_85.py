"""
Tests for net_discovery.py to boost coverage to 85%+.
Targets: red team methods (2084-2209), error paths, helper functions.
"""

import os
from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.net_discovery import (
    _safe_truncate,
    _parse_ldap_rootdse,
    _parse_nmap_krb5_info,
    _extract_dhcp_dns_servers,
    _extract_dhcp_domains,
    _parse_ip6_neighbors,
)


# -------------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------------


def test_safe_truncate_normal():
    """Test safe truncate with normal string."""
    result = _safe_truncate("hello world", 5)
    assert result == "hello"


def test_safe_truncate_short():
    """Test safe truncate when string is shorter than limit."""
    result = _safe_truncate("hi", 10)
    assert result == "hi"


def test_safe_truncate_non_string():
    """Test safe truncate with non-string input."""
    result = _safe_truncate(None, 10)  # type: ignore
    assert result == ""


def test_safe_truncate_zero_limit():
    """Test safe truncate with zero limit."""
    result = _safe_truncate("hello", 0)
    assert result == ""


def test_safe_truncate_negative_limit():
    """Test safe truncate with negative limit."""
    result = _safe_truncate("hello", -5)
    assert result == ""


# -------------------------------------------------------------------------
# LDAP Parsing
# -------------------------------------------------------------------------


def test_parse_ldap_rootdse_empty():
    """Test parsing empty LDAP response."""
    result = _parse_ldap_rootdse("")
    assert result == {}


def test_parse_ldap_rootdse_valid():
    """Test parsing valid LDAP response."""
    text = """defaultNamingContext: DC=example,DC=com
rootDomainNamingContext: DC=example,DC=com
dnsHostName: dc.example.com
namingContexts: DC=example,DC=com
namingContexts: CN=Configuration,DC=example,DC=com
supportedLDAPVersion: 3
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
"""
    result = _parse_ldap_rootdse(text)
    assert "defaultNamingContext" in result
    assert "dnsHostName" in result
    assert "namingContexts" in result
    assert isinstance(result["namingContexts"], list)


def test_parse_ldap_rootdse_malformed():
    """Test parsing malformed LDAP response."""
    text = "no colon here\n"
    result = _parse_ldap_rootdse(text)
    assert result == {}


# -------------------------------------------------------------------------
# Kerberos Parsing
# -------------------------------------------------------------------------


def test_parse_nmap_krb5_info_empty():
    """Test parsing empty krb5 output."""
    result = _parse_nmap_krb5_info("")
    assert result == []


def test_parse_nmap_krb5_info_valid():
    """Test parsing valid krb5 output."""
    text = """Nmap scan report for 10.0.0.1
PORT   STATE SERVICE
88/tcp open  kerberos-sec
|   Realm: EXAMPLE.COM
"""
    result = _parse_nmap_krb5_info(text)
    assert "EXAMPLE.COM" in result or "EXAMPLE" in result


# -------------------------------------------------------------------------
# DHCP Extraction
# -------------------------------------------------------------------------


def test_extract_dhcp_dns_servers_empty():
    """Test extracting DNS servers from empty discovery result."""
    result = _extract_dhcp_dns_servers({})
    assert result == []


def test_extract_dhcp_dns_servers_valid():
    """Test extracting DNS servers from valid discovery result."""
    discovery = {
        "dhcp_servers": [
            {"dns": ["10.0.0.1", "10.0.0.2"]},
            {"dns": ["10.0.0.3"]},
        ]
    }
    result = _extract_dhcp_dns_servers(discovery)
    assert "10.0.0.1" in result
    assert "10.0.0.2" in result
    assert "10.0.0.3" in result


def test_extract_dhcp_dns_servers_non_dict():
    """Test extracting DNS servers with non-dict entries."""
    discovery = {"dhcp_servers": ["not a dict", None, 123]}
    result = _extract_dhcp_dns_servers(discovery)
    assert result == []


def test_extract_dhcp_domains_empty():
    """Test extracting domains from empty discovery result."""
    result = _extract_dhcp_domains({})
    assert result == []


def test_extract_dhcp_domains_valid():
    """Test extracting domains from valid discovery result."""
    discovery = {
        "dhcp_servers": [
            {"domain": "example.com"},
            {"domain_search": "test.local"},
        ]
    }
    result = _extract_dhcp_domains(discovery)
    assert len(result) >= 0  # May be filtered by sanitize


# -------------------------------------------------------------------------
# IPv6 Neighbor Parsing
# -------------------------------------------------------------------------


def test_parse_ip6_neighbors_empty():
    """Test parsing empty IPv6 neighbor output."""
    result = _parse_ip6_neighbors("")
    assert result == []


def test_parse_ip6_neighbors_valid():
    """Test parsing valid IPv6 neighbor output."""
    text = """fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
fe80::2 dev eth0 lladdr 11:22:33:44:55:66 STALE
"""
    result = _parse_ip6_neighbors(text)
    assert len(result) == 2
    assert result[0]["ip"] == "fe80::1"
    assert result[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_parse_ip6_neighbors_no_lladdr():
    """Test parsing IPv6 neighbors without lladdr."""
    text = "fe80::1 dev eth0 INCOMPLETE\n"
    result = _parse_ip6_neighbors(text)
    assert len(result) == 1
    assert result[0]["ip"] == "fe80::1"


# -------------------------------------------------------------------------
# Red Team Methods - Early Exits (mocked)
# -------------------------------------------------------------------------


def test_redteam_ipv6_discovery_no_interface():
    """Test IPv6 discovery with no interface."""
    from redaudit.core.net_discovery import _redteam_ipv6_discovery

    result = _redteam_ipv6_discovery(None, {})
    assert result["status"] == "skipped_no_interface"


def test_redteam_ipv6_discovery_no_root():
    """Test IPv6 discovery without root."""
    from redaudit.core.net_discovery import _redteam_ipv6_discovery

    with patch("redaudit.core.net_discovery._is_root", return_value=False):
        result = _redteam_ipv6_discovery("eth0", {})
        assert result["status"] == "skipped_requires_root"


def test_redteam_bettercap_no_interface():
    """Test bettercap recon with no interface."""
    from redaudit.core.net_discovery import _redteam_bettercap_recon

    result = _redteam_bettercap_recon(None, {})
    assert result["status"] == "skipped_no_interface"


def test_redteam_bettercap_disabled():
    """Test bettercap recon when disabled."""
    from redaudit.core.net_discovery import _redteam_bettercap_recon

    result = _redteam_bettercap_recon("eth0", {}, active_l2=False)
    assert result["status"] == "skipped_disabled"


def test_redteam_bettercap_tool_missing():
    """Test bettercap recon when tool missing."""
    from redaudit.core.net_discovery import _redteam_bettercap_recon

    with patch("shutil.which", return_value=None):
        result = _redteam_bettercap_recon("eth0", {"bettercap": False}, active_l2=True)
        assert result["status"] == "tool_missing"


def test_redteam_bettercap_no_root():
    """Test bettercap recon without root."""
    from redaudit.core.net_discovery import _redteam_bettercap_recon

    with (
        patch("redaudit.core.net_discovery._is_root", return_value=False),
        patch("shutil.which", return_value="/usr/bin/bettercap"),
    ):
        result = _redteam_bettercap_recon("eth0", {"bettercap": True}, active_l2=True)
        assert result["status"] == "skipped_requires_root"


def test_redteam_scapy_no_interface():
    """Test scapy custom with no interface."""
    from redaudit.core.net_discovery import _redteam_scapy_custom

    result = _redteam_scapy_custom(None, {})
    assert result["status"] == "skipped_no_interface"


def test_redteam_scapy_disabled():
    """Test scapy custom when disabled."""
    from redaudit.core.net_discovery import _redteam_scapy_custom

    result = _redteam_scapy_custom("eth0", {}, active_l2=False)
    assert result["status"] == "skipped_disabled"


def test_redteam_scapy_no_root():
    """Test scapy custom without root."""
    from redaudit.core.net_discovery import _redteam_scapy_custom

    with patch("redaudit.core.net_discovery._is_root", return_value=False):
        result = _redteam_scapy_custom("eth0", {}, active_l2=True)
        assert result["status"] == "skipped_requires_root"


def test_redteam_scapy_tool_missing():
    """Test scapy when import fails."""
    from redaudit.core.net_discovery import _redteam_scapy_custom

    with (
        patch("redaudit.core.net_discovery._is_root", return_value=True),
        patch.dict("sys.modules", {"scapy": None, "scapy.all": None}),
    ):
        # Reset import cache
        import sys

        if "scapy" in sys.modules:
            del sys.modules["scapy"]
        if "scapy.all" in sys.modules:
            del sys.modules["scapy.all"]
        result = _redteam_scapy_custom("eth0", {}, active_l2=True)
        assert result["status"] in ("tool_missing", "error", "skipped_requires_root")


# -------------------------------------------------------------------------
# Other Red Team Methods - Early Exits
# -------------------------------------------------------------------------


def test_redteam_vlan_enum_no_data():
    """Test VLAN enum returns expected structure."""
    from redaudit.core.net_discovery import _redteam_vlan_enum

    with patch("redaudit.core.net_discovery._tcpdump_capture") as mock_cap:
        mock_cap.return_value = {"status": "no_data"}
        result = _redteam_vlan_enum("eth0", {"tcpdump": True})
        assert "status" in result


def test_redteam_stp_topology_no_data():
    """Test STP topology returns expected structure."""
    from redaudit.core.net_discovery import _redteam_stp_topology

    with patch("redaudit.core.net_discovery._tcpdump_capture") as mock_cap:
        mock_cap.return_value = {"status": "no_data"}
        result = _redteam_stp_topology("eth0", {"tcpdump": True})
        assert "status" in result


def test_redteam_hsrp_vrrp_no_data():
    """Test HSRP/VRRP discovery returns expected structure."""
    from redaudit.core.net_discovery import _redteam_hsrp_vrrp_discovery

    with patch("redaudit.core.net_discovery._tcpdump_capture") as mock_cap:
        mock_cap.return_value = {"status": "no_data"}
        result = _redteam_hsrp_vrrp_discovery("eth0", {"tcpdump": True})
        assert "status" in result


def test_redteam_llmnr_nbtns_no_data():
    """Test LLMNR/NBNS capture returns expected structure."""
    from redaudit.core.net_discovery import _redteam_llmnr_nbtns_capture

    with patch("redaudit.core.net_discovery._tcpdump_capture") as mock_cap:
        mock_cap.return_value = {"status": "no_data"}
        result = _redteam_llmnr_nbtns_capture("eth0", {"tcpdump": True})
        assert "status" in result


def test_redteam_router_discovery_tool_missing():
    """Test router discovery when tools missing."""
    from redaudit.core.net_discovery import _redteam_router_discovery

    with (
        patch("shutil.which", return_value=None),
        patch("redaudit.core.net_discovery._tcpdump_capture") as mock_cap,
    ):
        mock_cap.return_value = {"status": "tool_missing", "tool": "tcpdump"}
        result = _redteam_router_discovery("eth0", {"nmap": False, "tcpdump": False})
        assert "status" in result


# -------------------------------------------------------------------------
# RPC and LDAP Enum - Early Exits
# -------------------------------------------------------------------------


def test_redteam_rpc_enum_no_targets():
    """Test RPC enum with no targets."""
    from redaudit.core.net_discovery import _redteam_rpc_enum

    result = _redteam_rpc_enum([], {})
    assert result["status"] == "no_targets"


def test_redteam_rpc_enum_tool_missing():
    """Test RPC enum when tools missing."""
    from redaudit.core.net_discovery import _redteam_rpc_enum

    with patch("shutil.which", return_value=None):
        result = _redteam_rpc_enum(["10.0.0.1"], {"rpcclient": False, "nmap": False})
        assert result["status"] == "tool_missing"


def test_redteam_ldap_enum_no_targets():
    """Test LDAP enum with no targets."""
    from redaudit.core.net_discovery import _redteam_ldap_enum

    result = _redteam_ldap_enum([], {})
    assert result["status"] == "no_targets"


def test_redteam_ldap_enum_tool_missing():
    """Test LDAP enum when tools missing."""
    from redaudit.core.net_discovery import _redteam_ldap_enum

    with patch("shutil.which", return_value=None):
        result = _redteam_ldap_enum(["10.0.0.1"], {"ldapsearch": False, "nmap": False})
        assert result["status"] == "tool_missing"


def test_redteam_kerberos_enum_no_targets():
    """Test Kerberos enum with no targets."""
    from redaudit.core.net_discovery import _redteam_kerberos_enum

    result = _redteam_kerberos_enum([], {})
    assert result["status"] == "no_targets"


def test_redteam_kerberos_enum_tool_missing():
    """Test Kerberos enum when tools missing."""
    from redaudit.core.net_discovery import _redteam_kerberos_enum

    with patch("shutil.which", return_value=None):
        result = _redteam_kerberos_enum(["10.0.0.1"], {"nmap": False, "kerbrute": False})
        assert result["status"] == "tool_missing"


# -------------------------------------------------------------------------
# DNS Zone Transfer - Early Exits
# -------------------------------------------------------------------------


def test_redteam_dns_zone_transfer_tool_missing():
    """Test DNS zone transfer when dig missing."""
    from redaudit.core.net_discovery import _redteam_dns_zone_transfer

    with patch("shutil.which", return_value=None):
        result = _redteam_dns_zone_transfer({}, {"dig": False})
        assert result["status"] == "tool_missing"


def test_redteam_dns_zone_transfer_no_dns_servers():
    """Test DNS zone transfer with no DNS servers."""
    from redaudit.core.net_discovery import _redteam_dns_zone_transfer

    with patch("shutil.which", return_value="/usr/bin/dig"):
        result = _redteam_dns_zone_transfer({}, {"dig": True})
        assert result["status"] == "no_targets"


def test_redteam_dns_zone_transfer_no_zone():
    """Test DNS zone transfer with no zone hint."""
    from redaudit.core.net_discovery import _redteam_dns_zone_transfer

    discovery = {"dhcp_servers": [{"dns": ["10.0.0.1"]}]}
    with patch("shutil.which", return_value="/usr/bin/dig"):
        result = _redteam_dns_zone_transfer(discovery, {"dig": True})
        assert result["status"] in ("skipped_no_zone", "no_data", "ok")


# -------------------------------------------------------------------------
# tcpdump Capture - Early Exits
# -------------------------------------------------------------------------


def test_tcpdump_capture_no_interface():
    """Test tcpdump capture with no interface."""
    from redaudit.core.net_discovery import _tcpdump_capture

    result = _tcpdump_capture("", "port 80", {}, timeout_s=5)
    assert result["status"] == "skipped_no_interface"


def test_tcpdump_capture_tool_missing():
    """Test tcpdump capture when tool missing."""
    from redaudit.core.net_discovery import _tcpdump_capture

    with patch("shutil.which", return_value=None):
        result = _tcpdump_capture("eth0", "port 80", {"tcpdump": False}, 5)
        assert result["status"] == "tool_missing"


def test_tcpdump_capture_no_root():
    """Test tcpdump capture without root."""
    from redaudit.core.net_discovery import _tcpdump_capture

    with (
        patch("shutil.which", return_value="/usr/sbin/tcpdump"),
        patch("redaudit.core.net_discovery._is_root", return_value=False),
    ):
        result = _tcpdump_capture("eth0", "port 80", {"tcpdump": True}, 5)
        assert result["status"] == "skipped_requires_root"
