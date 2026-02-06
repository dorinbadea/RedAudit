#!/usr/bin/env python3
"""
RedAudit - Tests for net_discovery helper functions.
"""

from redaudit.core import net_discovery, redteam


def test_is_ipv4_and_dedupe():
    assert redteam._is_ipv4("10.0.0.1") is True
    assert redteam._is_ipv4("2001:db8::1") is False
    assert redteam._is_ipv4("bad") is False

    items = ["a", "b", "a", "c", "b"]
    assert redteam._dedupe_preserve_order(items) == ["a", "b", "c"]


def test_gather_redteam_targets():
    discovery = {
        "alive_hosts": ["10.0.0.1", "bad"],
        "arp_hosts": [{"ip": "10.0.0.2"}, {"ip": "2001:db8::1"}],
        "netbios_hosts": [{"ip": "10.0.0.3"}],
        "dhcp_servers": [{"ip": "10.0.0.4"}],
    }
    targets = redteam._gather_redteam_targets(discovery, max_targets=3)
    assert targets == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_sanitize_iface_and_zone():
    assert net_discovery._sanitize_iface("eth0") == "eth0"
    assert net_discovery._sanitize_iface("bad iface") is None
    assert net_discovery._sanitize_iface(None) is None

    assert redteam._sanitize_dns_zone("corp.local") == "corp.local"
    assert redteam._sanitize_dns_zone("corp.local.") == "corp.local"
    assert redteam._sanitize_dns_zone("bad..zone") is None


def test_index_and_filter_ports():
    masscan = {
        "open_ports": [
            {"ip": "10.0.0.1", "port": 22, "protocol": "tcp"},
            {"ip": "10.0.0.1", "port": 53, "protocol": "udp"},
            {"ip": "bad", "port": 80, "protocol": "tcp"},
        ]
    }
    idx = redteam._index_open_tcp_ports(masscan)
    assert idx == {"10.0.0.1": {22}}

    targets = ["10.0.0.1", "10.0.0.2"]
    assert redteam._filter_targets_by_port(targets, idx, 22, 10) == ["10.0.0.1"]
    assert redteam._filter_targets_by_port(targets, idx, 99999, 1) == ["10.0.0.1"]
    assert redteam._filter_targets_by_any_port(targets, idx, [22, 80], 10) == ["10.0.0.1"]
    assert redteam._filter_targets_by_any_port(targets, idx, [], 1) == ["10.0.0.1"]


def test_parse_snmpwalk_and_smb():
    snmp = """
.1.3.6.1.2.1.1.1.0 = STRING: Test Device
.1.3.6.1.2.1.1.5.0 = STRING: Host1
"""
    parsed = redteam._parse_snmpwalk(snmp)
    assert parsed["sysDescr"] == "Test Device"
    assert parsed["sysName"] == "Host1"

    smb = """
OS: Windows 10
Computer name: HOST1
Domain name: EXAMPLE
Sharename: SHARE1
Sharename: SHARE2
"""
    smb_parsed = redteam._parse_smb_nmap(smb)
    assert smb_parsed["os"] == "Windows 10"
    assert smb_parsed["computer_name"] == "HOST1"
    assert smb_parsed["domain"] == "EXAMPLE"
    assert smb_parsed["shares"] == ["SHARE1", "SHARE2"]


def test_parse_ldap_rootdse_and_krb5():
    text = """
defaultNamingContext: DC=example,DC=com
namingContexts: DC=example,DC=com
supportedLDAPVersion: 3
supportedSASLMechanisms: GSSAPI
"""
    parsed = redteam._parse_ldap_rootdse(text)
    assert parsed["defaultNamingContext"] == "DC=example,DC=com"
    assert parsed["namingContexts"] == ["DC=example,DC=com"]
    assert parsed["supportedLDAPVersion"] == ["3"]
    assert parsed["supportedSASLMechanisms"] == ["GSSAPI"]

    krb = "Realm: EXAMPLE.LOCAL\nrealm: TEST.LOCAL"
    realms = redteam._parse_nmap_krb5_info(krb)
    assert realms == ["EXAMPLE.LOCAL", "TEST.LOCAL"]


def test_extract_dhcp_dns_and_domains():
    discovery = {
        "dhcp_servers": [
            {"dns": ["8.8.8.8", "8.8.4.4"], "domain": "corp.local"},
            {"dns": ["8.8.8.8"], "domain_search": "example.local"},
        ]
    }
    assert redteam._extract_dhcp_dns_servers(discovery) == ["8.8.8.8", "8.8.4.4"]
    assert redteam._extract_dhcp_domains(discovery) == ["corp.local", "example.local"]


def test_safe_truncate_and_parse_ip6_neighbors():
    assert redteam._safe_truncate("abc", 2) == "ab"
    assert redteam._safe_truncate("abc", 0) == ""

    ip6 = "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    parsed = redteam._parse_ip6_neighbors(ip6)
    assert parsed[0]["ip"] == "fe80::1"
    assert parsed[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert parsed[0]["dev"] == "eth0"
