#!/usr/bin/env python3
"""
RedAudit - Tests for agentless verification helpers.
"""

from unittest.mock import patch

from redaudit.core import agentless_verify


def test_select_agentless_probe_targets():
    hosts = [
        {
            "ip": "10.0.0.1",
            "ports": [
                {"port": 22, "service": "ssh"},
                {"port": 80, "service": "http"},
                {"port": 445, "service": "microsoft-ds"},
                {"port": 3389, "service": "rdp"},
                {"port": 389, "service": "ldap"},
            ],
        }
    ]

    targets = agentless_verify.select_agentless_probe_targets(hosts)
    assert len(targets) == 1
    target = targets[0]
    assert target.smb is True
    assert target.rdp is True
    assert target.ldap is True
    assert 22 in target.ssh_ports
    assert 80 in target.http_ports


def test_parse_helpers():
    smb_text = """
OS: Windows 10
Computer name: HOST1
Domain name: EXAMPLE
message signing enabled and required
SMBv1
"""
    smb = agentless_verify.parse_smb_nmap(smb_text)
    assert smb["os"] == "Windows 10"
    assert smb["computer_name"] == "HOST1"
    assert smb["domain"] == "EXAMPLE"
    assert smb["smb_signing_required"] is True
    assert smb["smbv1_detected"] is True

    ldap_text = "defaultNamingContext: DC=example,DC=com\nsupportedLDAPVersion: 3 2"
    ldap = agentless_verify.parse_ldap_rootdse(ldap_text)
    assert ldap["defaultNamingContext"] == "DC=example,DC=com"
    assert ldap["supportedLDAPVersion"] == ["3", "2"]

    rdp_text = "DNS_Computer_Name: HOST1\nProduct_Version: 10.0.1"
    rdp = agentless_verify.parse_rdp_ntlm_info(rdp_text)
    assert rdp["dns_computer_name"] == "HOST1"
    assert rdp["product_version"] == "10.0.1"

    ssh_text = "| 2048 SHA256:abc key (RSA)\n| 1024 MD5:11:22 key"
    ssh = agentless_verify.parse_ssh_hostkeys(ssh_text)
    assert len(ssh["hostkeys"]) == 2

    http_text = "http-title: Welcome\nhttp-server-header:\nApache/2.4"
    http = agentless_verify.parse_http_probe(http_text)
    assert http["title"] == "Welcome"
    assert http["server"] == "Apache/2.4"


def test_probe_and_summarize_agentless_services(monkeypatch):
    target = agentless_verify.AgentlessProbeTarget(
        ip="10.0.0.1", smb=True, rdp=True, ldap=True, ssh_ports=(22,), http_ports=(80,)
    )

    outputs = [
        (0, "Computer name: HOST1", ""),
        (0, "DNS_Computer_Name: HOST1", ""),
        (0, "defaultNamingContext: DC=example,DC=com", ""),
        (0, "SHA256:abc", ""),
        (0, "http-title: Welcome", ""),
    ]

    monkeypatch.setattr("redaudit.core.agentless_verify.shutil.which", lambda _cmd: "/usr/bin/nmap")
    monkeypatch.setattr(
        "redaudit.core.agentless_verify._run_nmap_script", lambda *_args, **_kwargs: outputs.pop(0)
    )

    result = agentless_verify.probe_agentless_services(target)
    assert result["smb"]["computer_name"] == "HOST1"
    assert result["rdp"]["dns_computer_name"] == "HOST1"
    assert "defaultNamingContext" in result["ldap"]
    assert result["ssh"]["ports"] == [22]
    assert result["http"]["ports"] == [80]

    fp = agentless_verify.summarize_agentless_fingerprint(result)
    assert fp["computer_name"] == "HOST1"
    assert fp["http_title"] == "Welcome"
