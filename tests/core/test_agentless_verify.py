#!/usr/bin/env python3
"""
RedAudit - Tests for agentless verification helpers.
"""

from unittest.mock import MagicMock, patch

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


def test_decode_text_edge_cases():
    assert agentless_verify._decode_text("test") == "test"
    assert agentless_verify._decode_text(b"test") == "test"
    assert agentless_verify._decode_text(None) == ""
    assert agentless_verify._decode_text(123) == "123"


def test_select_probe_targets_edge():
    hosts = [
        {"ip": "1.1.1.1", "ports": [{"port": 445, "service": "microsoft-ds"}]},
        {"ip": "2.2.2.2", "ports": [{"port": 3389, "service": "ms-wbt-server"}]},
        {"ip": "3.3.3.3", "ports": [{"port": 389, "service": "ldap"}]},
        {"ip": "4.4.4.4", "ports": [{"port": 2222, "service": "ssh"}]},
        {"ip": "5.5.5.5", "ports": [{"port": 80, "service": "http"}]},
    ]
    targets = agentless_verify.select_agentless_probe_targets(hosts)
    assert len(targets) == 5
    assert targets[0].smb is True
    assert targets[1].rdp is True
    assert targets[2].ldap is True
    assert 2222 in targets[3].ssh_ports
    assert 80 in targets[4].http_ports


def test_select_agentless_probe_targets_invalid_entries():
    from redaudit.core.models import Host, Service

    host_bad_service = Host(ip="10.0.0.9", services=[Service(port="bad", name="ssh")])
    hosts = [
        host_bad_service,
        {"ip": "10.0.0.10", "ports": [{"port": "x", "service": "ssh"}, {"port": None}]},
        {"ip": None, "ports": [{"port": 22, "service": "ssh"}]},
    ]
    targets = agentless_verify.select_agentless_probe_targets(hosts)
    assert targets == []


def test_parse_smb_nmap_edge():
    text = (
        "OS: Windows 10\n"
        "Computer name: WIN10-PRO\n"
        "Domain name: WORKGROUP\n"
        "message signing enabled but not required\n"
        "SMBv1: true"
    )
    res = agentless_verify.parse_smb_nmap(text)
    assert res["os"] == "Windows 10"
    assert res["computer_name"] == "WIN10-PRO"
    assert res["domain"] == "WORKGROUP"
    assert res["smb_signing_enabled"] is True
    assert res["smb_signing_required"] is False
    assert res["smbv1_detected"] is True

    assert (
        agentless_verify.parse_smb_nmap("message signing enabled and required")[
            "smb_signing_required"
        ]
        is True
    )
    assert (
        agentless_verify.parse_smb_nmap("message signing disabled")["smb_signing_enabled"] is False
    )


def test_parse_smb_nmap_blank_domain_ignores_fqdn():
    text = (
        "| smb-os-discovery: \n"
        "|   Computer name: 41c64e8260a5\n"
        "|   Domain name: \n"
        "|   FQDN: 41c64e8260a5\n"
    )
    res = agentless_verify.parse_smb_nmap(text)
    assert res["computer_name"] == "41c64e8260a5"
    assert "domain" not in res


def test_parse_ldap_rootdse_edge():
    text = "dnsHostName: dc1.lab.local\ndefaultNamingContext: DC=lab,DC=local\nsupportedLDAPVersion: 2, 3"
    res = agentless_verify.parse_ldap_rootdse(text)
    assert res["dnsHostName"] == "dc1.lab.local"
    assert res["defaultNamingContext"] == "DC=lab,DC=local"
    assert "3" in res["supportedLDAPVersion"]

    assert agentless_verify.parse_ldap_rootdse("") == {}


def test_parse_ldap_rootdse_skips_invalid_lines():
    text = "invalid line\nkey:\n:missing\nsupportedLDAPVersion: 3"
    res = agentless_verify.parse_ldap_rootdse(text)
    assert res["supportedLDAPVersion"] == ["3"]


def test_parse_rdp_ntlm_info_edge():
    text = "NetBIOS_Domain_Name: LAB\nNetBIOS_Computer_Name: SRV-RDP"
    res = agentless_verify.parse_rdp_ntlm_info(text)
    assert res["netbios_domain"] == "LAB"
    assert res["netbios_name"] == "SRV-RDP"

    assert agentless_verify.parse_rdp_ntlm_info("") == {}


def test_parse_ssh_hostkeys_edge():
    text = "| ssh-rsa SHA256:abc... (RSA)\n| ecdsa-sha2-nistp256 MD5:123... (ECDSA)"
    res = agentless_verify.parse_ssh_hostkeys(text)
    assert any("SHA256:abc" in k for k in res["hostkeys"])

    assert agentless_verify.parse_ssh_hostkeys("") == {}


def test_parse_ssh_hostkeys_limits_and_skips():
    text = "\n".join(
        [
            "no fingerprints here",
            "| ssh-rsa SHA256:one key",
            "| ssh-rsa SHA256:two key",
            "| ssh-rsa SHA256:three key",
            "| ssh-rsa SHA256:four key",
            "| ssh-rsa SHA256:five key",
            "| ssh-rsa SHA256:six key",
        ]
    )
    res = agentless_verify.parse_ssh_hostkeys(text)
    assert len(res["hostkeys"]) == 5


def test_parse_http_probe_edge():
    text = "http-title: Home Page\nhttp-server-header: Apache/2.4.41"
    res = agentless_verify.parse_http_probe(text)
    assert res["title"] == "Home Page"
    assert res["server"] == "Apache/2.4.41"

    text_multi = "http-server-header:\n  nginx/1.18.0"
    res = agentless_verify.parse_http_probe(text_multi)
    assert res["server"] == "nginx/1.18.0"

    text_hik = "http-title: Hikvision Digital Technology\nhttp-server-header: App-Http-Server"
    res = agentless_verify.parse_http_probe(text_hik)
    assert res["device_vendor"] == "Hikvision"

    text_nmap = "|_http-title: Directory listing for /\n|_http-server-header: SimpleHTTP/0.6"
    res = agentless_verify.parse_http_probe(text_nmap)
    assert res["title"] == "Directory listing for /"
    assert res["server"] == "SimpleHTTP/0.6"

    assert agentless_verify.parse_http_probe("") == {}


def test_summarize_fingerprint_edge():
    probe = {
        "smb": {"os": "Windows 7", "computer_name": "LEGACY"},
        "http": {"title": "Login", "device_type": "camera"},
        "ssh": {"hostkeys": ["ssh-ed25519 hash"]},
    }
    summary = agentless_verify.summarize_agentless_fingerprint(probe)
    assert summary["os"] == "Windows 7"
    assert summary["computer_name"] == "LEGACY"
    assert summary["device_type"] == "camera"
    assert "ssh-ed25519" in summary["ssh_hostkeys"][0]


def test_summarize_fingerprint_includes_version_and_server():
    probe = {
        "ip": "1.2.3.4",
        "rdp": {"product_version": "10.0.1"},
        "http": {"server": "nginx/1.21"},
    }
    summary = agentless_verify.summarize_agentless_fingerprint(probe)
    assert summary["product_version"] == "10.0.1"
    assert summary["http_server"] == "nginx/1.21"


def test_probe_services_dry_run():
    target = agentless_verify.AgentlessProbeTarget(ip="1.1.1.1", smb=True, rdp=True)
    with patch("redaudit.core.agentless_verify._run_nmap_script", return_value=(0, "output", "")):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            res = agentless_verify.probe_agentless_services(target, dry_run=True)
            assert res["smb"]["returncode"] == 0


def test_make_runner_instantiates():
    runner = agentless_verify._make_runner(dry_run=True, timeout=1.0)
    assert runner is not None


def test_run_nmap_script_missing_binary(monkeypatch):
    monkeypatch.setattr(agentless_verify.shutil, "which", lambda _name: None)
    rc, out, err = agentless_verify._run_nmap_script(
        "10.0.0.1", ports="445", scripts="smb-os-discovery"
    )
    assert rc == 127
    assert "nmap not found" in err


def test_run_nmap_script_success(monkeypatch):
    class _Runner:
        def run(self, *_args, **_kwargs):
            return type("Res", (), {"returncode": 0, "stdout": b"ok", "stderr": b""})()

    monkeypatch.setattr(agentless_verify.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(agentless_verify, "_make_runner", lambda **_k: _Runner())
    rc, out, err = agentless_verify._run_nmap_script("10.0.0.1", ports="22", scripts="ssh-hostkey")
    assert rc == 0
    assert "ok" in out
    assert err == ""


def test_probe_services_invalid_ip_and_missing_tool(monkeypatch):
    target = agentless_verify.AgentlessProbeTarget(ip="bad ip", smb=True)
    res = agentless_verify.probe_agentless_services(target)
    assert res["error"] == "invalid_ip"

    target = agentless_verify.AgentlessProbeTarget(ip="10.0.0.1", smb=True)
    monkeypatch.setattr(agentless_verify.shutil, "which", lambda _name: None)
    res = agentless_verify.probe_agentless_services(target)
    assert res["error"] == "tool_missing"


def test_probe_services_uses_redteam_smb(monkeypatch):
    target = agentless_verify.AgentlessProbeTarget(
        ip="10.0.0.1", smb=True, red_team_findings={"smb": {"os": "Windows"}}
    )
    monkeypatch.setattr(agentless_verify.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(
        agentless_verify,
        "_run_nmap_script",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError()),
    )
    res = agentless_verify.probe_agentless_services(target)
    assert res["smb"]["os"] == "Windows"
