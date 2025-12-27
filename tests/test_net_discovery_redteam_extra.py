#!/usr/bin/env python3
"""
Extra coverage for net discovery helpers and redteam enum paths.
"""

from __future__ import annotations

from types import SimpleNamespace

from redaudit.core import net_discovery


def test_run_cmd_wraps_command_runner(monkeypatch):
    class _DummyRunner:
        def __init__(self, **_kwargs):
            return None

        def run(self, *_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout="ok", stderr="warn")

    monkeypatch.setattr(net_discovery, "CommandRunner", _DummyRunner)

    rc, out, err = net_discovery._run_cmd(["echo", "ok"], timeout_s=1, logger=None)

    assert rc == 0
    assert out == "ok"
    assert err == "warn"


def test_dhcp_discover_parses_domain_hints(monkeypatch):
    monkeypatch.setattr(net_discovery.shutil, "which", lambda _tool: True)

    sample = "\n".join(
        [
            "| DHCPOFFER:",
            "|   Server Identifier: 192.168.1.1",
            "|   Subnet Mask: 255.255.255.0",
            "|   Router: 192.168.1.1",
            "|   Domain Name Server: 8.8.8.8",
            "|   Domain Name: example.local",
            "|   Domain Search: corp.local",
        ]
    )
    monkeypatch.setattr(net_discovery, "_run_cmd", lambda *_a, **_k: (0, sample, ""))

    result = net_discovery.dhcp_discover(interface="eth0")

    assert result["servers"]
    server = result["servers"][0]
    assert server["domain"] == "example.local"
    assert server["domain_search"] == "corp.local"


def test_dhcp_discover_returns_error_on_failure(monkeypatch):
    monkeypatch.setattr(net_discovery.shutil, "which", lambda _tool: True)
    monkeypatch.setattr(net_discovery, "_run_cmd", lambda *_a, **_k: (1, "", "boom"))

    result = net_discovery.dhcp_discover(interface=None)

    assert result["error"] == "boom"


def test_discover_networks_arp_dedupes(monkeypatch):
    monkeypatch.setattr(
        net_discovery,
        "_check_tools",
        lambda: {"arp-scan": True, "netdiscover": True},
    )
    monkeypatch.setattr(net_discovery.shutil, "which", lambda _tool: True)
    monkeypatch.setattr(
        net_discovery,
        "arp_scan_active",
        lambda *_a, **_k: {"hosts": [{"ip": "192.168.1.1"}], "error": None},
    )
    monkeypatch.setattr(
        net_discovery,
        "netdiscover_scan",
        lambda *_a, **_k: {"hosts": [{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}]},
    )

    result = net_discovery.discover_networks(
        target_networks=["192.168.1.0/24"],
        protocols=["arp"],
    )

    assert {host["ip"] for host in result["arp_hosts"]} == {"192.168.1.1", "192.168.1.2"}


def test_redteam_ldap_enum_parses_rootdse(monkeypatch):
    monkeypatch.setattr(net_discovery.shutil, "which", lambda _tool: True)

    out = "\n".join(
        [
            "defaultNamingContext: DC=corp,DC=local",
            "rootDomainNamingContext: DC=corp,DC=local",
            "dnsHostName: dc1.corp.local",
            "supportedLDAPVersion: 3",
        ]
    )
    monkeypatch.setattr(net_discovery, "_run_cmd", lambda *_a, **_k: (0, out, ""))

    result = net_discovery._redteam_ldap_enum(["192.168.1.10"], tools={"ldapsearch": True})

    assert result["status"] == "ok"
    assert result["hosts"][0]["defaultNamingContext"] == "DC=corp,DC=local"


def test_redteam_kerberos_enum_with_userenum(monkeypatch, tmp_path):
    monkeypatch.setattr(net_discovery.shutil, "which", lambda _tool: True)
    userlist = tmp_path / "users.txt"
    userlist.write_text("user1\n", encoding="utf-8")

    def _fake_run_cmd(args, *_a, **_k):
        cmd = " ".join(args)
        if "krb5-info" in cmd:
            return 0, "Realm: EXAMPLE.COM", ""
        if "kerbrute" in cmd:
            return 0, "VALID USERNAME: user1@EXAMPLE.COM", ""
        return 1, "", "nope"

    monkeypatch.setattr(net_discovery, "_run_cmd", _fake_run_cmd)

    result = net_discovery._redteam_kerberos_enum(
        ["192.168.1.10"],
        tools={"nmap": True, "kerbrute": True},
        userlist_path=str(userlist),
    )

    assert result["status"] == "ok"
    assert result["userenum"]["status"] == "ok"
    assert "user1" in result["userenum"]["valid_users_sample"]
