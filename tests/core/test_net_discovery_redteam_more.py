#!/usr/bin/env python3
"""
Extra coverage for net_discovery redteam helpers.
"""

import builtins
import sys
import types
from unittest.mock import MagicMock

from redaudit.core import redteam


def test_redteam_snmp_walk_parses_output(monkeypatch):
    tools = {"snmpwalk": True}

    def _which(name):
        return "/usr/bin/snmpwalk" if name == "snmpwalk" else None

    def _run_cmd(_args, _timeout_s=None, logger=None, **_kwargs):
        output = ".1.3.6.1.2.1.1.1.0 = STRING: Test Device\n"
        return 0, output, ""

    monkeypatch.setattr(redteam.shutil, "which", _which)
    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd)

    result = redteam._redteam_snmp_walk(["10.0.0.1"], tools, community="public")
    assert result["status"] == "ok"
    assert result["hosts"][0]["sysDescr"] == "Test Device"


def test_redteam_snmp_walk_no_targets():
    result = redteam._redteam_snmp_walk([], {"snmpwalk": True})
    assert result["status"] == "no_targets"


def test_redteam_snmp_walk_tool_missing(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: None)
    result = redteam._redteam_snmp_walk(["10.0.0.1"], {"snmpwalk": False})
    assert result["status"] == "tool_missing"


def test_redteam_smb_enum_uses_enum4linux(monkeypatch):
    tools = {"enum4linux": True, "nmap": False}

    def _which(name):
        return "/usr/bin/enum4linux" if name == "enum4linux" else None

    def _run_cmd(_args, _timeout_s=None, logger=None, **_kwargs):
        return 0, "ENUM4LINUX OUTPUT", ""

    monkeypatch.setattr(redteam.shutil, "which", _which)
    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd)

    result = redteam._redteam_smb_enum(["10.0.0.2"], tools)
    assert result["tool"] == "enum4linux"
    assert result["hosts"][0]["raw"] == "ENUM4LINUX OUTPUT"


def test_redteam_smb_enum_tool_missing(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: None)
    result = redteam._redteam_smb_enum(["10.0.0.2"], {"enum4linux": False, "nmap": False})
    assert result["status"] == "tool_missing"


def test_redteam_smb_enum_parses_nmap(monkeypatch):
    tools = {"enum4linux": False, "nmap": True}

    def _which(name):
        return "/usr/bin/nmap" if name == "nmap" else None

    def _run_cmd(_args, _timeout_s=None, logger=None, **_kwargs):
        output = "OS: Windows 10\nComputer name: HOST1\nDomain name: EXAMPLE\n"
        return 0, output, ""

    monkeypatch.setattr(redteam.shutil, "which", _which)
    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd)

    result = redteam._redteam_smb_enum(["10.0.0.3"], tools)
    host = result["hosts"][0]
    assert host["tool"] == "nmap"
    assert host["os"] == "Windows 10"
    assert host["computer_name"] == "HOST1"
    assert host["domain"] == "EXAMPLE"


def test_redteam_rustscan_sweep_parses_ports(monkeypatch):
    tools = {"rustscan": True}

    def _run_multi(*args, **kwargs):
        return {"10.0.0.10": [445]}, None

    monkeypatch.setattr(redteam, "run_rustscan_multi", _run_multi)

    result = redteam._redteam_rustscan_sweep(["10.0.0.0/30"], tools)
    assert result["status"] == "ok"
    assert result["open_ports"][0]["port"] == 445


def test_redteam_rustscan_returns_error(monkeypatch):
    tools = {"rustscan": True}

    def _run_multi(*args, **kwargs):
        return {}, "Rustscan failed"

    monkeypatch.setattr(redteam, "run_rustscan_multi", _run_multi)

    result = redteam._redteam_rustscan_sweep(["10.0.0.0/30"], tools)
    assert result["status"] == "error"
    assert "Rustscan failed" in result["error"]


def test_redteam_rustscan_no_results(monkeypatch):
    tools = {"rustscan": True}
    monkeypatch.setattr(redteam, "run_rustscan_multi", lambda *a, **k: ({}, None))
    # If no ports found, returns 'no_data' status?
    # Let's check implementation behavior
    result = redteam._redteam_rustscan_sweep(["10.0.0.0/16"], tools)
    assert result["status"] == "no_data"


def test_tcpdump_capture_paths(monkeypatch):
    tools = {"tcpdump": True}

    monkeypatch.setattr(redteam, "_is_root", lambda: True)
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/tcpdump")
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "sample", ""))

    assert redteam._tcpdump_capture("", "arp", tools, 1)["status"] == "skipped_no_interface"

    result = redteam._tcpdump_capture("eth0", "arp", tools, 1)
    assert result["status"] == "ok"
    assert result["raw_sample"] == "sample"


def test_tcpdump_capture_tool_missing(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: None)
    result = redteam._tcpdump_capture("eth0", "arp", {"tcpdump": False}, 1)
    assert result["status"] == "tool_missing"


def test_redteam_rpc_enum_rpcclient_parses(monkeypatch):
    tools = {"rpcclient": True, "nmap": False}

    def _which(name):
        return "/usr/bin/rpcclient" if name == "rpcclient" else None

    output = "\n".join(
        [
            "OS version: 10.0",
            "Server type: 0x1234",
            "Comment: Example",
            "Domain: EXAMPLE",
        ]
    )

    monkeypatch.setattr(redteam.shutil, "which", _which)
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, output, ""))

    result = redteam._redteam_rpc_enum(["10.0.0.4"], tools)
    host = result["hosts"][0]
    assert host["tool"] == "rpcclient"
    assert host["os_version"] == "10.0"
    assert host["domain"] == "EXAMPLE"


def test_redteam_rpc_enum_tool_missing(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: None)
    result = redteam._redteam_rpc_enum(["10.0.0.4"], {"rpcclient": False, "nmap": False})
    assert result["status"] == "tool_missing"


def test_redteam_rpc_enum_nmap_raw(monkeypatch):
    tools = {"rpcclient": False, "nmap": True}

    def _which(name):
        return "/usr/bin/nmap" if name == "nmap" else None

    monkeypatch.setattr(redteam.shutil, "which", _which)
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "Nmap output", ""))

    result = redteam._redteam_rpc_enum(["10.0.0.4"], tools)
    host = result["hosts"][0]
    assert host["tool"] == "nmap"
    assert host["raw"] == "Nmap output"


def test_redteam_dns_zone_transfer_no_targets(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/dig")
    result = redteam._redteam_dns_zone_transfer({"dhcp_servers": []}, {"dig": True})
    assert result["status"] == "no_targets"


def test_redteam_dns_zone_transfer_success(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/dig")

    def _run_cmd(_args, _timeout_s=None, logger=None, **_kwargs):
        output = "\n".join(
            [
                "example.local. 300 IN A 10.0.0.1",
                "XFR size: 2 records",
            ]
        )
        return 0, output, ""

    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd)

    discovery = {
        "dhcp_servers": [
            {"dns": ["10.0.0.53"], "domain": "example.local"},
        ]
    }
    result = redteam._redteam_dns_zone_transfer(discovery, {"dig": True})
    assert result["status"] == "ok"
    assert result["zone"] == "example.local"


def test_run_cmd_exception(monkeypatch):
    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *_a, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr(redteam, "CommandRunner", _Runner)
    rc, _out, err = redteam._run_cmd(["echo", "hi"], timeout_s=1)
    assert rc == -1
    assert err


def test_sanitize_iface_and_zone():
    assert redteam._sanitize_iface("eth0") == "eth0"
    assert redteam._sanitize_iface("bad iface") is None
    assert redteam._sanitize_iface(None) is None

    assert redteam._sanitize_dns_zone("example.local") == "example.local"
    assert redteam._sanitize_dns_zone("bad..zone") is None
    assert redteam._sanitize_dns_zone("") is None


def test_index_open_tcp_ports_filters_invalid():
    res = redteam._index_open_tcp_ports(
        {
            "open_ports": [
                "bad",
                {"ip": "not-an-ip", "port": 80, "protocol": "tcp"},
                {"ip": "1.1.1.1", "port": "x", "protocol": "tcp"},
                {"ip": "1.1.1.1", "port": 80, "protocol": "udp"},
                {"ip": "1.1.1.1", "port": 80, "protocol": "tcp"},
            ]
        }
    )
    assert res == {"1.1.1.1": {80}}


def test_filter_targets_helpers():
    open_tcp = {"1.1.1.1": {445}, "1.1.1.2": {80}}
    targets = ["1.1.1.1", "1.1.1.2"]
    assert redteam._filter_targets_by_port(targets, open_tcp, "bad", 1) == ["1.1.1.1"]
    assert redteam._filter_targets_by_any_port(targets, open_tcp, ["bad"], 1) == ["1.1.1.1"]


def test_gather_redteam_targets_excludes_ips():
    discovery = {
        "alive_hosts": ["10.0.0.1", "10.0.0.2"],
        "arp_hosts": [{"ip": "10.0.0.3"}],
        "netbios_hosts": [{"ip": "10.0.0.4"}],
        "dhcp_servers": [{"ip": "10.0.0.5"}],
    }
    result = redteam._gather_redteam_targets(
        discovery,
        max_targets=10,
        exclude_ips={"10.0.0.2", "10.0.0.3"},
    )
    assert result == ["10.0.0.1", "10.0.0.4", "10.0.0.5"]


def test_redteam_snmp_walk_error_and_timeout(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/snmpwalk")

    def _run_cmd(_args, _timeout_s=None, logger=None, **_kwargs):
        return 1, "", "connection refused"

    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd)
    result = redteam._redteam_snmp_walk(["10.0.0.1"], {"snmpwalk": True})
    assert result["errors"]

    def _run_cmd_timeout(_args, _timeout_s=None, logger=None, **_kwargs):
        return 1, "", "timeout"

    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd_timeout)
    result = redteam._redteam_snmp_walk(["10.0.0.1"], {"snmpwalk": True})
    assert result["status"] == "no_data"


def test_redteam_smb_enum_empty_snippet(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/enum4linux")
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "", ""))
    result = redteam._redteam_smb_enum(["10.0.0.1"], {"enum4linux": True})
    assert result["status"] == "no_data"


def test_redteam_smb_enum_nmap_snippet(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(redteam, "_parse_smb_nmap", lambda _text: {})
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "raw output", ""))
    result = redteam._redteam_smb_enum(["10.0.0.1"], {"enum4linux": False, "nmap": True})
    assert result["hosts"][0]["raw"] == "raw output"


def test_redteam_rustscan_no_targets():
    result = redteam._redteam_rustscan_sweep([], {"rustscan": True})
    assert result["status"] == "no_targets"


def test_run_cmd_exception_logs(monkeypatch):
    logger = MagicMock()

    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *_a, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr(redteam, "CommandRunner", _Runner)
    rc, _out, _err = redteam._run_cmd(["echo", "hi"], timeout_s=1, logger=logger)
    assert rc == -1
    assert logger.error.called


def test_run_redteam_discovery_progress_errors(monkeypatch):
    result = {"tools": {}}
    options = {"max_targets": "bad", "snmp_community": 123, "use_masscan": False}

    def _progress(*_args, **_kwargs):
        raise RuntimeError("boom")

    class _Thread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return None

        def join(self, timeout=None):
            raise RuntimeError("boom")

    monkeypatch.setattr(redteam.threading, "Thread", _Thread)
    monkeypatch.setattr(redteam, "_gather_redteam_targets", lambda *_a, **_k: [])
    for name in (
        "_redteam_rustscan_sweep",
        "_redteam_snmp_walk",
        "_redteam_smb_enum",
        "_redteam_rpc_enum",
        "_redteam_ldap_enum",
        "_redteam_kerberos_enum",
        "_redteam_dns_zone_transfer",
        "_redteam_vlan_enum",
        "_redteam_stp_topology",
        "_redteam_hsrp_vrrp_discovery",
        "_redteam_llmnr_nbtns_capture",
        "_redteam_router_discovery",
        "_redteam_ipv6_discovery",
        "_redteam_bettercap_recon",
        "_redteam_scapy_custom",
    ):
        monkeypatch.setattr(redteam, name, lambda *_a, **_k: {"status": "skipped"})

    redteam.run_redteam_discovery(
        result,
        ["10.0.0.0/24"],
        redteam_options=options,
        progress_callback=_progress,
        progress_step=1,
        progress_total=2,
    )
    assert result["redteam"]["enabled"] is True


def test_is_root_handles_exception(monkeypatch):
    monkeypatch.setattr(redteam.os, "geteuid", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert redteam._is_root() is False


def test_safe_truncate_invalid_inputs():
    assert redteam._safe_truncate(None, 10) == ""
    assert redteam._safe_truncate("text", 0) == ""


def test_tcpdump_capture_requires_root(monkeypatch):
    monkeypatch.setattr(redteam, "_is_root", lambda: False)
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/tcpdump")
    res = redteam._tcpdump_capture("eth0", "arp", {"tcpdump": True}, 1)
    assert res["status"] == "skipped_requires_root"


def test_tcpdump_capture_packet_bounds_and_error(monkeypatch):
    monkeypatch.setattr(redteam, "_is_root", lambda: True)
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/tcpdump")
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (1, "", "bad"))
    res = redteam._tcpdump_capture("eth0", "arp", {"tcpdump": True}, 1, packets=0)
    assert res["error"] == "bad"
    res = redteam._tcpdump_capture("eth0", "arp", {"tcpdump": True}, 1, packets=999)
    assert res["error"] == "bad"


def test_redteam_rpc_enum_empty_snippet(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/rpcclient")
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "", ""))
    res = redteam._redteam_rpc_enum(["10.0.0.1"], {"rpcclient": True, "nmap": False})
    assert res["status"] == "no_data"


def test_redteam_rpc_enum_nmap_raw(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "raw output", ""))
    res = redteam._redteam_rpc_enum(["10.0.0.2"], {"rpcclient": False, "nmap": True})
    assert res["hosts"][0]["raw"] == "raw output"


def test_redteam_rpc_enum_future_exception(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/rpcclient")

    def _boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(redteam, "_run_cmd", _boom)
    res = redteam._redteam_rpc_enum(["10.0.0.3"], {"rpcclient": True, "nmap": False})
    assert res["status"] == "no_data"


def test_redteam_ldap_enum_tool_missing(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: None)
    res = redteam._redteam_ldap_enum(["10.0.0.1"], {"ldapsearch": False, "nmap": False})
    assert res["status"] == "tool_missing"


def test_redteam_ldap_enum_ldapsearch_raw(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/ldapsearch")
    monkeypatch.setattr(redteam, "_parse_ldap_rootdse", lambda _t: {})
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "raw", ""))
    res = redteam._redteam_ldap_enum(["10.0.0.2"], {"ldapsearch": True, "nmap": False})
    assert res["hosts"][0]["raw"] == "raw"


def test_redteam_ldap_enum_nmap_parsed(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(redteam, "_parse_ldap_rootdse", lambda _t: {"defaultNamingContext": "x"})
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "ok", ""))
    res = redteam._redteam_ldap_enum(["10.0.0.3"], {"ldapsearch": False, "nmap": True})
    assert res["hosts"][0]["defaultNamingContext"] == "x"


def test_redteam_ldap_enum_nmap_raw(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(redteam, "_parse_ldap_rootdse", lambda _t: {})
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, "raw", ""))
    res = redteam._redteam_ldap_enum(["10.0.0.4"], {"ldapsearch": False, "nmap": True})
    assert res["hosts"][0]["raw"] == "raw"


def test_redteam_ldap_enum_future_exception(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/ldapsearch")
    monkeypatch.setattr(
        redteam, "_run_cmd", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    res = redteam._redteam_ldap_enum(["10.0.0.5"], {"ldapsearch": True, "nmap": False})
    assert res["status"] == "no_data"


def test_redteam_kerberos_enum_tool_missing(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: None)
    res = redteam._redteam_kerberos_enum(["10.0.0.1"], {"nmap": False, "kerbrute": False})
    assert res["status"] == "tool_missing"


def test_redteam_kerberos_enum_userenum_errors(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/kerbrute")
    monkeypatch.setattr(redteam.os.path, "exists", lambda _p: True)

    def _run_cmd(_cmd, *_a, **_k):
        users = "\n".join([f"VALID USERNAME: user{i}@EXAMPLE.COM" for i in range(60)])
        return 1, users, "fail"

    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd)
    res = redteam._redteam_kerberos_enum(
        ["10.0.0.1"], {"nmap": False, "kerbrute": True}, realm="EXAMPLE.COM", userlist_path="list"
    )
    assert res["userenum"]["error"] == "fail"
    assert len(res["userenum"]["valid_users_sample"]) == 50


def test_extract_dhcp_helpers_skip_invalid():
    discovery = {"dhcp_servers": ["bad", {"dns": ["1.1.1.1"], "domain": "example.local"}]}
    assert redteam._extract_dhcp_dns_servers(discovery) == ["1.1.1.1"]
    assert redteam._extract_dhcp_domains({"dhcp_servers": ["bad"]}) == []


def test_redteam_dns_zone_transfer_record_limit(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/dig")
    lines = "\n".join([f"example.local. 300 IN A 10.0.0.{i}" for i in range(60)])

    def _run_cmd(*_a, **_k):
        return 0, lines + "\nXFR size: 60", ""

    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd)
    discovery = {"dhcp_servers": [{"dns": ["10.0.0.53"], "domain": "example.local"}]}
    res = redteam._redteam_dns_zone_transfer(discovery, {"dig": True}, zone="example.local")
    assert len(res["attempts"][0]["records_sample"]) == 50


def test_redteam_vlan_enum_invalid_vlan_and_error(monkeypatch):
    monkeypatch.setattr(
        redteam,
        "_tcpdump_capture",
        lambda *_a, **_k: {"status": "ok", "raw_sample": "vlan abc", "error": "err"},
    )
    res = redteam._redteam_vlan_enum("eth0", {"tcpdump": True})
    assert res["status"] == "no_data"
    assert res["error"] == "err"


def test_redteam_stp_topology_error(monkeypatch):
    monkeypatch.setattr(
        redteam,
        "_tcpdump_capture",
        lambda *_a, **_k: {"status": "ok", "raw_sample": "root id 1", "error": "err"},
    )
    res = redteam._redteam_stp_topology("eth0", {"tcpdump": True})
    assert res["error"] == "err"


def test_redteam_hsrp_vrrp_limits_and_error(monkeypatch):
    ips = " ".join([f"10.0.0.{i}" for i in range(30)])
    monkeypatch.setattr(
        redteam,
        "_tcpdump_capture",
        lambda *_a, **_k: {"status": "ok", "raw_sample": f"HSRP {ips}", "error": "err"},
    )
    res = redteam._redteam_hsrp_vrrp_discovery("eth0", {"tcpdump": True})
    assert len(res["ip_candidates"]) == 20
    assert res["error"] == "err"


def test_redteam_llmnr_nbtns_error(monkeypatch):
    raw = "\n\n10.0.0.1.5355 ? HOST\n10.0.0.2 137 ? NAME"
    monkeypatch.setattr(
        redteam,
        "_tcpdump_capture",
        lambda *_a, **_k: {"status": "ok", "raw_sample": raw, "error": "err"},
    )
    res = redteam._redteam_llmnr_nbtns_capture("eth0", {"tcpdump": True})
    assert res["error"] == "err"


def test_redteam_router_discovery_limits(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/nmap")
    raw = " ".join([f"10.0.0.{i}" for i in range(30)])
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (0, raw, ""))
    res = redteam._redteam_router_discovery("eth0", {"nmap": True})
    assert len(res["router_candidates"]) == 20


def test_redteam_router_discovery_fallback_limits(monkeypatch):
    raw = " ".join([f"10.0.0.{i}" for i in range(30)])
    monkeypatch.setattr(
        redteam,
        "_tcpdump_capture",
        lambda *_a, **_k: {"status": "ok", "raw_sample": raw, "error": None},
    )
    res = redteam._redteam_router_discovery("eth0", {"nmap": False})
    assert len(res["router_candidates"]) == 20


def test_parse_ip6_neighbors_edge_cases():
    text = "fe80::1 dev eth0 lladdr\nfe80::2 dev\n"
    res = redteam._parse_ip6_neighbors(text)
    assert res


def test_redteam_ipv6_discovery_requires_root(monkeypatch):
    monkeypatch.setattr(redteam, "_is_root", lambda: False)
    res = redteam._redteam_ipv6_discovery("eth0", {"ping6": True})
    assert res["status"] == "skipped_requires_root"


def test_redteam_ipv6_discovery_ping_errors(monkeypatch):
    monkeypatch.setattr(redteam, "_is_root", lambda: True)
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/ping6")

    def _run_cmd(cmd, *_a, **_k):
        if cmd[0] == "ping6":
            return 1, "", "fail"
        return 0, "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff", ""

    monkeypatch.setattr(redteam, "_run_cmd", _run_cmd)
    res = redteam._redteam_ipv6_discovery("eth0", {"ping6": True, "ip": True})
    assert res["errors"]


def test_redteam_ipv6_discovery_ping_fallback(monkeypatch):
    monkeypatch.setattr(redteam, "_is_root", lambda: True)
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/ping")
    monkeypatch.setattr(redteam, "_run_cmd", lambda *_a, **_k: (1, "", "fail"))
    res = redteam._redteam_ipv6_discovery("eth0", {"ping6": False, "ping": True})
    assert res["errors"]


def test_redteam_bettercap_missing_tool(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: None)
    res = redteam._redteam_bettercap_recon("eth0", {"bettercap": False}, active_l2=True)
    assert res["status"] == "tool_missing"


def test_redteam_bettercap_requires_root(monkeypatch):
    monkeypatch.setattr(redteam.shutil, "which", lambda _name: "/usr/bin/bettercap")
    monkeypatch.setattr(redteam, "_is_root", lambda: False)
    res = redteam._redteam_bettercap_recon("eth0", {"bettercap": True}, active_l2=True)
    assert res["status"] == "skipped_requires_root"


def test_redteam_scapy_custom_disabled():
    res = redteam._redteam_scapy_custom("eth0", {"scapy": True}, active_l2=False)
    assert res["status"] == "skipped_disabled"


def test_redteam_scapy_custom_requires_root(monkeypatch):
    monkeypatch.setattr(redteam, "_is_root", lambda: False)
    res = redteam._redteam_scapy_custom("eth0", {"scapy": True}, active_l2=True)
    assert res["status"] == "skipped_requires_root"


def test_redteam_scapy_custom_import_error(monkeypatch):
    monkeypatch.setattr(redteam, "_is_root", lambda: True)
    real_import = __import__

    def _blocked_import(name, *args, **kwargs):
        if name == "scapy":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(sys, "modules", dict(sys.modules))
    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    res = redteam._redteam_scapy_custom("eth0", {"scapy": True}, active_l2=True)
    assert res["status"] == "tool_missing"


def test_redteam_scapy_custom_on_pkt_error(monkeypatch):
    monkeypatch.setattr(redteam, "_is_root", lambda: True)
    fake_scapy = types.SimpleNamespace(__version__="1.0")

    class _Pkt:
        def haslayer(self, *_a, **_k):
            raise RuntimeError("boom")

    def _sniff(*_a, **_k):
        _k["prn"](_Pkt())

    fake_all = types.SimpleNamespace(
        Dot1Q=object(), sniff=_sniff, conf=types.SimpleNamespace(verb=0)
    )
    monkeypatch.setitem(sys.modules, "scapy", fake_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_all)
    res = redteam._redteam_scapy_custom("eth0", {"scapy": True}, active_l2=True)
    assert res["status"] == "no_data"
