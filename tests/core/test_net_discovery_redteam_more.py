#!/usr/bin/env python3
"""
Extra coverage for net_discovery redteam helpers.
"""

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
