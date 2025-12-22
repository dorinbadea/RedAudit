#!/usr/bin/env python3
"""
Topology discovery coverage for async and sync paths.
"""

from __future__ import annotations

import json

from redaudit.core import topology


def _fake_run_cmd(args, *_a, **_k):
    cmd = " ".join(args)
    if cmd == "ip route show":
        return (
            0,
            "\n".join(
                [
                    "default via 192.168.1.1 dev eth0",
                    "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10",
                    "10.0.0.0/24 dev tun0 proto kernel scope link src 10.0.0.2",
                ]
            ),
            "",
        )
    if cmd == "lldpctl -f json":
        payload = {
            "lldp": {
                "interface": {
                    "eth0": {
                        "chassis": {"name": "switch1", "descr": "Core Switch"},
                        "port": {"id": {"value": "Gi0/1"}, "descr": "Uplink"},
                    }
                }
            }
        }
        return 0, json.dumps(payload), ""
    if cmd == "arp-scan --localnet --interface eth0":
        return (
            0,
            "\n".join(
                [
                    "192.168.1.1\t00:11:22:33:44:55\tVendor",
                    "192.168.1.5\t66:77:88:99:aa:bb\tVendor",
                ]
            ),
            "",
        )
    if cmd == "ip neigh show dev eth0":
        return (
            0,
            "192.168.1.5 dev eth0 lladdr 66:77:88:99:aa:bb REACHABLE",
            "",
        )
    if cmd == "ip -d link show dev eth0":
        return 0, "vlan id 10", ""
    if cmd == "tcpdump -nn -e -i eth0 -c 20 vlan":
        return 0, "12:00:00 vlan 10, p 0, ethertype IPv4", ""
    if cmd == "tcpdump -nn -e -i eth0 -c 10 ether dst 01:00:0c:cc:cc:cc":
        return 0, "CDP: Device ID: switch1", ""
    return 1, "", "unsupported"


def _fake_which(tool):
    return tool in {"ip", "tcpdump", "arp-scan", "lldpctl"}


def test_discover_topology_async_happy_path(monkeypatch):
    monkeypatch.setattr(topology, "_run_cmd", _fake_run_cmd)
    monkeypatch.setattr(topology.shutil, "which", _fake_which)

    result = topology.discover_topology(
        target_networks=["172.16.0.0/16"],
        network_info=[{"interface": "eth0", "ip": "192.168.1.10", "network": "192.168.1.0/24"}],
    )

    assert result["enabled"] is True
    assert result["default_gateway"]["ip"] == "192.168.1.1"
    assert result["interfaces"]
    iface = result["interfaces"][0]
    assert iface["arp"]["hosts"]
    assert iface["neighbor_cache"]["entries"]
    assert 10 in iface["vlan"]["ids"]
    assert iface["lldp"]["neighbors"]
    assert iface["cdp"]["observations"]
    assert "10.0.0.0/24" in result["candidate_networks"]


def test_discover_topology_sync_fallback(monkeypatch):
    monkeypatch.setattr(topology, "_run_cmd", _fake_run_cmd)
    monkeypatch.setattr(topology.shutil, "which", _fake_which)

    def _raise_runtime_error(coro, *_args, **_kwargs):
        try:
            coro.close()
        except Exception:
            pass
        raise RuntimeError("fail")

    monkeypatch.setattr(topology.asyncio, "run", _raise_runtime_error)

    result = topology.discover_topology(
        target_networks=["172.16.0.0/16"],
        network_info=[{"interface": "eth0", "ip": "192.168.1.10", "network": "192.168.1.0/24"}],
    )

    assert result["enabled"] is True
    assert result["interfaces"]
