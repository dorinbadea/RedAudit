#!/usr/bin/env python3
"""
RedAudit - Topology Discovery Tests
Copyright (C) 2026  Dorin Badea
GPLv3 License

Unit tests for redaudit/core/topology.py (best-effort topology discovery).
"""

import os
import sys
import unittest
import asyncio
import ipaddress
import shutil
from unittest.mock import MagicMock, patch

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.topology import (  # noqa: E402
    _discover_topology_async,
    _discover_topology_sync,
    _extract_lldp_neighbors,
    _networks_from_route_table,
    _parse_arp_scan,
    _parse_ip_neigh,
    _parse_ip_route,
    _parse_vlan_ids_from_ip_link,
    _parse_vlan_ids_from_tcpdump,
    discover_topology,
    _run_cmd,
)


class TestTopologyParsing(unittest.TestCase):
    def test_parse_ip_route(self):
        # Normal
        stdout = (
            "default via 1.1.1.1 dev eth0\n10.0.0.0/8 via 1.1.1.2 dev eth0 src 1.1.1.3 metric 10\n"
        )
        self.assertEqual(len(_parse_ip_route(stdout)), 2)
        # Exception branches (65, 73, 78, 83)
        self.assertEqual(len(_parse_ip_route("default via")), 1)
        self.assertEqual(len(_parse_ip_route("1.1.1.0/24 via")), 1)
        self.assertEqual(len(_parse_ip_route("1.1.1.0/24 dev")), 1)
        self.assertEqual(len(_parse_ip_route("1.1.1.0/24 src")), 1)
        self.assertEqual(len(_parse_ip_route("1.1.1.0/24 metric")), 1)
        # Empty lines (53)
        self.assertEqual(len(_parse_ip_route("\n   \n")), 0)

    def test_parse_arp_scan(self):
        tab = "\t"
        stdout = (
            f"Interface: e0\nStarting\\nEnding\nWARNING\n1.1.1.1{tab}AA:BB:CC:DD:EE:FF{tab}Vendor\n"
        )
        self.assertEqual(len(_parse_arp_scan(stdout)), 1)
        # Empty lines (106)
        self.assertEqual(len(_parse_arp_scan("\n\n")), 0)
        # No match (113)
        self.assertEqual(len(_parse_arp_scan("invalid line")), 0)

    def test_parse_ip_neigh(self):
        stdout = "1.1.1.1 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n2.2.2.2 dev\n\n"
        res = _parse_ip_neigh(stdout)
        self.assertEqual(len(res), 2)
        # State (143)
        self.assertEqual(res[0]["state"], "REACHABLE")
        # lladdr exception (140)
        self.assertEqual(len(_parse_ip_neigh("1.1.1.1 lladdr")), 1)

    def test_parse_vlan_ids(self):
        self.assertEqual(_parse_vlan_ids_from_ip_link("vlan id 10"), [10])
        self.assertEqual(_parse_vlan_ids_from_tcpdump("vlan 20"), [20])
        # re.finditer exception (160, 172)
        with patch("redaudit.core.topology.re.finditer") as miter:
            m = MagicMock()
            m.group.return_value = "invalid"
            miter.return_value = [m]
            self.assertEqual(_parse_vlan_ids_from_ip_link("x"), [])
            self.assertEqual(_parse_vlan_ids_from_tcpdump("x"), [])

    def test_extract_lldp_neighbors(self):
        self.assertEqual(_extract_lldp_neighbors({}, "e0"), [])
        # Exception (217)
        with patch("redaudit.core.topology.isinstance", side_effect=Exception()):
            self.assertEqual(_extract_lldp_neighbors({"lldp": {"interface": {"e0": {}}}}, "e0"), [])
        # Multiple neighbors (189)
        data = {
            "lldp": {
                "interface": {"e0": [{"chassis": {"name": "sw1"}}, {"chassis": {"name": "sw2"}}]}
            }
        }
        self.assertEqual(len(_extract_lldp_neighbors(data, "e0")), 2)
        # Single neighbor (191)
        data = {"lldp": {"interface": {"e0": {"chassis": {"name": "n"}}}}}
        self.assertEqual(len(_extract_lldp_neighbors(data, "e0")), 1)
        # Empty neighbor prune (222)
        data = {"lldp": {"interface": {"e0": {"chassis": {}, "port": {}}}}}
        self.assertEqual(len(_extract_lldp_neighbors(data, "e0")), 0)

    def test_extract_lldp_neighbors_get_exception(self):
        class _Bad:
            def get(self, *_args, **_kwargs):
                raise Exception("boom")

        self.assertEqual(_extract_lldp_neighbors(_Bad(), "e0"), [])

    def test_networks_from_route_table(self):
        # 234 continue (default/none), 236 continue (no /), 241 continue (invalid)
        routes = [
            {"dst": "1.1.1.0/24"},
            {"dst": "1.1.1.1"},  # 236 no /
            {"dst": "default"},  # 234 default
            {"dst": "CRASH/24"},  # 241 crash
        ]
        real_ip_net = ipaddress.ip_network

        def se(val, **kwargs):
            if "CRASH" in str(val):
                raise Exception("crash")
            return real_ip_net(val, **kwargs)

        with patch("redaudit.core.topology.ipaddress.ip_network", side_effect=se):
            self.assertEqual(len(_networks_from_route_table(routes)), 1)


class TestTopologyAsyncScenarios(unittest.TestCase):
    async def mock_run_async(self, args, **kwargs):
        if "route" in args:
            return 0, "default via 1.1.1.1 dev eth0\n10.0.0.0/8 via 1.1.1.1", ""
        if "lldpctl" in args:
            if getattr(self, "lldp_fail_connect", False):
                return 1, "", "socket unable to connect"
            return (
                0,
                '{"lldp": {"interface": {"eth0": {"chassis": {"id": {"value": "v1"}, "name": "sw1"}}}}}',
                "",
            )
        if "arp-scan" in args:
            if getattr(self, "arp_fail", False):
                raise Exception("arp fatal")
            return 0, "1.1.1.1\tAA:BB:CC:DD:EE:FF\tVendor", ""
        if "neigh" in args:
            if getattr(self, "neigh_fail", False):
                raise Exception("neigh fatal")
            return 0, "1.1.1.1 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE", ""
        if "link" in args:
            if getattr(self, "link_fail", False):
                raise Exception("link fatal")
            return 0, "vlan id 10", ""
        if "tcpdump" in args:
            return 0, "vlan 20\nCDP data", ""
        return 0, "", ""

    def test_async_scenarios(self):
        with patch("redaudit.core.topology._run_cmd_async", side_effect=self.mock_run_async):
            with patch("shutil.which", return_value="/bin/tool"):
                # Complete async run
                topo = asyncio.run(
                    _discover_topology_async(
                        ["10.0.0.0/8"], [{"interface": "eth0", "network": "10.0.0.0/8"}]
                    )
                )
                self.assertTrue(topo["enabled"])
                # 428 dedup
                topo = asyncio.run(
                    _discover_topology_async([], [{"interface": "eth0"}, {"interface": "eth0"}])
                )
                self.assertEqual(len(topo["interfaces"]), 1)

    def test_async_errors(self):
        # 503, 514, 529 Exceptions
        self.arp_fail = True
        self.neigh_fail = True
        self.link_fail = True
        with patch("redaudit.core.topology._run_cmd_async", side_effect=self.mock_run_async):
            with patch("shutil.which", return_value="/bin/tool"):
                topo = asyncio.run(_discover_topology_async([], [{"interface": "eth0"}]))
                self.assertTrue(topo["interfaces"][0]["arp"]["error"])
                self.assertTrue(topo["interfaces"][0]["neighbor_cache"]["error"])

    def test_async_lldpctl_invalid_json(self):
        async def mock_run_async(args, **_kwargs):
            if "route" in args:
                return 0, "default via 1.1.1.1 dev eth0", ""
            if "lldpctl" in args:
                return 0, "{not-json", ""
            return 0, "", ""

        with patch("redaudit.core.topology._run_cmd_async", side_effect=mock_run_async):
            with patch("shutil.which", return_value="/bin/tool"):
                topo = asyncio.run(
                    _discover_topology_async(["10.0.0.0/8"], [{"interface": "eth0"}])
                )
                self.assertIn("routes", topo)

    def test_async_lldpctl_socket_hint(self):
        async def mock_run_async(args, **_kwargs):
            if "route" in args:
                return 0, "default via 1.1.1.1 dev eth0", ""
            if "lldpctl" in args:
                return 1, "", "socket unable to connect"
            return 0, "", ""

        with patch("redaudit.core.topology._run_cmd_async", side_effect=mock_run_async):
            with patch("shutil.which", return_value="/bin/tool"):
                topo = asyncio.run(_discover_topology_async([], [{"interface": "eth0"}]))
                self.assertTrue(any("Hint" in e for e in topo["errors"]))

    def test_async_lldp_tcpdump_and_cdp_limits(self):
        async def mock_run_async(args, **_kwargs):
            if args[:2] == ["ip", "route"]:
                return 0, "default via 1.1.1.1 dev eth0\n127.0.0.0/8 dev lo", ""
            if args[0] == "arp-scan":
                return 0, "1.1.1.1\tAA:BB:CC:DD:EE:FF\tVendor", ""
            if args[0:2] == ["ip", "neigh"]:
                return 0, "1.1.1.1 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE", ""
            if args[0:2] == ["ip", "-d"]:
                return 0, "vlan id 10", ""
            if args[0] == "tcpdump" and "vlan" in args:
                return 0, "vlan 20", ""
            if args[0] == "tcpdump" and "01:00:0c:cc:cc:cc" in args:
                lines = [f"line {i}" for i in range(12)]
                return 0, "\n".join(lines), ""
            if args[0] == "tcpdump" and "0x88cc" in args:
                out = "\n".join(
                    [
                        "System Name TLV (5), length 18: Switch-01",
                        "Port ID TLV (2), length 11: Gi1/0/1",
                    ]
                )
                return 0, out, ""
            if args[0] == "ifconfig":
                return 0, "vlan: 100 parent interface: en0", ""
            return 0, "", ""

        def _which(name):
            if name == "lldpctl":
                return None
            return "/bin/tool"

        with patch("redaudit.core.topology._run_cmd_async", side_effect=mock_run_async):
            with patch("shutil.which", side_effect=_which):
                topo = asyncio.run(
                    _discover_topology_async(
                        ["10.0.0.0/8", "bad-net"], [{"interface": "eth0", "network": "10.0.0.0/8"}]
                    )
                )
                iface = topo["interfaces"][0]
                self.assertTrue(iface["lldp"]["neighbors"])
                self.assertLessEqual(len(iface["cdp"]["observations"]), 10)

    def test_async_results_basesexception(self):
        # Line 564
        async def mock_gather_wrap(*args, **kwargs):
            return [BaseException(), ({"interface": "e0", "networks": []}, [])]

        with patch("redaudit.core.topology.asyncio.gather", side_effect=mock_gather_wrap):
            with patch("shutil.which", return_value="/bin/tool"):
                topo = asyncio.run(_discover_topology_async([], []))
                self.assertEqual(len(topo["interfaces"]), 1)

    def test_async_loops_exceptions(self):
        # 388, 577, 585
        real_ip_net = ipaddress.ip_network

        def se(val, **kwargs):
            if "CRASH" in str(val):
                raise Exception("crash")
            return real_ip_net(val, **kwargs)

        with patch("redaudit.core.topology.ipaddress.ip_network", side_effect=se):
            with patch("redaudit.core.topology._run_cmd_async", side_effect=self.mock_run_async):
                with patch("shutil.which", return_value="/bin/tool"):
                    # 411: local net crash
                    topo = asyncio.run(
                        _discover_topology_async(
                            ["10.0.0.0/8"], [{"interface": "e0", "network": "CRASH"}]
                        )
                    )
                    # Falls back to gateway (eth0 from route table)
                    self.assertEqual(len(topo["interfaces"]), 1)

    def test_collect_iface_async_errors(self):
        async def mock_err(*args, **kwargs):
            return 1, "", "err string"

        with patch("redaudit.core.topology._run_cmd_async", side_effect=mock_err):
            with patch("shutil.which", return_value="/bin/tool"):
                # 393: interface missing
                res = asyncio.run(_discover_topology_async([], [{"interface": None}]))
                self.assertEqual(len(res["interfaces"]), 0)

                # 411: crash in ip_network during overlaps check
                real_ip_net = ipaddress.ip_network

                def se(val, **kwargs):
                    if "CRASH" in str(val):
                        raise Exception("crash")
                    return real_ip_net(val, **kwargs)

                with patch("redaudit.core.topology.ipaddress.ip_network", side_effect=se):
                    # No routes mocked here so default gateway won't be found
                    with patch(
                        "redaudit.core.topology._extract_default_gateway", return_value=None
                    ):
                        topo = asyncio.run(
                            _discover_topology_async(
                                ["10.0.0.0/8"], [{"interface": "eth0", "network": "CRASH"}]
                            )
                        )
                        # No matches, no gateway -> map.keys() which is eth0
                        self.assertEqual(len(topo["interfaces"]), 1)


class TestTopologySyncScenarios(unittest.TestCase):
    def test_sync_coverage(self):
        def mock_sync(args, **kwargs):
            return (
                0,
                "default via 1.1.1.1 dev eth0\n10.0.0.0/8 dev eth0\n127.0.0.0/8 dev lo\n169.254.0.0/16 dev eth0",
                "",
            )

        with patch("shutil.which", return_value="/bin/tool"):
            with patch("redaudit.core.topology._run_cmd", side_effect=mock_sync):
                # 681 fallback interfaces
                topo = _discover_topology_sync([], [])
                # Should find eth0 via default gateway
                self.assertEqual(len(topo["interfaces"]), 1)

                # 653: iface None
                topo = _discover_topology_sync([], [{"interface": None}])
                # Gateway fallback -> eth0
                self.assertEqual(len(topo["interfaces"]), 1)

                # 824: if n in local_nets (match 10.0.0.0/8)
                # 827: skip 127.
                topo = _discover_topology_sync(
                    ["1.1.1.1"], [{"interface": "eth0", "network": "10.0.0.0/8"}]
                )
                self.assertEqual(topo["candidate_networks"], [])

    def test_sync_errors_and_filtering(self):
        def mock_sync(args, **kwargs):
            return 1, "", "failure socket connect"

        with patch("shutil.which", return_value="/bin/tool"):
            with patch("redaudit.core.topology._run_cmd", side_effect=mock_sync):
                # 634: ip route fail
                # 706: lldpctl fail
                # 730: arp-scan fail
                # 740: neigh fail
                # 755: link fail
                topo = _discover_topology_sync([], [{"interface": "e0"}])
                self.assertTrue(topo["errors"])
                self.assertTrue(any("Hint" in e for e in topo["errors"]))  # 705

    def test_sync_exceptions_coverage(self):
        # 647, 670, 816
        real_ip_net = ipaddress.ip_network

        def se(val, **kwargs):
            if "CRASH" in str(val):
                raise Exception("crash")
            return real_ip_net(val, **kwargs)

        with patch("redaudit.core.topology.ipaddress.ip_network", side_effect=se):
            with patch(
                "redaudit.core.topology._run_cmd",
                return_value=(0, "default via 1.1.1.1 dev eth0", ""),
            ):
                with patch("shutil.which", return_value="/bin/tool"):
                    topo = _discover_topology_sync(
                        ["CRASH"], [{"interface": "e0", "network": "CRASH"}]
                    )
                    # Exception handled, falls back to gateway eth0
                    self.assertEqual(len(topo["interfaces"]), 1)

    def test_sync_tcpdump_and_vlan_paths(self):
        def mock_sync(args, **kwargs):
            if args[:2] == ["ip", "route"]:
                return 0, "default via 1.1.1.1 dev eth0\n10.0.0.0/8 dev eth0", ""
            if args[:2] == ["arp-scan", "--localnet"]:
                return 0, "1.1.1.1\tAA:BB:CC:DD:EE:FF\tVendor", ""
            if args[:2] == ["ip", "neigh"]:
                return 0, "1.1.1.1 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE", ""
            if args[:2] == ["ifconfig", "eth0"]:
                return 0, "vlan: 10 parent interface: en0", ""
            if args[:3] == ["ip", "-d", "link"]:
                return 0, "vlan id 20", ""
            if args[0] == "tcpdump" and "vlan" in args:
                return 0, "vlan 30", ""
            if args[0] == "tcpdump" and "0x88cc" in args:
                return 0, "System Name TLV (5), length 18: Switch-01", ""
            if args[0] == "tcpdump" and "01:00:0c:cc:cc:cc" in args:
                lines = [f"line {i}" for i in range(12)]
                return 0, "\n".join(lines), ""
            return 0, "", ""

        def _which(name):
            if name == "lldpctl":
                return None
            return "/bin/tool"

        with patch("shutil.which", side_effect=_which):
            with patch("redaudit.core.topology._run_cmd", side_effect=mock_sync):
                topo = _discover_topology_sync(
                    ["10.0.0.0/8", "bad"], [{"interface": "eth0", "network": "bad"}]
                )
                iface = topo["interfaces"][0]
                self.assertTrue(iface["vlan"]["ids"])
                self.assertTrue(iface["lldp"]["neighbors"])
                self.assertLessEqual(len(iface["cdp"]["observations"]), 10)


class TestTopologyRunCmdDirect(unittest.TestCase):
    def test_run_cmd_internals(self):
        with patch("redaudit.core.topology.CommandRunner") as mock_runner_cls:
            runner_inst = mock_runner_cls.return_value
            res = MagicMock()
            res.returncode = 0
            res.stdout = "out"
            res.stderr = "err"
            runner_inst.run.return_value = res
            rc, o, e = _run_cmd(["test"], 1)
            self.assertEqual(rc, 0)
            self.assertEqual(o, "out")
            runner_inst.run.side_effect = Exception("kaboom")
            with self.assertRaises(Exception):
                _run_cmd(["test"], 1)

    def test_discover_topology_loop_fallback(self):
        # 281: fallback warning
        # Ensure we simulate running loop correctly
        with patch(
            "redaudit.core.topology._discover_topology_sync", return_value={"enabled": True}
        ) as mock_sync:
            with patch(
                "redaudit.core.topology.asyncio.get_running_loop", side_effect=RuntimeError()
            ):

                def _raise_runtime_error(coro, *_args, **_kwargs):
                    try:
                        coro.close()
                    except Exception:
                        pass
                    raise Exception("crash")

                with patch("redaudit.core.topology.asyncio.run", side_effect=_raise_runtime_error):
                    logger = MagicMock()
                    discover_topology([], [], logger=logger)
                    logger.warning.assert_called()
                    mock_sync.assert_called()

    def test_fallback_no_ip_sync(self):
        # 636
        with patch("shutil.which", return_value=None):
            res = _discover_topology_sync([], [])
            self.assertTrue(any("ip command not found" in e for e in res["errors"]))

    def test_extract_lldp_exception(self):
        # 217: exception in lldp extraction
        with patch("redaudit.core.topology.isinstance", side_effect=Exception("crash")):
            res = _extract_lldp_neighbors({"lldp": {"interface": {"e0": {}}}}, "e0")
            self.assertEqual(res, [])
        # 185
        res = _extract_lldp_neighbors({"lldp": {}}, "e0")
        self.assertEqual(res, [])


if __name__ == "__main__":
    unittest.main()
