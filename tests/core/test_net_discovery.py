#!/usr/bin/env python3
"""
Tests for net_discovery module.
"""

import os
import shutil
import subprocess
import threading
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from redaudit.core import net_discovery
from redaudit.core.net_discovery import (
    _check_tools,
    discover_networks,
    dhcp_discover,
    fping_sweep,
    mdns_discover,
    netbios_discover,
    netdiscover_scan,
    upnp_discover,
    arp_scan_active,
    detect_routed_networks,
    _analyze_vlans,
    _gather_redteam_targets,
    _redteam_bettercap_recon,
    _redteam_dns_zone_transfer,
    _redteam_hsrp_vrrp_discovery,
    _redteam_ipv6_discovery,
    _redteam_kerberos_enum,
    _redteam_ldap_enum,
    _redteam_llmnr_nbtns_capture,
    _redteam_rustscan_sweep,
    _redteam_router_discovery,
    _redteam_rpc_enum,
    _redteam_scapy_custom,
    _redteam_smb_enum,
    _redteam_snmp_walk,
    _redteam_stp_topology,
    _redteam_vlan_enum,
    _run_cmd,
    _sanitize_dns_zone,
    _sanitize_iface,
)


class TestToolCheck(unittest.TestCase):
    """Test tool availability detection."""

    @patch("shutil.which")
    def test_check_tools_all_available(self, mock_which):
        mock_which.return_value = "/usr/bin/tool"
        tools = _check_tools()
        self.assertTrue(tools["nmap"])
        self.assertTrue(tools["fping"])
        self.assertTrue(tools["nbtscan"])

    @patch("shutil.which")
    def test_check_tools_none_available(self, mock_which):
        mock_which.return_value = None
        tools = _check_tools()
        self.assertFalse(tools["nmap"])
        self.assertFalse(tools["fping"])


class TestDHCPDiscover(unittest.TestCase):
    """Test DHCP discovery parsing."""

    @patch("shutil.which")
    def test_dhcp_no_nmap(self, mock_which):
        mock_which.return_value = None
        result = dhcp_discover()
        self.assertEqual(result["error"], "nmap not available")
        self.assertEqual(result["servers"], [])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_dhcp_parse_single_server(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/nmap"
        mock_run.return_value = (
            0,
            """
Pre-scan script results:
| broadcast-dhcp-discover:
|   Response 1 of 1:
|     DHCPOFFER:
|       Server Identifier: 192.168.178.1
|       IP Address Offered: 192.168.178.50
|       Subnet Mask: 255.255.255.0
|       Router: 192.168.178.1
|       Domain Name Server: 8.8.8.8
""",
            "",
        )

        result = dhcp_discover()
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["servers"]), 1)
        self.assertEqual(result["servers"][0]["ip"], "192.168.178.1")
        self.assertEqual(result["servers"][0]["gateway"], "192.168.178.1")


class TestFpingSweep(unittest.TestCase):
    """Test fping sweep parsing."""

    @patch("shutil.which")
    def test_fping_not_available(self, mock_which):
        mock_which.return_value = None
        result = fping_sweep("192.168.1.0/24")
        self.assertEqual(result["error"], "fping not available")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_fping_parse_hosts(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/fping"
        mock_run.return_value = (
            0,
            """192.168.1.1
192.168.1.2
192.168.1.10
""",
            "",
        )

        result = fping_sweep("192.168.1.0/24")
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["alive_hosts"]), 3)
        self.assertIn("192.168.1.1", result["alive_hosts"])


class TestNetBIOSDiscover(unittest.TestCase):
    """Test NetBIOS discovery parsing."""

    @patch("shutil.which")
    def test_netbios_no_tools(self, mock_which):
        mock_which.return_value = None
        result = netbios_discover("192.168.1.0/24")
        self.assertEqual(result["error"], "Neither nbtscan nor nmap available")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_netbios_nbtscan_parse(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/nbtscan"
        mock_run.return_value = (
            0,
            """
IP               NetBIOS Name     Server    User              MAC
192.168.1.10     DESKTOP-ABC      <server>  ADMIN             aa:bb:cc:dd:ee:ff
192.168.1.20     LAPTOP-XYZ       <server>  USER              11:22:33:44:55:66
""",
            "",
        )

        result = netbios_discover("192.168.1.0/24")
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["hosts"]), 2)
        self.assertEqual(result["hosts"][0]["name"], "DESKTOP-ABC")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_netbios_nmap_parse_trims_trailing_comma(self, mock_which, mock_run):
        mock_which.side_effect = lambda tool: "/usr/bin/nmap" if tool == "nmap" else None
        mock_run.return_value = (
            0,
            """
Nmap scan report for 192.168.1.30
Host is up (0.0010s latency).
| nbstat:
|   NetBIOS name: SERVER01, NetBIOS user: <unknown>
""",
            "",
        )

        result = netbios_discover("192.168.1.0/24")
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["hosts"]), 1)
        self.assertEqual(result["hosts"][0]["name"], "SERVER01")


class TestNetdiscoverScan(unittest.TestCase):
    """Test netdiscover ARP scan parsing."""

    @patch("shutil.which")
    def test_netdiscover_not_available(self, mock_which):
        mock_which.return_value = None
        result = netdiscover_scan("192.168.1.0/24")
        self.assertEqual(result["error"], "netdiscover not available")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_netdiscover_parse(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/netdiscover"
        mock_run.return_value = (
            0,
            """
192.168.1.1     d4:24:dd:07:7c:c5      1      60  Unknown vendor
192.168.1.10    aa:bb:cc:dd:ee:ff      1      60  Intel Corporation
""",
            "",
        )

        result = netdiscover_scan("192.168.1.0/24")
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["hosts"]), 2)
        self.assertEqual(result["hosts"][0]["mac"], "d4:24:dd:07:7c:c5")


class TestVLANAnalysis(unittest.TestCase):
    """Test VLAN candidate detection."""

    def test_single_dhcp_no_vlan(self):
        result = {
            "dhcp_servers": [
                {"ip": "192.168.1.1", "subnet": "255.255.255.0", "gateway": "192.168.1.1"}
            ]
        }
        candidates = _analyze_vlans(result)
        self.assertEqual(len(candidates), 0)

    def test_multiple_dhcp_suggests_vlan(self):
        result = {
            "dhcp_servers": [
                {"ip": "192.168.1.1", "subnet": "255.255.255.0", "gateway": "192.168.1.1"},
                {"ip": "192.168.2.1", "subnet": "255.255.255.0", "gateway": "192.168.2.1"},
            ]
        }
        candidates = _analyze_vlans(result)
        self.assertEqual(len(candidates), 1)
        self.assertIn("guest", candidates[0]["description"].lower())


class TestDiscoverNetworks(unittest.TestCase):
    """Test main discover_networks function."""

    @patch("redaudit.core.net_discovery._check_tools")
    @patch("redaudit.core.net_discovery.dhcp_discover")
    @patch("redaudit.core.net_discovery.fping_sweep")
    def test_discover_networks_basic(self, mock_fping, mock_dhcp, mock_tools):
        mock_tools.return_value = {"nmap": True, "fping": True, "nbtscan": False}
        mock_dhcp.return_value = {"servers": [], "error": None}
        mock_fping.return_value = {"alive_hosts": ["192.168.1.1"], "error": None}

        result = discover_networks(
            target_networks=["192.168.1.0/24"],
            protocols=["dhcp", "fping"],
        )

        self.assertTrue(result["enabled"])
        self.assertIn("dhcp", result["protocols_used"])
        self.assertEqual(len(result["alive_hosts"]), 1)

    @patch("redaudit.core.net_discovery._check_tools")
    @patch("redaudit.core.net_discovery.dhcp_discover")
    @patch("redaudit.core.net_discovery.fping_sweep")
    def test_discover_networks_progress_callback(self, mock_fping, mock_dhcp, mock_tools):
        mock_tools.return_value = {"nmap": True, "fping": True, "nbtscan": False}
        mock_dhcp.return_value = {"servers": [], "error": None}
        mock_fping.return_value = {"alive_hosts": ["192.168.1.1"], "error": None}

        calls = []

        def cb(label: str, step_index: int, step_total: int):
            calls.append((label, step_index, step_total))

        discover_networks(
            target_networks=["192.168.1.0/24"],
            protocols=["dhcp", "fping"],
            progress_callback=cb,
        )

        self.assertTrue(calls, "progress_callback should be called at least once")
        self.assertTrue(any("DHCP" in c[0] for c in calls))
        self.assertTrue(any("ICMP" in c[0] for c in calls))
        self.assertTrue(all(c[2] == 2 for c in calls), "step_total should be 2 for 2 protocols")

    @patch("redaudit.core.hyperscan.hyperscan_full_discovery")
    @patch("redaudit.core.net_discovery._check_tools")
    def test_discover_networks_hyperscan_uses_shared_progress(self, mock_tools, mock_hyperscan):
        mock_tools.return_value = {"nmap": True, "fping": True, "nbtscan": False}
        mock_hyperscan.return_value = {
            "arp_hosts": [],
            "udp_devices": [],
            "tcp_hosts": {},
            "duration_seconds": 0.1,
        }

        calls = []

        def cb(label: str, step_index: int, step_total: int):
            calls.append((label, step_index, step_total))

        discover_networks(
            target_networks=["192.168.1.0/24"],
            protocols=["hyperscan"],
            progress_callback=cb,
        )

        mock_hyperscan.assert_called_once()
        kwargs = mock_hyperscan.call_args.kwargs
        self.assertIn("progress_callback", kwargs)
        self.assertTrue(callable(kwargs["progress_callback"]))

        # Simulate HyperScan progress updates and ensure they flow into the outer callback.
        hs_cb = kwargs["progress_callback"]
        hs_cb(50, 100, "TCP sweep")
        self.assertTrue(any("HyperScan:" in c[0] for c in calls))


class TestRedTeamDiscovery(unittest.TestCase):
    """Test Red Team net discovery helpers (best-effort)."""

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("redaudit.core.net_discovery.shutil.which")
    @patch("redaudit.core.net_discovery.fping_sweep")
    @patch("redaudit.core.net_discovery._check_tools")
    def test_redteam_snmp_and_smb(self, mock_tools, mock_fping, mock_which, mock_run):
        mock_tools.return_value = {
            "nmap": True,
            "fping": True,
            "nbtscan": False,
            "netdiscover": False,
            "avahi-browse": False,
            "snmpwalk": True,
            "enum4linux": False,
            "masscan": False,
        }
        mock_fping.return_value = {"alive_hosts": ["192.168.1.10"], "error": None}

        def which_side_effect(name: str):
            if name in ("snmpwalk", "nmap"):
                return f"/usr/bin/{name}"
            return None

        mock_which.side_effect = which_side_effect

        def run_side_effect(args, timeout_s, logger=None):
            if args and args[0] == "snmpwalk":
                return (
                    0,
                    ".1.3.6.1.2.1.1.1.0 = STRING: Linux test\n"
                    ".1.3.6.1.2.1.1.5.0 = STRING: host1\n",
                    "",
                )
            if args and args[0] == "nmap":
                return (
                    0,
                    "Host script results:\n"
                    "| smb-os-discovery:\n"
                    "|   OS: Windows 10\n"
                    "|   Computer name: DESKTOP-ABC\n"
                    "|   Domain name: WORKGROUP\n"
                    "| smb-enum-shares:\n"
                    "|   Sharename: PUBLIC\n",
                    "",
                )
            return (0, "", "")

        mock_run.side_effect = run_side_effect

        result = discover_networks(
            target_networks=["192.168.1.0/24"],
            protocols=["fping"],
            redteam=True,
        )

        self.assertTrue(result.get("redteam_enabled"))
        self.assertIn("redteam", result)
        self.assertEqual(result["redteam"]["targets_considered"], 1)

        snmp = result["redteam"]["snmp"]
        self.assertEqual(snmp["status"], "ok")
        self.assertEqual(snmp["hosts"][0]["sysDescr"], "Linux test")

        smb = result["redteam"]["smb"]
        self.assertEqual(smb["status"], "ok")
        self.assertEqual(smb["hosts"][0]["os"], "Windows 10")


if __name__ == "__main__":
    unittest.main()


def test_run_cmd_exception():
    """Test _run_cmd exception handling (lines 54-57)."""
    with patch("redaudit.core.net_discovery.CommandRunner.run", side_effect=Exception("Fatal")):
        rc, out, err = _run_cmd(["ls"], 1, logger=MagicMock())
        assert rc == -1
        assert "Fatal" in err


def test_dhcp_discover_nmap_fail():
    """Test dhcp_discover nmap failure (lines 118-120)."""
    with patch("shutil.which", return_value="/bin/nmap"):
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(1, "", "nmap error")):
            res = dhcp_discover()
            assert res["error"] == "dhcp-discover failed on default route: nmap error"


def test_dhcp_discover_parsing_edge():
    """Test dhcp_discover parsing edge cases (lines 135-138, 161, 167, 173)."""
    # DHCPOFFER without IP, then another DHCPOFFER with IP.
    out = "DHCPOFFER:\nDHCPOFFER:\nServer Identifier: 1.1.1.1\nDomain Name: target.local\nDomain Search: search.local"
    with patch("shutil.which", return_value="/bin/nmap"):
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, out, "")):
            res = dhcp_discover()
            assert len(res["servers"]) == 1
            assert res["servers"][0]["ip"] == "1.1.1.1"


def test_fping_sweep_stderr_alive():
    """Test fping_sweep alive detection from stderr (lines 216-221)."""
    with patch("shutil.which", return_value="/bin/fping"):
        with patch(
            "redaudit.core.net_discovery._run_cmd", return_value=(0, "", "1.1.1.1 is alive")
        ):
            res = fping_sweep("1.1.1.1")
            assert "1.1.1.1" in res["alive_hosts"]


def test_netbios_discover_nmap_fallback():
    """Test netbios_discover nbtscan missing, nmap fallback (line 269)."""
    with patch("shutil.which", side_effect=lambda x: "/bin/nmap" if x == "nmap" else None):
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            return_value=(0, "Nmap scan report for 1.1.1.1\nNetBIOS name: HOST", ""),
        ):
            res = netbios_discover("1.1.1.1")
            assert res["hosts"][0]["name"] == "HOST"


def test_netdiscover_passive_and_vendor():
    """Test netdiscover_scan passive mode and vendor parsing (lines 341, 358-359)."""
    with patch("shutil.which", return_value="/bin/netdiscover"):
        out = "1.2.3.4 aa:bb:cc:dd:ee:ff 1 60 Cisco Systems"
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, out, "")):
            res = netdiscover_scan("1.2.3.0/24", active=False)
            assert res["hosts"][0]["vendor"] == "Cisco Systems"


def test_arp_scan_active_parsing():
    """Test arp_scan_active parsing (lines 414-426)."""
    with patch("shutil.which", return_value="/bin/arp-scan"):
        out = "1.2.3.4\taa:bb:cc:dd:ee:ff\tVendor Name"
        with patch(
            "redaudit.core.net_discovery._run_cmd_suppress_stderr", return_value=(0, out, "")
        ):
            res = arp_scan_active()
            assert res["hosts"][0]["vendor"] == "Vendor Name"


def test_mdns_discover_iot_fallback():
    """Test mdns_discover iot specific queries fallback (lines 492-506)."""
    with patch("shutil.which", return_value="/bin/avahi-browse"):
        # First call empty, second one (iot) has more than top-5 (calls top-5)
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            side_effect=[
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "=;eth0;IPv4;Printer;_http._tcp;local;192.168.1.10", ""),
            ],
        ):
            res = mdns_discover()
            assert res["services"][0]["name"] == "Printer"


def test_upnp_discover_retry_and_ssdp():
    """Test upnp_discover retry and SSDP fallback (lines 583-596)."""
    with patch("shutil.which", return_value="/bin/nmap"):
        # 2 failures, then 1 SSDP success
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            side_effect=[(0, "", ""), (0, "", ""), (0, "Server: NAS\n1.2.3.4:", "")],
        ):
            with patch("time.sleep"):
                res = upnp_discover(retries=2)
                assert res["devices"][0]["device"] == "NAS"


def test_discover_networks_protocol_loops():
    """Test discover_networks with various protocols and errors (lines 641, 670, 714, 730, 740, 748, 834, 836)."""
    # Force errors for all
    with patch("redaudit.core.net_discovery.dhcp_discover", return_value={"error": "E1"}):
        with patch("redaudit.core.net_discovery.fping_sweep", return_value={"error": "E2"}):
            with patch(
                "redaudit.core.net_discovery.netbios_discover", return_value={"error": "E3"}
            ):
                with patch(
                    "redaudit.core.net_discovery.arp_scan_active", return_value={"error": "E4"}
                ):
                    with patch(
                        "redaudit.core.net_discovery.netdiscover_scan", return_value={"error": "E5"}
                    ):
                        with patch(
                            "redaudit.core.net_discovery.mdns_discover",
                            return_value={"error": "E6"},
                        ):
                            with patch(
                                "redaudit.core.net_discovery.upnp_discover",
                                return_value={"error": "E7"},
                            ):
                                with patch(
                                    "redaudit.core.net_discovery._check_tools",
                                    return_value={"arp-scan": True},
                                ):
                                    res = discover_networks(
                                        ["1.1.1.0/24"],
                                        protocols=[
                                            "dhcp",
                                            "fping",
                                            "netbios",
                                            "arp",
                                            "mdns",
                                            "upnp",
                                        ],
                                    )
                                    assert len(res["errors"]) >= 6


def test_discover_networks_hyperscan_errors():
    """Test discover_networks hyperscan error handling (lines 834-836)."""
    # 834: ImportError
    with patch("builtins.__import__", side_effect=ImportError("No HS")):
        res = discover_networks([], protocols=["hyperscan"])
        assert any("module not available" in e for e in res["errors"])
    # 836: Exception
    with patch("redaudit.core.hyperscan.hyperscan_full_discovery", side_effect=Exception("Crash")):
        res = discover_networks([], protocols=["hyperscan"])
        assert any("hyperscan: Crash" in e for e in res["errors"])


def test_analyze_vlans_logic():
    """Test _analyze_vlans multiple subnets (line 881)."""
    from redaudit.core.net_discovery import _analyze_vlans

    results = {
        "dhcp_servers": [
            {"ip": "1.1.1.1", "subnet": "255.255.255.0", "gateway": "1.1.1.1"},
            {"ip": "2.2.2.2", "subnet": "255.255.255.0", "gateway": "2.2.2.2"},
        ]
    }
    candidates = _analyze_vlans(results)
    assert len(candidates) == 1
    assert candidates[0]["gateway"] == "2.2.2.2"


def test_redteam_discovery_ticker_and_cleanup():
    """Test _run_redteam_discovery progress ticker (lines 933-937, 947-949)."""
    # Mock progress callback to be slow enough to let ticker run
    mock_cb = MagicMock()
    with patch("redaudit.core.net_discovery._check_tools", return_value={}):
        with patch("redaudit.core.net_discovery._gather_redteam_targets", return_value=[]):
            from redaudit.core.net_discovery import _run_redteam_discovery

            # Ticker runs every 3s. We'll simulate a 4s task to ensure ticker hits.
            def slow_task(*args, **kwargs):
                import time

                time.sleep(4)
                return {}

            with patch(
                "redaudit.core.net_discovery._redteam_rustscan_sweep", side_effect=slow_task
            ):
                _run_redteam_discovery(
                    {}, [], progress_callback=mock_cb, redteam_options={"max_targets": 10}
                )
    # Ticker should have called _progress_redteam
    # Just verify it finishes without error


def test_redteam_snmp_walk_errors():
    """Test _redteam_snmp_walk error paths (lines 1226, 1228, 1252, 1263)."""
    # 1226: No targets
    assert _redteam_snmp_walk([], {})["status"] == "no_targets"
    # 1228: Tool missing
    assert _redteam_snmp_walk(["1.1.1.1"], {})["status"] == "tool_missing"
    # 1252: Error log
    with patch("shutil.which", return_value="snmpwalk"):
        with patch(
            "redaudit.core.net_discovery._run_cmd", return_value=(1, "", "Permission Denied")
        ):
            res = _redteam_snmp_walk(["1.1.1.1"], {"snmpwalk": True})
            assert "Permission Denied" in res["errors"][0]
    # 1263: Row-based raw fallback
    with patch("shutil.which", return_value="snmpwalk"):
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, "UNKNOWN OUTPUT", "")):
            res = _redteam_snmp_walk(["1.1.1.1"], {"snmpwalk": True})
            assert res["hosts"][0]["raw"] == "UNKNOWN OUTPUT"


def test_redteam_smb_enum_nmap_fallback():
    """Test _redteam_smb_enum nmap fallback and raw snippet (lines 1325, 1356)."""
    # 1325: Tool missing
    assert _redteam_smb_enum(["1.1.1.1"], {})["status"] == "tool_missing"
    # 1356: Raw snippet
    with patch("shutil.which", side_effect=lambda x: "nmap" if x == "nmap" else None):
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            return_value=(0, "Nmap header\nweird output", ""),
        ):
            res = _redteam_smb_enum(["1.1.1.1"], {"nmap": True})
            assert res["hosts"][0]["tool"] == "nmap"
            assert "raw" in res["hosts"][0]


def test_redteam_rustscan_sweep_errors():
    """Test _redteam_rustscan_sweep tool check and error handling."""
    # Tool missing
    assert _redteam_rustscan_sweep(["1.1.1.1"], {"rustscan": False})["status"] == "tool_missing"

    # Execution error
    with patch("redaudit.core.net_discovery.run_rustscan_multi") as mock_run:
        mock_run.return_value = ({}, "Fatal Error")
        res = _redteam_rustscan_sweep(["1.1.1.0/24"], {"rustscan": True})
        assert res["status"] == "error"
        assert "Fatal Error" in res["error"]


def test_redteam_rpc_enum_parsing():
    """Test _redteam_rpc_enum parsing and fallback (lines 1531, 1539)."""
    with patch("shutil.which", side_effect=lambda x: "rpcclient" if x == "rpcclient" else None):
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            return_value=(0, "os version: Win10\ndomain: WORKGROUP", ""),
        ):
            res = _redteam_rpc_enum(["1.1.1.1"], {"rpcclient": True})
            assert res["hosts"][0]["os_version"] == "Win10"
        # 1531: Raw fallback
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, "just some text", "")):
            res = _redteam_rpc_enum(["1.1.1.1"], {"rpcclient": True})
            assert "raw" in res["hosts"][0]


def test_redteam_kerberos_enum_userlist_paths():
    """Test _redteam_kerberos_enum userlist edge cases (lines 1702, 1704, 1708, 1733)."""
    # 1702: Kerbrute missing
    with patch("shutil.which", return_value="nmap"):
        res = _redteam_kerberos_enum(
            ["1.1.1.1"], {"nmap": True, "kerbrute": False}, userlist_path="/tmp/users"
        )
        assert res["userenum"]["status"] == "tool_missing"
    # 1704: Path missing
    with patch("shutil.which", side_effect=lambda x: "nmap" if x == "nmap" else "kerbrute"):
        with patch("os.path.exists", return_value=False):
            res = _redteam_kerberos_enum(
                ["1.1.1.1"], {"nmap": True, "kerbrute": True}, userlist_path="/tmp/no"
            )
            assert res["userenum"]["status"] == "error"
    # 1708: No realm
    with patch("shutil.which", return_value="/bin/kerbrute"):
        with patch("os.path.exists", return_value=True):
            with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, "", "")):
                res = _redteam_kerberos_enum(
                    ["1.1.1.1"], {"nmap": True, "kerbrute": True}, userlist_path="/tmp/users"
                )
                assert res["userenum"]["status"] == "skipped_no_realm"


def test_redteam_dns_zone_transfer_edge():
    """Test _redteam_dns_zone_transfer no zone and failure (lines 1792, 1811)."""
    # 1792: No zone
    res = _redteam_dns_zone_transfer({"dhcp_servers": [{"dns": ["1.1.1.1"]}]}, {"dig": True})
    assert res["status"] == "skipped_no_zone"
    # 1811: Transfer failed msg
    with patch("shutil.which", return_value="dig"):
        with patch(
            "redaudit.core.net_discovery._run_cmd", return_value=(1, "transfer failed", "dig error")
        ):
            res = _redteam_dns_zone_transfer(
                {"dhcp_servers": [{"dns": ["1.1.1.1"]}]}, {"dig": True}, zone="target.local"
            )
            assert "transfer failed" in res["errors"][0]


def test_redteam_bettercap_recon_edge():
    """Test _redteam_bettercap_recon disabled and error (lines 2160, 2183)."""
    # 2160: active_l2 false
    assert (
        _redteam_bettercap_recon("eth0", {"bettercap": True}, active_l2=False)["status"]
        == "skipped_disabled"
    )
    # 2183: Error capture
    with patch("redaudit.core.net_discovery._is_root", return_value=True):
        with patch("shutil.which", return_value="bettercap"):
            with patch("redaudit.core.net_discovery._run_cmd", return_value=(1, "", "Fatal error")):
                res = _redteam_bettercap_recon("eth0", {"bettercap": True}, active_l2=True)
                assert res["error"] == "Fatal error"


def test_redteam_scapy_custom_exception():
    """Test _redteam_scapy_custom exception (line 2221)."""
    with patch("redaudit.core.net_discovery._is_root", return_value=True):
        # Mock scapy imports
        mock_scapy = MagicMock()
        mock_scapy.__version__ = "2.4.5"
        mock_dot1q = MagicMock()
        mock_sniff = MagicMock(side_effect=Exception("Scapy Error"))

        with patch.dict(
            "sys.modules",
            {
                "scapy": mock_scapy,
                "scapy.all": MagicMock(Dot1Q=mock_dot1q, sniff=mock_sniff),
            },
        ):
            # Need to patch the actual sniff call inside the function
            with patch("scapy.all.sniff", side_effect=Exception("Scapy Error")):
                res = _redteam_scapy_custom("eth0", {}, active_l2=True)
                # The function returns {"status": "error", "error": "..."} on exception
                assert res["status"] == "error"
                assert "Scapy Error" in res.get("error", "")


def test_sanitize_iface_none():
    """Test _sanitize_iface with None/invalid (line 1126, 1129)."""
    assert _sanitize_iface(None) is None
    assert _sanitize_iface("badinterface#") is None


def test_sanitize_dns_zone_none():
    """Test _sanitize_dns_zone with invalid inputs (lines 1134, 1138, 1140, 1142)."""
    assert _sanitize_dns_zone(None) is None
    assert _sanitize_dns_zone("a" * 300) is None
    assert _sanitize_dns_zone("a..b") is None
    assert _sanitize_dns_zone("-abc") is None


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

    assert result["error"] == "dhcp-discover failed on default route: boom"


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

    res = net_discovery.discover_networks(["1.1.1.0/24"], protocols=["arp"])
    # merged unique IPs = 2
    assert len(res["arp_hosts"]) == 2


class TestRoutingDiscovery(unittest.TestCase):
    """Test routing discovery (Hidden Networks)."""

    @patch("shutil.which")
    @patch("redaudit.core.net_discovery._run_cmd")
    def test_detect_routed_networks_linux(self, mock_run_cmd, mock_which):
        """Test parsing of ip route/neigh on Linux."""
        mock_which.return_value = "/usr/bin/ip"

        # Mock ip route output
        route_out = """default via 192.168.1.1 dev eth0 proto dhcp metric 100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50 metric 100
10.0.100.0/24 via 192.168.1.1 dev eth0
172.16.0.0/24 dev docker0 proto kernel scope link src 172.16.0.1 linkdown
192.168.105.0/24 dev eth0.105 proto kernel scope link src 192.168.105.2
"""

        # Mock ip neigh output
        neigh_out = """192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.100 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
192.168.105.1 dev eth0.105 lladdr 11:22:33:44:55:66 REACHABLE
"""

        def side_effect(cmd, timeout_s, logger):
            cmd_str = " ".join(cmd)
            if "ip route" in cmd_str:
                return 0, route_out, ""
            if "ip neigh" in cmd_str:
                return 0, neigh_out, ""
            return 1, "", "Command not found"

        mock_run_cmd.side_effect = side_effect

        result = detect_routed_networks(logger=None)

        # Assertions
        self.assertIn("networks", result)
        self.assertIn("gateways", result)

        networks = result["networks"]
        # Should detect the routed network
        self.assertIn("10.0.100.0/24", networks)
        # Should detect directly connected networks too
        self.assertIn("192.168.105.0/24", networks)
        self.assertIn("172.16.0.0/24", networks)
        self.assertIn("192.168.1.0/24", networks)

        # Gateways
        gateways = [g["ip"] for g in result["gateways"]]
        self.assertIn("192.168.1.1", gateways)
        # 192.168.105.1 is just a neighbor, not a explicit gateway in route table

    @patch("redaudit.core.net_discovery._run_cmd")
    def test_detect_routed_networks_failure(self, mock_run_cmd):
        """Test handling of command failure."""
        mock_run_cmd.return_value = (1, "", "ip: command not found")

        result = detect_routed_networks(logger=None)
        self.assertIn("error", result)
        self.assertEqual(result["networks"], [])


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
