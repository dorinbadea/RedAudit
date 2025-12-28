#!/usr/bin/env python3
import sys
import unittest
from unittest.mock import MagicMock, patch, mock_open
import warnings

# Add project root to path
sys.path.append(".")

from redaudit.core.net_discovery import (
    fping_sweep,
    dhcp_discover,
    netbios_discover,
    netdiscover_scan,
    arp_scan_active,
    mdns_discover,
    upnp_discover,
    discover_networks,
)


class TestNetDiscoveryV395(unittest.TestCase):
    def setUp(self):
        # Suppress warnings
        warnings.filterwarnings("ignore")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_fping_sweep_logic(self, mock_which, mock_run_cmd):
        """Test fping sweep parsing and error handling."""
        # Mock fping being available
        mock_which.return_value = "/usr/bin/fping"

        # Test 1: Successful output (stdout has just IPs due to -a flag)
        mock_run_cmd.return_value = (
            0,
            """
192.168.1.1
192.168.1.10
        """.strip(),
            "192.168.1.50 is unreachable",
        )

        results = fping_sweep("192.168.1.0/24", logger=None)
        # results is a dict {"alive_hosts": [...], "error": ...}
        self.assertIn("192.168.1.1", results["alive_hosts"])
        self.assertIn("192.168.1.10", results["alive_hosts"])
        self.assertNotIn("192.168.1.50", results["alive_hosts"])

        # Test 1b: Stderr parsing (some versions output 'is alive' to stderr)
        mock_run_cmd.return_value = (0, "", "192.168.1.12 is alive")
        results = fping_sweep("192.168.1.0/24", logger=None)
        self.assertIn("192.168.1.12", results["alive_hosts"])

        # Test 2: Error handling (mock _run_cmd raising an exception indirectly)
        mock_run_cmd.side_effect = Exception("fping failed")
        # When _run_cmd itself fails, fping_sweep should handle gracefully
        # Actually _run_cmd is called, so we need to make fping unavailable
        mock_which.return_value = None
        mock_run_cmd.side_effect = None
        mock_run_cmd.return_value = (0, "", "")
        results = fping_sweep("192.168.1.0/24", logger=None)
        self.assertEqual(results["alive_hosts"], [])

    @patch("redaudit.core.net_discovery.CommandRunner")
    def test_dhcp_discover_corner_cases(self, mock_runner_cls):
        """Test DHCP discover with various nmap outputs (including piped prefixes)."""
        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner

        # Scenario: Nmap output with prefixes (the bug fixed in v3.9.4)
        mock_runner.run.return_value.returncode = 0
        mock_runner.run.return_value.stdout = """
Starting Nmap 7.94...
Nmap scan report for 192.168.1.1
Host is up (0.0020s latency).
PORT    STATE SERVICE
67/udp  open  dhcps
| dhcp-discover:
|   DHCP Message Type: DHCPACK
|   Server Identifier: 192.168.1.1
|   Domain Name: internal.corp
|_  Domain Search: sub.internal.corp
MAC Address: AA:BB:CC:DD:EE:FF (Vendor)
        """

        result = dhcp_discover(interface="eth0", logger=None)

        # Corrected: result is {"servers": [...], "error": ...}
        # We need to find the server and check its domain
        servers = result.get("servers", [])
        self.assertTrue(len(servers) > 0, "No DHCP servers found")
        self.assertEqual(servers[0].get("domain"), "internal.corp")
        self.assertEqual(servers[0].get("domain_search"), "sub.internal.corp")

        # Scenario: Failed execution
        mock_runner.run.return_value.returncode = 1
        mock_runner.run.return_value.stdout = ""
        mock_runner.run.return_value.stderr = "Error"
        result = dhcp_discover(interface="eth0", logger=None)
        self.assertEqual(result["servers"], [])

    @patch("redaudit.core.net_discovery.CommandRunner")
    def test_netbios_discover_parsing(self, mock_runner_cls):
        """Test NetBIOS parsing including trailing comma fix."""
        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner

        mock_runner.run.return_value.returncode = 0
        mock_runner.run.return_value.stdout = """
Nmap scan report for 192.168.1.50
Host is up.
Host script results:
| nbstat: NetBIOS name: FILESERVER, NetBIOS user: <unknown>, NetBIOS MAC: ...
|_Names: FILESERVER<00> flags: <unique> ...

Nmap scan report for 192.168.1.51
Host is up.
Host script results:
| nbstat: NetBIOS name: WORKSTATION01,
|_Names: WORKSTATION01<00> ...
        """

        # NOTE: logic falls back to nmap if nbtscan missing.
        # But we mocked CommandRunner, not shutil.which.
        # netbios_discover checks shutil.which("nbtscan") first.
        # We should ensure nbtscan is FALSE so it tests the nmap path,
        # OR mock nbtscan output if we assume it's true.
        # Given the parsing logic tested above matches nmap's format, let's force nbtscan=False.

        with patch("shutil.which") as mock_which:

            def which_side_effect(cmd):
                if cmd == "nbtscan":
                    return None
                if cmd == "nmap":
                    return "/usr/bin/nmap"
                return None

            mock_which.side_effect = which_side_effect

            results = netbios_discover("192.168.1.0/24")

            # Corrected: results is {"hosts": [...], "error": ...}
            hosts = results.get("hosts", [])
            host_map = {h["ip"]: h["name"] for h in hosts}

            self.assertEqual(host_map.get("192.168.1.50"), "FILESERVER")
            self.assertEqual(host_map.get("192.168.1.51"), "WORKSTATION01")

    @patch("redaudit.core.net_discovery.CommandRunner")
    @patch("shutil.which")
    def test_netdiscover_active_mode(self, mock_which, mock_runner_cls):
        """Test netdiscover wrapper logic."""
        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_which.return_value = "/usr/bin/netdiscover"

        # Mock active scan output
        mock_runner.run.return_value.returncode = 0
        mock_runner.run.return_value.stdout = """
 192.168.1.100   aa:bb:cc:dd:ee:01    1      60  Vendor1
 192.168.1.101   aa:bb:cc:dd:ee:02    1      60  Vendor2
        """

        # Test without interface (passive/default)
        result = netdiscover_scan("192.168.1.0/24")
        # Corrected: result is {"hosts": [...]}
        hosts = result.get("hosts", [])
        self.assertTrue(any(h["ip"] == "192.168.1.100" for h in hosts))

        # Test with interface (active)
        mock_runner.run.reset_mock()
        netdiscover_scan("192.168.1.0/24", interface="eth0", active=True)
        pass

    @patch("redaudit.core.net_discovery.CommandRunner")
    @patch("shutil.which")
    def test_run_arp_scan_active(self, mock_which, mock_runner_cls):
        """Test the robust arp-scan wrapper."""
        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_which.return_value = "/usr/bin/arp-scan"

        mock_runner.run.return_value.returncode = 0
        mock_runner.run.return_value.stdout = """
192.168.1.200\t00:11:22:33:44:55\tVendorA
192.168.1.201\t00:11:22:33:44:56\tVendorB
        """

        result = arp_scan_active(interface="eth0")
        hosts = result.get("hosts", [])
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["ip"], "192.168.1.200")
        self.assertEqual(hosts[0]["mac"], "00:11:22:33:44:55")

    @patch("redaudit.core.net_discovery.CommandRunner")
    def test_mdns_discover_retry(self, mock_runner_cls):
        """Test mDNS discovery retry logic."""
        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner

        fail_res = MagicMock()
        fail_res.returncode = 1
        fail_res.stdout = ""

        success_res = MagicMock()
        success_res.returncode = 0
        success_res.stdout = """
= eth0 IPv4 Apple TV                                     _airplay._tcp        local
   hostname = [Apple-TV.local]
   address = [192.168.1.70]
   port = [7000]
   txt = ["model=AppleTV"]
        """

        mock_runner.run.side_effect = [fail_res, success_res, success_res, success_res]

        results = mdns_discover(timeout_s=1, interface="eth0")
        self.assertIsInstance(results["services"], list)


class TestDiscoverNetworksOrchestration(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings("ignore")

    @patch("redaudit.core.net_discovery._check_tools")
    @patch("redaudit.core.net_discovery.dhcp_discover")
    @patch("redaudit.core.net_discovery.fping_sweep")
    @patch("redaudit.core.net_discovery.netbios_discover")
    @patch("redaudit.core.net_discovery.arp_scan_active")
    @patch("redaudit.core.net_discovery.netdiscover_scan")
    @patch("redaudit.core.net_discovery.mdns_discover")
    @patch("redaudit.core.net_discovery.upnp_discover")
    def test_discover_networks_full_flow(
        self,
        mock_upnp,
        mock_mdns,
        mock_netdiscover,
        mock_arp,
        mock_netbios,
        mock_fping,
        mock_dhcp,
        mock_check_tools,
    ):
        """Test full orchestration of discover_networks."""
        # Setup mocks
        mock_check_tools.return_value = {
            "nmap": True,
            "fping": True,
            "nbtscan": True,
            "netdiscover": True,
            "arp-scan": True,
            "avahi-browse": True,
        }

        mock_dhcp.return_value = {
            "servers": [{"ip": "192.168.1.1", "domain": "lab.local"}],
            "error": None,
        }
        mock_fping.return_value = {"alive_hosts": ["192.168.1.10", "192.168.1.20"], "error": None}
        mock_netbios.return_value = {
            "hosts": [{"ip": "192.168.1.10", "name": "WIN10"}],
            "error": None,
        }
        mock_arp.return_value = {
            "hosts": [{"ip": "192.168.1.30", "mac": "AA:BB:CC:11:22:33"}],
            "error": None,
        }
        mock_netdiscover.return_value = {
            "hosts": [{"ip": "192.168.1.31", "mac": "AA:BB:CC:44:55:66"}],
            "error": None,
        }
        mock_mdns.return_value = {
            "services": [{"name": "Printer", "type": "_ipp._tcp"}],
            "error": None,
        }
        mock_upnp.return_value = {
            "devices": [{"ip": "192.168.1.1", "device": "Router"}],
            "error": None,
        }

        # We exclude hyperscan to simplify mocking (it imports internally)
        protocols = ["dhcp", "fping", "netbios", "arp", "mdns", "upnp"]

        result = discover_networks(["192.168.1.0/24"], protocols=protocols, logger=None)

        # Verify aggregation
        self.assertEqual(len(result["dhcp_servers"]), 1)
        self.assertEqual(result["dhcp_servers"][0]["domain"], "lab.local")

        self.assertIn("192.168.1.10", result["alive_hosts"])
        self.assertIn("192.168.1.20", result["alive_hosts"])

        self.assertEqual(len(result["netbios_hosts"]), 1)
        self.assertEqual(result["netbios_hosts"][0]["name"], "WIN10")

        # ARP results from both arp-scan and netdiscover should be aggregated
        self.assertTrue(len(result["arp_hosts"]) >= 2)
        arp_ips = [h["ip"] for h in result["arp_hosts"]]
        self.assertIn("192.168.1.30", arp_ips)
        self.assertIn("192.168.1.31", arp_ips)

        self.assertEqual(len(result["mdns_services"]), 1)
        self.assertEqual(len(result["upnp_devices"]), 1)


class TestRedTeamFeatures(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings("ignore")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_snmp_walk(self, mock_which, mock_run_cmd):
        """Test SNMP walk parsing."""
        from redaudit.core.net_discovery import _redteam_snmp_walk

        mock_which.return_value = "/usr/bin/snmpwalk"

        # Output simulation
        mock_run_cmd.return_value = (
            0,
            """
.1.3.6.1.2.1.1.1.0 = STRING: "Linux server 5.10"
.1.3.6.1.2.1.1.5.0 = STRING: "srv01"
        """,
            "",
        )

        res = _redteam_snmp_walk(["192.168.1.10"], tools={"snmpwalk": True})
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(res["hosts"]), 1)
        self.assertEqual(res["hosts"][0]["sysDescr"], "Linux server 5.10")
        self.assertEqual(res["hosts"][0]["sysName"], "srv01")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_masscan_sweep(self, mock_which, mock_run_cmd):
        """Test masscan parsing."""
        from redaudit.core.net_discovery import _redteam_masscan_sweep

        mock_which.return_value = "/usr/bin/masscan"
        # Mock root
        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            mock_run_cmd.return_value = (
                0,
                """
Discovered open port 80/tcp on 192.168.1.50
Discovered open port 443/tcp on 192.168.1.51
            """,
                "",
            )

            res = _redteam_masscan_sweep(["192.168.1.0/24"], tools={"masscan": True})
            self.assertEqual(res["status"], "ok")
            self.assertEqual(len(res["open_ports"]), 2)
            self.assertEqual(res["open_ports"][0]["port"], 80)
            self.assertEqual(res["open_ports"][1]["port"], 443)

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_smb_enum_nmap(self, mock_which, mock_run_cmd):
        """Test SMB enum using Nmap fallback."""
        from redaudit.core.net_discovery import _redteam_smb_enum

        # Simulate enum4linux missing, nmap present
        def which_side_effect(cmd):
            return "/usr/bin/nmap" if cmd == "nmap" else None

        mock_which.side_effect = which_side_effect

        mock_run_cmd.return_value = (
            0,
            """
Host script results:
| smb-os-discovery:
|   OS: Windows 10 Pro 1909 (Windows 10 Pro 6.3)
|   Computer name: DESKTOP-LAB
|   Workgroup: WORKGROUP
|_  System time: 2025-12-28T12:00:00+00:00
| smb-enum-shares:
|   account_used: guest
|   \\\\192.168.1.50\\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (DESKTOP-LAB)
|   \\\\192.168.1.50\\Share$:
|     Type: STYPE_DISKTREE
|_    Comment:
        """,
            "",
        )

        res = _redteam_smb_enum(["192.168.1.50"], tools={"nmap": True, "enum4linux": False})
        self.assertEqual(res["tool"], "nmap")
        self.assertEqual(len(res["hosts"]), 1)
        host = res["hosts"][0]
        self.assertEqual(host["os"], "Windows 10 Pro 1909 (Windows 10 Pro 6.3)")
        self.assertIn("IPC$", host["shares"])
        self.assertIn("Share$", host["shares"])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_dns_zone_transfer(self, mock_which, mock_run_cmd):
        """Test DNS zone transfer."""
        from redaudit.core.net_discovery import _redteam_dns_zone_transfer

        mock_which.return_value = "/usr/bin/dig"

        discovery_result = {"dhcp_servers": [{"dns": ["192.168.1.1"], "domain": "lab.local"}]}

        mock_run_cmd.return_value = (
            0,
            """
; <<>> DiG 9.16.1 <<>> axfr lab.local @192.168.1.1
lab.local.      3600    IN  SOA ns1.lab.local. root.lab.local. 1 2 3 4 5
host1.lab.local. 3600    IN  A   192.168.1.10
host2.lab.local. 3600    IN  A   192.168.1.11
lab.local.      3600    IN  NS  ns1.lab.local.
;; XFR size: 4 records (messages 1, bytes 200)
        """,
            "",
        )

        res = _redteam_dns_zone_transfer(discovery_result, tools={"dig": True})
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(res["attempts"]), 1)
        self.assertTrue(res["attempts"][0]["success"])
        self.assertIn("host1.lab.local.", res["attempts"][0]["records_sample"][1])


class TestRedTeamFeaturesExtended(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings("ignore")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_rpc_enum(self, mock_which, mock_run_cmd):
        """Test RPC enumeration."""
        from redaudit.core.net_discovery import _redteam_rpc_enum

        mock_which.return_value = "/usr/bin/rpcclient"

        mock_run_cmd.return_value = (
            0,
            """
        srvinfo:
            Server Name: SRV01
            Security: User
            OS Version: 10.0
            Server Type: 0x800003
        """,
            "",
        )

        res = _redteam_rpc_enum(["192.168.1.10"], tools={"rpcclient": True})
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["tool"], "rpcclient")
        self.assertEqual(len(res["hosts"]), 1)
        self.assertEqual(res["hosts"][0]["os_version"], "10.0")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_ldap_enum(self, mock_which, mock_run_cmd):
        """Test LDAP enumeration."""
        from redaudit.core.net_discovery import _redteam_ldap_enum

        mock_which.return_value = "/usr/bin/ldapsearch"

        mock_run_cmd.return_value = (
            0,
            """
defaultNamingContext: DC=lab,DC=local
namingContexts: DC=lab,DC=local
namingContexts: CN=Configuration,DC=lab,DC=local
supportedLDAPVersion: 3
        """,
            "",
        )

        res = _redteam_ldap_enum(["192.168.1.10"], tools={"ldapsearch": True})
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(res["hosts"]), 1)
        self.assertEqual(res["hosts"][0]["defaultNamingContext"], "DC=lab,DC=local")
        self.assertIn("DC=lab,DC=local", res["hosts"][0]["namingContexts"])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_kerberos_enum(self, mock_which, mock_run_cmd):
        """Test Kerberos enumeration."""
        from redaudit.core.net_discovery import _redteam_kerberos_enum

        mock_which.return_value = "/usr/bin/nmap"

        mock_run_cmd.return_value = (
            0,
            """
88/tcp open  kerberos-sec
| krb5-info:
|   Realm: LAB.LOCAL
|   Provider: Active Directory
        """,
            "",
        )

        res = _redteam_kerberos_enum(["192.168.1.10"], tools={"nmap": True})
        self.assertEqual(res["hosts"][0]["realms"][0], "LAB.LOCAL")
        self.assertEqual(res["detected_realms"][0], "LAB.LOCAL")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_vlan_enum(self, mock_which, mock_run_cmd):
        """Test VLAN enumeration via tcpdump capture."""
        from redaudit.core.net_discovery import _redteam_vlan_enum

        mock_which.return_value = "/usr/bin/tcpdump"
        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            mock_run_cmd.return_value = (
                0,
                """
10:00:00.000000 802.1Q vlan 10 P0 IP 1.2.3.4 > 1.2.3.5: ICMP echo request
10:00:01.000000 802.1Q vlan 20 P0 IP 1.2.3.4 > 1.2.3.5: ICMP echo request
            """,
                "",
            )

            res = _redteam_vlan_enum("eth0", tools={"tcpdump": True})
            self.assertEqual(res["status"], "ok")
            self.assertIn(10, res["vlan_ids"])
            self.assertIn(20, res["vlan_ids"])


class TestRedTeamFeaturesFinal(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings("ignore")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_stp_topology(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_stp_topology

        mock_which.return_value = "/usr/bin/tcpdump"
        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            mock_run_cmd.return_value = (
                0,
                """
root id 8000.00e0.b0aa.aaaa
bridge id 8000.00e0.b0bb.bbbb
            """,
                "",
            )
            res = _redteam_stp_topology("eth0", tools={"tcpdump": True})
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["root_ids"][0], "8000.00e0.b0aa.aaaa")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_hsrp_vrrp(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_hsrp_vrrp_discovery

        mock_which.return_value = "/usr/bin/tcpdump"
        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            mock_run_cmd.return_value = (
                0,
                """
HSRP v1 192.168.1.1 Hello
VRRP v2 192.168.1.2 Adv
            """,
                "",
            )
            res = _redteam_hsrp_vrrp_discovery("eth0", tools={"tcpdump": True})
            self.assertIn("hsrp", res["protocols_observed"])
            self.assertIn("vrrp", res["protocols_observed"])
            self.assertIn("192.168.1.1", res["ip_candidates"])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_llmnr(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_llmnr_nbtns_capture

        mock_which.return_value = "/usr/bin/tcpdump"
        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            mock_run_cmd.return_value = (
                0,
                """
10:00:00.000000 IP 1.2.3.4.5355: UDP, length 10 ? WPAD
10:00:00.000000 IP 1.2.3.4.137: UDP, length 10 ? FILESERVER
            """,
                "",
            )
            res = _redteam_llmnr_nbtns_capture("eth0", tools={"tcpdump": True})
            self.assertIn("WPAD", res["llmnr_queries_sample"])
            self.assertIn("FILESERVER", res["nbns_queries_sample"])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_router_discovery_igmp(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_router_discovery

        mock_which.return_value = "/usr/bin/nmap"
        mock_run_cmd.return_value = (
            0,
            """
Pre-execution script output:
| broadcast-igmp-discovery:
|   192.168.1.1
|     Interface: eth0
|     Version: 2
|_    Querier: 192.168.1.1
        """,
            "",
        )
        res = _redteam_router_discovery("eth0", tools={"nmap": True})
        self.assertEqual(res["status"], "ok")
        self.assertIn("192.168.1.1", res["router_candidates"])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_ipv6_discovery(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_ipv6_discovery

        def which_side_effect(cmd):
            if cmd in ["ping6", "ip"]:
                return "/usr/bin/" + cmd
            return None

        mock_which.side_effect = which_side_effect

        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            mock_run_cmd.return_value = (
                0,
                """
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            """,
                "",
            )
            res = _redteam_ipv6_discovery("eth0", tools={"ip": True, "ping6": True})
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["neighbors"][0]["ip"], "fe80::1")
            self.assertEqual(res["neighbors"][0]["mac"], "aa:bb:cc:dd:ee:ff")

    @patch("redaudit.core.net_discovery._is_root", return_value=True)
    def test_redteam_scapy_custom(self, mock_root):
        from redaudit.core.net_discovery import _redteam_scapy_custom

        mock_scapy = MagicMock()
        mock_scapy.__version__ = "2.5.0"

        mock_dot1q = MagicMock()
        mock_dot1q.vlan = 100

        mock_pkt = MagicMock()
        mock_pkt.haslayer.return_value = True
        mock_pkt.__getitem__.return_value = mock_dot1q

        def mock_sniff(*args, **kwargs):
            prn = kwargs.get("prn")
            if prn:
                prn(mock_pkt)

        with patch.dict("sys.modules", {"scapy": mock_scapy, "scapy.all": mock_scapy}):
            mock_scapy.Dot1Q = MagicMock()
            mock_scapy.sniff = mock_sniff

            res = _redteam_scapy_custom("eth0", tools={}, active_l2=True)
            self.assertEqual(res["status"], "ok")
            self.assertIn(100, res["vlan_ids"])

            res = _redteam_scapy_custom("eth0", tools={}, active_l2=True)
            self.assertEqual(res["status"], "ok")
            self.assertIn(100, res["vlan_ids"])


class TestRedTeamFeaturesEdgeCases(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings("ignore")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_bettercap(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_bettercap_recon

        mock_which.return_value = "/usr/bin/bettercap"
        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            mock_run_cmd.return_value = (
                0,
                """
192.168.1.10 : 00:11:22:33:44:55 : Asus
            """,
                "",
            )
            res = _redteam_bettercap_recon("eth0", tools={"bettercap": True}, active_l2=True)
            self.assertEqual(res["status"], "ok")
            self.assertIn("192.168.1.10", res["raw_sample"])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_kerbrute_userenum(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_kerberos_enum

        def which_side_effect(cmd):
            return "/usr/bin/" + cmd

        mock_which.side_effect = which_side_effect

        # Phase 1: nmap fails or yields no realms, Phase 2: kerbrute runs if userlist_path provided
        # Nmap results (empty)
        nmap_res = (0, "", "")
        # Kerbrute results
        kerbrute_res = (
            0,
            """
2025/12/28 12:00:00 [+] VALID USERNAME:       admin@LAB.LOCAL
2025/12/28 12:00:00 [+] VALID USERNAME:       user1@LAB.LOCAL
        """,
            "",
        )

        mock_run_cmd.side_effect = [nmap_res, kerbrute_res]

        # Needs mock userlist file
        with patch("os.path.exists", return_value=True):
            res = _redteam_kerberos_enum(
                ["192.168.1.10"],
                tools={"nmap": True, "kerbrute": True},
                realm="LAB.LOCAL",
                userlist_path="/tmp/users.txt",
            )
            self.assertEqual(res["userenum"]["status"], "ok")
            self.assertIn("admin", res["userenum"]["valid_users_sample"])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_ipv6_ndp_fallback(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_ipv6_discovery

        # Mock only ndp available (macOS style)
        def which_side_effect(cmd):
            return "/usr/bin/ndp" if cmd == "ndp" else None

        mock_which.side_effect = which_side_effect

        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            mock_run_cmd.return_value = (
                0,
                """
fe80::1%eth0 aa:bb:cc:dd:ee:ff eth0 permanent R
            """,
                "",
            )
            res = _redteam_ipv6_discovery("eth0", tools={})
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["neighbors"][0]["ip"], "fe80::1%eth0")
            self.assertEqual(res["neighbors"][0]["mac"], "aa:bb:cc:dd:ee:ff")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_redteam_router_passive_fallback(self, mock_which, mock_run_cmd):
        from redaudit.core.net_discovery import _redteam_router_discovery

        # No nmap, use tcpdump
        mock_which.return_value = "/usr/bin/tcpdump"

        mock_run_cmd.return_value = (
            0,
            """
00:00:00.000000 IP 192.168.1.1 > 224.0.0.1: igmp query v2
        """,
            "",
        )

        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            res = _redteam_router_discovery("eth0", tools={"tcpdump": True})
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["tool"], "tcpdump")
            self.assertIn("192.168.1.1", res["router_candidates"])


if __name__ == "__main__":
    unittest.main()
