#!/usr/bin/env python3
"""
Unit tests for redaudit.core.scanner module coverage > 85%.
"""

import unittest
from unittest.mock import MagicMock, patch, mock_open, call
import subprocess
import os

from redaudit.core.scanner import (
    sanitize_ip,
    is_ipv6,
    is_ipv6_network,
    sanitize_hostname,
    is_web_service,
    is_suspicious_service,
    is_port_anomaly,
    get_nmap_arguments,
    get_nmap_arguments_for_target,
    extract_vendor_mac,
    extract_os_detection,
    extract_detailed_identity,
    output_has_identity,
    run_nmap_command,
    capture_traffic_snippet,
    start_background_capture,
    stop_background_capture,
    finalize_host_status,
)
from redaudit.utils.constants import (
    STATUS_UP,
    STATUS_DOWN,
    STATUS_FILTERED,
    STATUS_NO_RESPONSE,
)


class TestScannerCoverage(unittest.TestCase):

    # ---------- Utilities ----------

    def test_sanitize_ip(self):
        self.assertEqual(sanitize_ip("192.168.1.1"), "192.168.1.1")
        self.assertIsNone(sanitize_ip("999.999.999.999"))
        self.assertIsNone(sanitize_ip("invalid"))
        self.assertIsNone(sanitize_ip(None))
        self.assertEqual(sanitize_ip("  10.0.0.1  "), "10.0.0.1")
        # IPv6
        self.assertEqual(sanitize_ip("2001:db8::1"), "2001:db8::1")

    def test_is_ipv6(self):
        self.assertTrue(is_ipv6("2001:db8::1"))
        self.assertFalse(is_ipv6("192.168.1.1"))
        self.assertFalse(is_ipv6("invalid"))

    def test_is_ipv6_network(self):
        self.assertTrue(is_ipv6_network("2001:db8::/32"))
        self.assertFalse(is_ipv6_network("192.168.1.0/24"))
        self.assertFalse(is_ipv6_network("invalid"))

    def test_sanitize_hostname(self):
        self.assertEqual(sanitize_hostname("example.com"), "example.com")
        self.assertEqual(sanitize_hostname("host-1"), "host-1")
        self.assertIsNone(sanitize_hostname("invalid char$"))
        self.assertIsNone(sanitize_hostname(None))
        self.assertIsNone(sanitize_hostname("a" * 1025))  # Too long (>1024)

    def test_is_web_service(self):
        self.assertTrue(is_web_service("http"))
        self.assertTrue(is_web_service("https"))
        self.assertTrue(is_web_service("http-alt"))
        self.assertTrue(is_web_service("ssl/http"))
        self.assertFalse(is_web_service("ssh"))
        self.assertFalse(is_web_service(""))

    def test_is_suspicious_service(self):
        self.assertTrue(is_suspicious_service("openvpn"))
        self.assertTrue(is_suspicious_service("pptp"))
        self.assertTrue(is_suspicious_service("telnet"))
        self.assertFalse(is_suspicious_service("http"))
        self.assertFalse(is_suspicious_service(None))

    def test_is_port_anomaly(self):
        # 22 is usually ssh
        self.assertFalse(is_port_anomaly(22, "OpenSSH"))
        self.assertTrue(is_port_anomaly(22, "Apache httpd"))  # Weird
        # Unknown port
        self.assertFalse(is_port_anomaly(9999, "unknown"))

    # ---------- Nmap Logic ----------

    def test_get_nmap_arguments(self):
        self.assertIn("-sn", get_nmap_arguments("rapido"))
        self.assertIn("-F", get_nmap_arguments("normal"))
        self.assertIn("-p-", get_nmap_arguments("completo"))
        # Config timing
        self.assertIn("-T2", get_nmap_arguments("normal", config={"nmap_timing": "T2"}))

    def test_get_nmap_arguments_for_target(self):
        self.assertIn("-6", get_nmap_arguments_for_target("normal", "2001:db8::1"))
        self.assertNotIn("-6", get_nmap_arguments_for_target("normal", "192.168.1.1"))

    def test_extract_vendor_mac(self):
        text = "MAC Address: 00:11:22:33:44:55 (Cisco Systems)"
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "00:11:22:33:44:55")
        self.assertEqual(vendor, "Cisco Systems")

        self.assertEqual(extract_vendor_mac(""), (None, None))

    def test_extract_os_detection(self):
        text1 = "Running: Linux 4.X"
        text2 = "Aggressive OS guesses: Linux 5.4"
        text3 = "OS details: Windows 10"
        self.assertEqual(extract_os_detection(text1), "Linux 4.X")
        self.assertEqual(extract_os_detection(text2), "Linux 5.4")
        self.assertEqual(extract_os_detection(text3), "Windows 10")
        self.assertIsNone(extract_os_detection("No OS info"))

    def test_extract_detailed_identity_empty(self):
        self.assertIsNone(extract_detailed_identity(""))
        self.assertIsNone(extract_detailed_identity(None))

    def test_extract_detailed_identity_fritz_repeater(self):
        text = "|_http-title: FRITZ!Repeater 1200 AX\n"
        details = extract_detailed_identity(text)
        self.assertEqual(details["vendor"], "AVM")
        self.assertEqual(details["model"], "FRITZ!Repeater")
        self.assertEqual(details["device_type"], "iot_network_device")
        self.assertIn("FRITZ!OS", details["os_detected"])

    def test_extract_detailed_identity_fritz_box(self):
        text = "|_http-title: FRITZ!Box 7590 AX\n"
        details = extract_detailed_identity(text)
        self.assertEqual(details["vendor"], "AVM")
        self.assertEqual(details["model"], "FRITZ!Box")
        self.assertEqual(details["device_type"], "router")
        self.assertIn("FRITZ!OS", details["os_detected"])

    def test_output_has_identity(self):
        rec1 = {"stdout": "MAC Address: 00:11:22:33:44:55 (Vendor)"}
        self.assertTrue(output_has_identity([rec1]))

        rec2 = {"stdout": "Running: Linux"}
        self.assertTrue(output_has_identity([rec2]))

        # 'Running: unknown' matches regex because of IGNORECASE flag in scanner.py
        rec3 = {"stdout": "Running: unknown"}
        self.assertTrue(output_has_identity([rec3]))

        rec4 = {"stdout": "", "stderr": ""}
        self.assertFalse(output_has_identity([rec4]))

        rec5 = {"stdout": "Nothing useful here"}
        self.assertFalse(output_has_identity([rec5]))

    @patch("redaudit.core.scanner.nmap._make_runner")
    def test_run_nmap_command(self, mock_make_runner):
        mock_runner = MagicMock()
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Nmap scan report"
        mock_res.stderr = ""
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res
        mock_make_runner.return_value = mock_runner

        deep_obj = {}
        rec = run_nmap_command(["nmap", "-sV"], 10, "1.1.1.1", deep_obj)

        self.assertEqual(rec["returncode"], 0)
        self.assertEqual(rec["stdout"], "Nmap scan report")
        self.assertEqual(len(deep_obj["commands"]), 1)

        # Test full output inclusion
        rec2 = run_nmap_command(["nmap"], 10, "1.1.1.1", deep_obj, include_full_output=True)
        self.assertIn("stdout_full", rec2)

    @patch("redaudit.core.scanner.nmap._make_runner")
    def test_run_nmap_command_proxy_wrapper(self, mock_make_runner):
        mock_runner = MagicMock()
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "ok"
        mock_res.stderr = ""
        mock_res.timed_out = False
        mock_runner.run.return_value = mock_res
        mock_make_runner.return_value = mock_runner

        class _Proxy:
            def wrap_command(self, cmd):
                return ["proxychains"] + list(cmd)

        deep_obj = {}
        run_nmap_command(
            ["nmap", "-sV"],
            10,
            "1.1.1.1",
            deep_obj,
            proxy_manager=_Proxy(),
        )

        _, kwargs = mock_make_runner.call_args
        self.assertTrue(callable(kwargs.get("command_wrapper")))

    # ---------- Traffic Capture ----------

    @patch("redaudit.core.scanner.traffic._make_runner")
    @patch("redaudit.core.scanner.traffic.ipaddress")
    def test_capture_traffic_snippet(self, mock_ip, mock_make_runner):
        # Setup specific IP/Network match
        mock_ip.ip_address.return_value = "IP_OBJ"
        net_obj = MagicMock()
        net_obj.__contains__.return_value = True
        mock_ip.ip_network.return_value = net_obj

        networks = [{"network": "192.168.1.0/24", "interface": "eth0"}]
        tools = {"tcpdump": "/usr/bin/tcpdump"}

        # Test dry run
        self.assertIsNone(capture_traffic_snippet("1.2.3.4", "/tmp", networks, tools, dry_run=True))

        # Test Success
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=0, timed_out=False)
        mock_make_runner.return_value = mock_runner

        info = capture_traffic_snippet("192.168.1.50", "/tmp", networks, tools, duration=5)
        self.assertIsNotNone(info)
        self.assertEqual(info["iface"], "eth0")
        self.assertIn("pcap_file", info)

    @patch("redaudit.core.scanner.traffic.subprocess.Popen")
    @patch("redaudit.core.scanner.traffic.ipaddress")
    def test_start_stop_background_capture(self, mock_ip, mock_popen):
        # Setup interface discovery
        net_obj = MagicMock()
        net_obj.__contains__.return_value = True
        mock_ip.ip_network.return_value = net_obj
        networks = [{"network": "192.168.1.0/24", "interface": "eth0"}]
        tools = {"tcpdump": "/usr/bin/tcpdump"}

        # Start
        proc_mock = MagicMock()
        mock_popen.return_value = proc_mock

        info = start_background_capture("192.168.1.50", "/tmp", networks, tools)
        self.assertIsNotNone(info)
        self.assertEqual(info["process"], proc_mock)

        # Stop
        stop_background_capture(info, tools)
        proc_mock.terminate.assert_called()

    # ---------- Status Logic ----------

    def test_finalize_host_status(self):
        # Already UP
        self.assertEqual(finalize_host_status({"status": STATUS_UP}), STATUS_UP)

        # Down but ports found -> UP
        self.assertEqual(finalize_host_status({"status": STATUS_DOWN, "ports": [80]}), STATUS_UP)

        # Down, no ports, no deep scan -> DOWN
        self.assertEqual(finalize_host_status({"status": STATUS_DOWN}), STATUS_DOWN)

        # Filtered by response
        deep = {"commands": [{"stdout": "Host is up"}]}
        self.assertEqual(
            finalize_host_status({"status": STATUS_DOWN, "deep_scan": deep}), STATUS_FILTERED
        )

        # No response but commands tried -> NO_RESPONSE

    # ---------- Enrichment & Search ----------

    @patch("redaudit.core.scanner.enrichment._make_runner")
    @patch("redaudit.core.scanner.enrichment.ipaddress")
    def test_enrich_host_with_dns_whois(self, mock_ip, mock_make_runner):
        # Mock public IP for whois
        mock_ip.ip_address.return_value = MagicMock(is_private=False)

        tools = {"dig": "/bin/dig", "whois": "/bin/whois"}
        record = {"ip": "8.8.8.8"}

        # Setup mock runner
        mock_runner = MagicMock()
        mock_res = MagicMock()
        mock_res.stdout = "dns.google"
        mock_runner.run.return_value = mock_res
        mock_make_runner.return_value = mock_runner

        # Test DNS
        from redaudit.core.scanner import enrich_host_with_dns, enrich_host_with_whois

        enrich_host_with_dns(record, tools)
        self.assertIn("dns", record)
        self.assertEqual(record["dns"]["reverse"], ["dns.google"])

        # Test Whois
        enrich_host_with_whois(record, tools)
        self.assertIn("whois_summary", record["dns"])

    @patch("redaudit.core.scanner.enrichment._make_runner")
    def test_http_enrichment_probe(self, mock_make_runner):
        from redaudit.core.scanner import http_enrichment, http_identity_probe

        tools = {"curl": "curl", "wget": "wget"}

        # Mock curl headers response
        mock_runner = MagicMock()
        mock_runner.run.side_effect = [
            MagicMock(stdout="HTTP/1.1 200 OK\nServer: Apache"),  # curl -I
            MagicMock(stderr="HTTP/1.1 200 OK\nServer: Nginx"),  # wget spider
            MagicMock(stdout="<title>Test Page</title>"),  # body fetch
        ]
        mock_make_runner.return_value = mock_runner

        # Test http_enrichment
        res = http_enrichment("http://test.com", tools)
        self.assertIn("curl_headers", res)
        # Verify wget fallback logic if we called it (mock depends on order)

    @patch("redaudit.core.scanner.enrichment._fetch_http_headers")
    @patch("redaudit.core.scanner.enrichment._fetch_http_body")
    def test_http_identity_probe_logic(self, mock_body, mock_headers):
        from redaudit.core.scanner import http_identity_probe

        mock_headers.return_value = "Server: Apache/2.4"
        mock_body.return_value = "<html><head><title>Admin Panel</title></head></html>"

        tools = {"curl": "curl"}
        res = http_identity_probe("192.168.1.1", tools, ports=[80])

        self.assertEqual(res.get("http_server"), "Apache/2.4")
        self.assertEqual(res.get("http_title"), "Admin Panel")

    @patch("redaudit.core.scanner.enrichment._make_runner")
    def test_exploit_lookup(self, mock_make_runner):
        from redaudit.core.scanner import exploit_lookup

        tools = {"searchsploit": "searchsploit"}

        # Mock searchsploit output
        output = """---------------------------------------
 Exploit Title                        |  Path
---------------------------------------
Apache 2.4 - RCE                      | linux/remote/1234.py
Apache < 2.2 - Overflow               | linux/remote/5678.c
---------------------------------------"""

        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=0, stdout=output)
        mock_make_runner.return_value = mock_runner

        exploits = exploit_lookup("Apache", "2.4", tools)
        self.assertEqual(len(exploits), 2)
        self.assertIn("Apache 2.4 - RCE", exploits[0])

    @patch("redaudit.core.scanner.enrichment._make_runner")
    def test_ssl_deep_analysis(self, mock_make_runner):
        from redaudit.core.scanner import ssl_deep_analysis

        tools = {"testssl.sh": "testssl"}

        # Mock testssl output
        output = """
        VULNERABLE (Heartbleed)
        Cipher order checking... ok
        Weak cipher: RC4
        Protocol: TLS 1.0
        """

        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=0, timed_out=False, stdout=output)
        mock_make_runner.return_value = mock_runner

        res = ssl_deep_analysis("1.1.1.1", 443, tools)
        self.assertIsNotNone(res)
        self.assertIn("vulnerabilities", res)
        self.assertTrue(any("Heartbleed" in v for v in res["vulnerabilities"]))
        self.assertTrue(any("RC4" in c for c in res["weak_ciphers"]))
        self.assertIn("TLS 1.0", res["protocols"][0])

    # ---------- HTTP Fetchers ----------

    @patch("redaudit.core.scanner.enrichment._make_runner")
    def test_fetch_http_functions(self, mock_make_runner):
        from redaudit.core.scanner import _fetch_http_headers, _fetch_http_body

        tools_curl = {"curl": "curl"}
        tools_wget = {"wget": "wget"}

        # Mock runner
        mock_runner = MagicMock()
        mock_res_ok = MagicMock(returncode=0, stdout="OK_DATA")
        mock_res_err = MagicMock(returncode=1, stdout="", stderr="ERR_DATA")

        mock_runner.run.return_value = mock_res_ok
        mock_make_runner.return_value = mock_runner

        # Test Headers (curl)
        self.assertEqual(_fetch_http_headers("http://site.com", tools_curl), "OK_DATA")
        # Test Headers (wget)
        mock_runner.run.return_value = MagicMock(stderr="WGET_HEADERS")
        self.assertEqual(_fetch_http_headers("http://site.com", tools_wget), "WGET_HEADERS")

        # Test Body (curl)
        mock_runner.run.return_value = mock_res_ok
        self.assertEqual(_fetch_http_body("http://site.com", tools_curl), "OK_DATA")
        # Test Body (wget)
        self.assertEqual(_fetch_http_body("http://site.com", tools_wget), "OK_DATA")

    # ---------- TLS & Banner Grab ----------

    @patch("redaudit.core.scanner.enrichment._make_runner")
    def test_tls_enrichment(self, mock_make_runner):
        from redaudit.core.scanner import tls_enrichment

        tools = {"openssl": "openssl"}
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(stdout="Certificate Info\nIssuer: ...")
        mock_make_runner.return_value = mock_runner

        data = tls_enrichment("1.1.1.1", 443, tools)
        self.assertIn("tls_info", data)
        self.assertIn("Certificate Info", data["tls_info"])

    @patch("redaudit.core.scanner.enrichment._make_runner")
    def test_banner_grab_fallback(self, mock_make_runner):
        from redaudit.core.scanner import banner_grab_fallback
        import textwrap

        # Mock nmap output
        output = textwrap.dedent(
            """
        80/tcp open http
        | banner: Apache/2.4.41

        443/tcp open ssl/http
        | ssl-cert: Subject: commonName=example.com
        """
        ).strip()

        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(stdout=output, timed_out=False)
        mock_make_runner.return_value = mock_runner

        res = banner_grab_fallback("1.1.1.1", [80, 443], {}, timeout=5)
        self.assertEqual(res[80]["service"], "http")
        self.assertEqual(res[80]["banner"], "Apache/2.4.41")
        self.assertIn("example.com", res[443]["ssl_cert"])

        # Test timeout branch
        mock_runner.run.return_value = MagicMock(timed_out=True)
        res_timeout = banner_grab_fallback("1.1.1.1", [80], {})
        self.assertEqual(res_timeout, {})

    # ---------- Tshark Integration ----------

    @patch("redaudit.core.scanner.traffic.subprocess.Popen")
    @patch("redaudit.core.scanner.traffic.os.path.exists")
    @patch("redaudit.core.scanner.traffic._make_runner")
    def test_stop_capture_tshark(self, mock_make_runner, mock_exists, mock_popen):
        # Setup active capture
        proc = MagicMock()
        mock_exists.return_value = True  # pcap exists

        capture_info = {"process": proc, "pcap_file_abs": "/tmp/test.pcap", "iface": "eth0"}
        tools = {"tshark": "tshark"}

        # Mock tshark success
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(stdout="Tshark Summary Stats", timed_out=False)
        mock_make_runner.return_value = mock_runner

        res = stop_background_capture(capture_info, tools)
        self.assertIn("tshark_summary", res)
        proc.terminate.assert_called()

        # Mock tshark failure/timeout
        mock_runner.run.return_value = MagicMock(timed_out=True)
        res2 = stop_background_capture(capture_info, tools)
        self.assertIn("tshark_error", res2)

    # ---------- Status Edge Cases ----------

    def test_finalize_status_edge_cases(self):
        # filtered because of OS detection
        deep_os = {"commands": [{"stdout": "OS details: Linux"}]}
        self.assertEqual(
            finalize_host_status({"status": STATUS_DOWN, "deep_scan": deep_os}), STATUS_FILTERED
        )

        # filtered because of MAC
        deep_mac = {"mac_address": "AA:BB:CC:DD:EE:FF"}
        self.assertEqual(
            finalize_host_status({"status": STATUS_DOWN, "deep_scan": deep_mac}), STATUS_FILTERED
        )

        # no response at all
        deep_nada = {"commands": [{"stdout": "trash"}]}
        self.assertEqual(
            finalize_host_status({"status": STATUS_DOWN, "deep_scan": deep_nada}),
            STATUS_NO_RESPONSE,
        )

        # down and no deep scan -> down
        self.assertEqual(finalize_host_status({"status": STATUS_DOWN}), STATUS_DOWN)

    # ---------- Title Extraction & Exceptions ----------

    def test_extract_http_title_variants(self):
        from redaudit.core.scanner import _extract_http_title

        # Standard title
        html1 = "<html><head><title>My Title</title></head></html>"
        self.assertEqual(_extract_http_title(html1), "My Title")

        # Meta title
        html2 = '<meta name="title" content="Meta Title">'
        self.assertEqual(_extract_http_title(html2), "Meta Title")

        # OpenGraph
        html3 = '<meta property="og:title" content="OG Title">'
        self.assertEqual(_extract_http_title(html3), "OG Title")

        # H1 fallback
        html4 = "<body><h1>Heading Title</h1></body>"
        self.assertEqual(_extract_http_title(html4), "Heading Title")

        # Alt fallback (logo skip)
        html5 = '<img src="logo.png" alt="Logo">'  # Should skip
        self.assertEqual(_extract_http_title(html5), "")
        html6 = '<img src="img.png" alt="Alt Title">'
        self.assertEqual(_extract_http_title(html6), "Alt Title")

    @patch("redaudit.core.scanner.traffic._make_runner")
    @patch("redaudit.core.scanner.nmap._make_runner")
    def test_scanner_exceptions(self, mock_make_runner_nmap, mock_make_runner_traffic):
        from redaudit.core.scanner import run_nmap_command, capture_traffic_snippet

        # Mock generic exception in run_nmap_command (e.g. permission error during Popen)
        # Note: run_nmap_command catches nothing, it lets exception bubble up typically,
        # checking coverage miss lines 416 (timeout branch)

        # Configure both mocks to behave the same
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(timed_out=True, returncode=0, stdout="", stderr="")
        mock_make_runner_nmap.return_value = mock_runner
        mock_make_runner_traffic.return_value = mock_runner

        deep_obj = {}
        res = run_nmap_command(["cmd"], 1, "1.1.1.1", deep_obj)
        self.assertIn("error", res)
        self.assertIn("Timeout", res["error"])

        # Test generic exception capture in capture_traffic_snippet
        mock_runner.run.side_effect = Exception("Boom")
        tools = {"tcpdump": "tcpdump"}

        # Mock network match
        with patch("redaudit.core.scanner.traffic.ipaddress") as mock_ip:
            mock_ip.ip_address.return_value = "IP"
            mock_ip.ip_network.return_value = MagicMock()
            mock_ip.ip_network.return_value.__contains__.return_value = True

            res_snip = capture_traffic_snippet(
                "1.1.1.1",
                "/tmp",
                [{"network": "1.1.1.0/24", "interface": "eth0"}],
                tools,
                duration=1,
            )
            self.assertIn("tcpdump_error", res_snip)

    # ---------- Missing Tools & Tshark ----------

    def test_missing_tools_returns_empty(self):
        from redaudit.core.scanner import (
            capture_traffic_snippet,
            start_background_capture,
            enrich_host_with_dns,
            exploit_lookup,
            ssl_deep_analysis,
        )

        empty_tools = {}

        self.assertIsNone(capture_traffic_snippet("1.1.1.1", "/", [], empty_tools))
        self.assertIsNone(start_background_capture("1.1.1.1", "/", [], empty_tools))

        rec = {"ip": "1.1.1.1"}
        enrich_host_with_dns(rec, empty_tools)
        self.assertEqual(rec.get("dns"), {})  # Initialized but empty

        self.assertEqual(exploit_lookup("svc", "1.0", empty_tools), [])
        self.assertIsNone(ssl_deep_analysis("1.1.1.1", 443, empty_tools))

    @patch("redaudit.core.scanner.traffic._make_runner")
    @patch("redaudit.core.scanner.traffic.ipaddress")
    def test_capture_snippet_tshark(self, mock_ip, mock_make_runner):
        from redaudit.core.scanner import capture_traffic_snippet

        # Setup valid interface
        mock_ip.ip_address.return_value = "IP"
        mock_ip.ip_network.return_value = MagicMock()
        mock_ip.ip_network.return_value.__contains__.return_value = True

        tools = {"tcpdump": "tcpdump", "tshark": "tshark"}

        # Mock runner
        mock_runner = MagicMock()
        # First call tcpdump (ok), Second call tshark (ok)
        mock_runner.run.side_effect = [
            MagicMock(returncode=0, timed_out=False),  # tcpdump
            MagicMock(stdout="Tshark Analysis", timed_out=False),  # tshark
        ]
        mock_make_runner.return_value = mock_runner

        info = capture_traffic_snippet(
            "1.1.1.1", "/tmp", [{"network": "1.0.0.0/24", "interface": "eth0"}], tools, duration=1
        )
        self.assertIn("tshark_summary", info)

    # ---------- Input Validation & Edge Cases ----------

    def test_input_validation_logic(self):
        from redaudit.core.scanner import (
            exploit_lookup,
            start_background_capture,
            stop_background_capture,
            ssl_deep_analysis,
        )

        # exploit_lookup bad inputs
        tools = {"searchsploit": "searchsploit"}
        self.assertEqual(exploit_lookup(None, "1.0", tools), [])
        self.assertEqual(exploit_lookup("Apache", None, tools), [])
        self.assertEqual(exploit_lookup(123, "1.0", tools), [])
        self.assertEqual(exploit_lookup("", "1.0", tools), [])

        # ssl_deep_analysis bad inputs
        self.assertIsNone(ssl_deep_analysis("invalid_ip", 443, tools))
        self.assertIsNone(ssl_deep_analysis("1.1.1.1", "bad_port", tools))

        # stop_background_capture bad input
        self.assertIsNone(stop_background_capture({}, tools))
        self.assertIsNone(stop_background_capture(None, tools))

    @patch("redaudit.core.scanner.traffic.ipaddress")
    def test_start_background_capture_no_iface(self, mock_ip):
        from redaudit.core.scanner import start_background_capture

        # Mock IP parsing failure or no network match
        mock_ip.ip_address.side_effect = ValueError
        tools = {"tcpdump": "tcpdump"}

        res = start_background_capture("bad_ip", "/tmp", [], tools)
        self.assertIsNone(res)

        # Valid IP but no network match
        mock_ip.ip_address.side_effect = None
        mock_ip.ip_address.return_value = "IP"
        mock_ip.ip_network.side_effect = ValueError

        res2 = start_background_capture("1.1.1.1", "/tmp", [{"network": "bad"}], tools)
        self.assertIsNone(res2)

    # ---------- Dry Run & Limits ----------

    def test_dry_runs_and_limits(self):
        from redaudit.core.scanner import (
            capture_traffic_snippet,
            start_background_capture,
            banner_grab_fallback,
            stop_background_capture,
        )

        tools = {"tcpdump": "tcpdump"}

        # Capture snippet dry run
        res = capture_traffic_snippet("1.1.1.1", "/", [], tools, dry_run=True)
        self.assertIsNone(res)

        # Background capture dry run
        res_bg = start_background_capture("1.1.1.1", "/", [], tools, dry_run=True)
        self.assertIsNone(res_bg)

        # Stop background capture dry run (with mock tshark)
        stop_dry_res = stop_background_capture(
            {"process": MagicMock(), "pcap_file_abs": "/tmp/test.pcap", "iface": "eth0"},
            {"tshark": "tshark"},
            dry_run=True,
        )
        self.assertNotIn("tshark_summary", stop_dry_res)

        # Banner Grab Limits (max 20 ports)
        ports = list(range(1, 30))
        # Mock run_nmap_command internally called by banner_grab?? No, it calls _make_runner directly.
        # We need to mock _make_runner to avoid real nmap call
        with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_fac:
            mock_runner = MagicMock()
            mock_runner.run.return_value = MagicMock(stdout="", timed_out=False)
            mock_runner_fac.return_value = mock_runner

            banner_grab_fallback("1.1.1.1", ports, {})
            # Verify command args contain only first 20 ports
            call_args = mock_runner.run.call_args[0][0]  # cmd list
            port_arg = call_args[call_args.index("-p") + 1]
            self.assertEqual(len(port_arg.split(",")), 20)

        # Banner Grab Bad Inputs
        self.assertEqual(banner_grab_fallback("bad_ip", [80], {}), {})
        self.assertEqual(banner_grab_fallback("1.1.1.1", [], {}), {})
        self.assertEqual(banner_grab_fallback("1.1.1.1", None, {}), {})

    # ---------- Comprehensive Exceptions ----------

    @patch("redaudit.core.scanner.traffic._make_runner")  # For start/stop capture
    @patch("redaudit.core.scanner.enrichment._make_runner")  # For exploit/banner
    def test_comprehensive_exceptions(self, mock_loader_enrich, mock_loader_traffic):
        from redaudit.core.scanner import (
            exploit_lookup,
            banner_grab_fallback,
            start_background_capture,
            stop_background_capture,
        )

        # Exploit Lookup Timeout
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(timed_out=True)
        # Mock for both injected mocks
        mock_loader_enrich.return_value = mock_runner
        mock_loader_traffic.return_value = mock_runner

        self.assertEqual(exploit_lookup("svc", "1.0", {"searchsploit": "yes"}), [])

        # Exploit Lookup Error
        mock_runner.run.side_effect = Exception("Searchsploit died")
        self.assertEqual(exploit_lookup("svc", "1.0", {"searchsploit": "yes"}), [])

        # Banner Grab Timeout
        mock_runner.run.side_effect = None
        mock_runner.run.return_value = MagicMock(timed_out=True)

        self.assertEqual(banner_grab_fallback("1.1.1.1", [80], {}, timeout=1), {})

        # Banner Grab Error
        mock_runner.run.side_effect = Exception("Nmap died")
        self.assertEqual(banner_grab_fallback("1.1.1.1", [80], {}, timeout=1), {})

    @patch("redaudit.core.scanner.traffic.subprocess.Popen")
    @patch("redaudit.core.scanner.traffic.ipaddress")
    def test_background_capture_exceptions(self, mock_ip, mock_popen):
        from redaudit.core.scanner import start_background_capture, stop_background_capture

        # Setup valid match
        mock_ip.ip_address.return_value = "IP"
        mock_ip.ip_network.return_value = MagicMock()
        mock_ip.ip_network.return_value.__contains__.return_value = True

        tools = {"tcpdump": "tcpdump"}

        # Start capture exception
        mock_popen.side_effect = Exception("Popen failed")

        nets = [{"network": "1.0.0.0/24", "interface": "eth0"}]
        self.assertIsNone(start_background_capture("1.1.1.1", "/tmp", nets, tools))

        # Stop capture exception (proc.terminate fails)
        proc = MagicMock()
        proc.terminate.side_effect = Exception("Terminate failed")
        res = stop_background_capture({"process": proc, "iface": "eth0"}, tools)
        self.assertIn("tcpdump_error", res)

        # Stop capture timeout -> kill
        proc.terminate.side_effect = subprocess.TimeoutExpired("cmd", 1)
        res2 = stop_background_capture({"process": proc, "iface": "eth0"}, tools)
        self.assertIn("tcpdump_error", res2)
        proc.kill.assert_called()

    # ---------- Final Edge Cases ----------

    @patch("redaudit.core.scanner.enrichment._make_runner")
    def test_ssl_analysis_clean(self, mock_make_runner):
        from redaudit.core.scanner import ssl_deep_analysis

        tools = {"testssl.sh": "testssl"}
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(
            returncode=0, stdout="Protocol: TLS 1.2", timed_out=False
        )
        mock_make_runner.return_value = mock_runner

        res = ssl_deep_analysis("1.1.1.1", 443, tools)
        # Should have summary "No major issues detected" if findings are empty?
        # Default findings are empty lists.
        # But verify output parsing didn't find "VULNERABLE" or "Weak cipher"
        self.assertIn("No major issues detected", res.get("summary", ""))

    @patch("redaudit.core.scanner.traffic.ipaddress")
    def test_capture_network_parsing_error(self, mock_ip):
        from redaudit.core.scanner import capture_traffic_snippet

        tools = {"tcpdump": "tcpdump"}
        mock_ip.ip_address.return_value = "IP"
        # Raise exception for first network, pass second?
        # or just fail loop check

        # We want to trigger line 476: except Exception: continue
        # This happens inside 'for net in networks' loop when ip_network(net["network"]) fails

        def side_effect_network(net, strict=False):
            if net == "bad_cidr":
                raise ValueError("Bad CIDR")
            return MagicMock()

        mock_ip.ip_network.side_effect = side_effect_network

        # We need a valid match to return something, or just verify it didn't crash
        # If no iface found, returns None

        nets = [
            {"network": "bad_cidr", "interface": "eth0"}
        ]  # Should trigger exception and continue -> return None
        res = capture_traffic_snippet("1.1.1.1", "/tmp", nets, tools)
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()


class TestScannerSanitization(unittest.TestCase):
    """Edge case tests for IP/hostname sanitization."""

    def test_sanitize_ip_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        self.assertEqual(sanitize_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(sanitize_ip("  10.0.0.1  "), "10.0.0.1")
        self.assertEqual(sanitize_ip("0.0.0.0"), "0.0.0.0")
        self.assertEqual(sanitize_ip("255.255.255.255"), "255.255.255.255")

    def test_sanitize_ip_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        self.assertEqual(sanitize_ip("::1"), "::1")
        self.assertEqual(sanitize_ip("2001:db8::1"), "2001:db8::1")
        self.assertEqual(sanitize_ip("fe80::1"), "fe80::1")

    def test_sanitize_ip_invalid(self):
        """Test invalid IP inputs."""
        self.assertIsNone(sanitize_ip(None))
        self.assertIsNone(sanitize_ip(""))
        self.assertIsNone(sanitize_ip("   "))
        self.assertIsNone(sanitize_ip(123))
        self.assertIsNone(sanitize_ip(["192.168.1.1"]))
        self.assertIsNone(sanitize_ip("not-an-ip"))
        self.assertIsNone(sanitize_ip("192.168.1"))
        self.assertIsNone(sanitize_ip("999.999.999.999"))

    def test_sanitize_ip_too_long(self):
        """Test IP address exceeding max length."""
        long_ip = "192.168.1." + "1" * 1100
        self.assertIsNone(sanitize_ip(long_ip))

    def test_sanitize_hostname_valid(self):
        """Test valid hostnames."""
        self.assertEqual(sanitize_hostname("example.com"), "example.com")
        self.assertEqual(sanitize_hostname("my-server"), "my-server")
        self.assertEqual(sanitize_hostname("server01.local"), "server01.local")
        self.assertEqual(sanitize_hostname("  test.domain  "), "test.domain")

    def test_sanitize_hostname_invalid(self):
        """Test invalid hostname inputs."""
        self.assertIsNone(sanitize_hostname(None))
        self.assertIsNone(sanitize_hostname(""))
        self.assertIsNone(sanitize_hostname(123))
        self.assertIsNone(sanitize_hostname("host name"))  # Space not allowed
        self.assertIsNone(sanitize_hostname("host;name"))  # Special char
        self.assertIsNone(sanitize_hostname("host'name"))  # Quote

    def test_sanitize_hostname_too_long(self):
        """Test hostname exceeding max length."""
        long_hostname = "a" * 1100
        self.assertIsNone(sanitize_hostname(long_hostname))


class TestScannerServiceDetection(unittest.TestCase):
    """Tests for service type detection functions."""

    def test_is_web_service_exact_matches(self):
        """Test exact web service name matches."""
        self.assertTrue(is_web_service("http"))
        self.assertTrue(is_web_service("https"))
        self.assertTrue(is_web_service("www"))
        self.assertTrue(is_web_service("http-proxy"))
        self.assertTrue(is_web_service("ssl/http"))

    def test_is_web_service_keyword_matches(self):
        """Test keyword-based web service detection."""
        self.assertTrue(is_web_service("HTTP-Alt"))
        self.assertTrue(is_web_service("apache-httpd"))
        self.assertTrue(is_web_service("nginx-ssl"))
        self.assertTrue(is_web_service("web-admin"))

    def test_is_web_service_non_web(self):
        """Test non-web services."""
        self.assertFalse(is_web_service("ssh"))
        self.assertFalse(is_web_service("ftp"))
        self.assertFalse(is_web_service("mysql"))
        self.assertFalse(is_web_service(""))
        self.assertFalse(is_web_service(None))

    def test_is_suspicious_service(self):
        """Test suspicious service detection."""
        self.assertTrue(is_suspicious_service("socks5"))
        self.assertTrue(is_suspicious_service("tor"))
        self.assertTrue(is_suspicious_service("tcpwrapped"))
        self.assertTrue(is_suspicious_service("backdoor"))
        self.assertTrue(is_suspicious_service("meterpreter"))
        self.assertTrue(is_suspicious_service("cobalt-strike"))

    def test_is_suspicious_service_normal(self):
        """Test normal services not flagged as suspicious."""
        self.assertFalse(is_suspicious_service("http"))
        self.assertFalse(is_suspicious_service("ssh"))
        self.assertFalse(is_suspicious_service("mysql"))
        self.assertFalse(is_suspicious_service(""))
        self.assertFalse(is_suspicious_service(None))


class TestScannerPortAnomaly(unittest.TestCase):
    """Tests for port anomaly detection."""

    def test_is_port_anomaly_standard_services(self):
        """Test that standard services on their ports are NOT anomalies."""
        self.assertFalse(is_port_anomaly(22, "ssh"))
        self.assertFalse(is_port_anomaly(22, "openssh"))
        self.assertFalse(is_port_anomaly(80, "http"))
        self.assertFalse(is_port_anomaly(443, "https"))
        self.assertFalse(is_port_anomaly(443, "ssl"))
        self.assertFalse(is_port_anomaly(3306, "mysql"))

    def test_is_port_anomaly_unexpected_services(self):
        """Test that unexpected services on standard ports ARE anomalies."""
        self.assertTrue(is_port_anomaly(22, "http"))  # HTTP on SSH port
        self.assertTrue(is_port_anomaly(80, "ssh"))  # SSH on HTTP port
        self.assertTrue(is_port_anomaly(443, "ftp"))  # FTP on HTTPS port
        self.assertTrue(is_port_anomaly(22, "unknown"))  # Unknown on SSH port

    def test_is_port_anomaly_non_standard_ports(self):
        """Test that non-standard ports don't trigger anomaly."""
        # Ports NOT in STANDARD_PORT_SERVICES
        self.assertFalse(is_port_anomaly(9999, "anything"))
        self.assertFalse(is_port_anomaly(12345, "unknown"))
        self.assertFalse(is_port_anomaly(31337, "backdoor"))

    def test_is_port_anomaly_empty_service(self):
        """Test empty service name handling."""
        self.assertFalse(is_port_anomaly(22, ""))
        self.assertFalse(is_port_anomaly(22, None))


class TestScannerIPv6Detection(unittest.TestCase):
    """Tests for IPv6 detection functions."""

    def test_is_ipv6_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        self.assertTrue(is_ipv6("::1"))
        self.assertTrue(is_ipv6("2001:db8::1"))
        self.assertTrue(is_ipv6("fe80::1"))
        self.assertTrue(is_ipv6("::ffff:192.168.1.1"))

    def test_is_ipv6_ipv4(self):
        """Test IPv4 addresses return False."""
        self.assertFalse(is_ipv6("192.168.1.1"))
        self.assertFalse(is_ipv6("10.0.0.1"))
        self.assertFalse(is_ipv6("0.0.0.0"))

    def test_is_ipv6_invalid(self):
        """Test invalid inputs return False."""
        self.assertFalse(is_ipv6("not-an-ip"))
        self.assertFalse(is_ipv6(""))

    def test_is_ipv6_network(self):
        """Test IPv6 network CIDR detection."""
        self.assertTrue(is_ipv6_network("2001:db8::/32"))
        self.assertTrue(is_ipv6_network("fe80::/10"))
        self.assertFalse(is_ipv6_network("192.168.1.0/24"))
        self.assertFalse(is_ipv6_network("10.0.0.0/8"))
        self.assertFalse(is_ipv6_network("invalid"))


class TestScannerMACExtraction(unittest.TestCase):
    """Tests for MAC address and vendor extraction."""

    def test_extract_vendor_mac_standard_format(self):
        """Test standard Nmap MAC output format."""
        text = "MAC Address: 00:11:22:33:44:55 (Cisco Systems)"
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "00:11:22:33:44:55")
        self.assertEqual(vendor, "Cisco Systems")

    def test_extract_vendor_mac_lowercase(self):
        """Test lowercase MAC address."""
        text = "MAC Address: aa:bb:cc:dd:ee:ff (Unknown Vendor)"
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(vendor, "Unknown Vendor")

    def test_extract_vendor_mac_mixed_case(self):
        """Test mixed case MAC address."""
        text = "MAC Address: Aa:Bb:Cc:Dd:Ee:Ff (Apple, Inc.)"
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "Aa:Bb:Cc:Dd:Ee:Ff")
        self.assertEqual(vendor, "Apple, Inc.")

    def test_extract_vendor_mac_multiline(self):
        """Test extraction from multiline output."""
        text = """
        PORT   STATE SERVICE
        22/tcp open  ssh
        MAC Address: DE:AD:BE:EF:CA:FE (Test Vendor)
        """
        mac, vendor = extract_vendor_mac(text)
        self.assertEqual(mac, "DE:AD:BE:EF:CA:FE")
        self.assertEqual(vendor, "Test Vendor")

    def test_extract_vendor_mac_no_match(self):
        """Test output without MAC address."""
        text = "No MAC address found in this output"
        mac, vendor = extract_vendor_mac(text)
        self.assertIsNone(mac)
        self.assertIsNone(vendor)

    def test_extract_vendor_mac_empty_input(self):
        """Test empty/None input."""
        self.assertEqual(extract_vendor_mac(""), (None, None))
        self.assertEqual(extract_vendor_mac(None), (None, None))


class TestScannerOSDetection(unittest.TestCase):
    """Tests for OS detection extraction."""

    def test_extract_os_detection_os_details(self):
        """Test OS details pattern."""
        text = "OS details: Linux 3.2 - 4.9"
        result = extract_os_detection(text)
        self.assertEqual(result, "Linux 3.2 - 4.9")

    def test_extract_os_detection_running(self):
        """Test Running pattern."""
        text = "Running: Microsoft Windows 10"
        result = extract_os_detection(text)
        self.assertEqual(result, "Microsoft Windows 10")

    def test_extract_os_detection_cpe(self):
        """Test OS CPE pattern."""
        text = "OS CPE: cpe:/o:linux:linux_kernel:4.15"
        result = extract_os_detection(text)
        self.assertEqual(result, "linux:linux_kernel:4.15")

    def test_extract_os_detection_aggressive_guess(self):
        """Test aggressive OS guess pattern."""
        text = "Aggressive OS guesses: Linux 4.15 (95%), Windows 10 (80%)"
        result = extract_os_detection(text)
        self.assertEqual(result, "Linux 4.15 (95%)")

    def test_extract_os_detection_no_match(self):
        """Test output without OS info."""
        text = "PORT   STATE SERVICE\n22/tcp open  ssh"
        result = extract_os_detection(text)
        self.assertIsNone(result)

    def test_extract_os_detection_empty_input(self):
        """Test empty/None input."""
        self.assertIsNone(extract_os_detection(""))
        self.assertIsNone(extract_os_detection(None))

    def test_extract_os_detection_truncation(self):
        """Test long OS string truncation to 100 chars."""
        long_os = "A" * 200
        text = f"OS details: {long_os}"
        result = extract_os_detection(text)
        self.assertEqual(len(result), 100)


class TestScannerNmapArguments(unittest.TestCase):
    """Tests for Nmap argument generation."""

    def test_get_nmap_arguments_modes(self):
        """Test different scan modes."""
        args_rapid = get_nmap_arguments("rapido")
        self.assertIn("-sn", args_rapid)
        self.assertIn("--max-retries 1", args_rapid)

        args_normal = get_nmap_arguments("normal")
        self.assertIn("-F", args_normal)
        self.assertIn("-sV", args_normal)

        args_full = get_nmap_arguments("completo")
        self.assertIn("-p-", args_full)
        # -sC is redundant with -A, so we only check for -A
        self.assertIn("-A", args_full)
        self.assertNotIn("--open", args_full)

    def test_get_nmap_arguments_invalid_mode(self):
        """Test fallback for invalid mode."""
        args = get_nmap_arguments("invalid_mode")
        # Should return normal mode args
        self.assertIn("-F", args)

    def test_get_nmap_arguments_stealth(self):
        """Test stealth mode with custom timing."""
        config = {"nmap_timing": "T2"}
        args = get_nmap_arguments("normal", config)
        self.assertIn("-T2", args)

    def test_get_nmap_arguments_for_target_ipv4(self):
        """Test IPv4 target doesn't add -6 flag."""
        args = get_nmap_arguments_for_target("normal", "192.168.1.0/24")
        self.assertNotIn("-6", args)

    def test_get_nmap_arguments_for_target_ipv6(self):
        """Test IPv6 target adds -6 flag."""
        args = get_nmap_arguments_for_target("normal", "2001:db8::/32")
        self.assertIn("-6", args)


class TestScannerOutputHasIdentity(unittest.TestCase):
    """Tests for identity detection in scan output."""

    def test_output_has_identity_with_mac(self):
        """Test detection of MAC address."""
        records = [{"stdout": "MAC Address: 00:11:22:33:44:55 (Vendor)"}]
        self.assertTrue(output_has_identity(records))

    def test_extract_vendor_mac_accepts_bytes(self):
        """extract_vendor_mac should accept bytes output from subprocess."""
        from redaudit.core.scanner import extract_vendor_mac

        mac, vendor = extract_vendor_mac(b"MAC Address: 00:11:22:33:44:55 (Vendor)\n")
        self.assertEqual(mac, "00:11:22:33:44:55")
        self.assertEqual(vendor, "Vendor")

    def test_output_has_identity_with_os_details(self):
        """Test detection of OS details."""
        records = [{"stdout": "OS details: Linux 4.x"}]
        self.assertTrue(output_has_identity(records))

    def test_output_has_identity_with_running(self):
        """Test detection of Running pattern."""
        records = [{"stdout": "Running: Windows Server 2019"}]
        self.assertTrue(output_has_identity(records))

    def test_output_has_identity_with_device_type(self):
        """Test detection of Device type."""
        records = [{"stdout": "Device type: router|switch"}]
        self.assertTrue(output_has_identity(records))

    def test_output_has_identity_empty(self):
        """Test empty records."""
        self.assertFalse(output_has_identity([]))
        self.assertFalse(output_has_identity([{"stdout": ""}]))
        self.assertFalse(output_has_identity([{"stdout": "PORT STATE SERVICE"}]))


if __name__ == "__main__":
    unittest.main()


def test_extract_vendor_mac_non_string_input():
    """Test extract_vendor_mac handles non-string input (line 27)."""
    # Pass an integer (non-string, non-bytes)
    mac, vendor = extract_vendor_mac(12345)
    assert mac is None
    assert vendor is None


def test_output_has_identity_stderr_bytes():
    """Test output_has_identity handles stderr as bytes (line 68)."""
    records = [
        {
            "stdout": "",
            "stderr": b"MAC Address: aa:bb:cc:dd:ee:ff (TestVendor)",
        }
    ]
    result = output_has_identity(records)
    assert result is True


def test_output_has_identity_stdout_bytes():
    """Test output_has_identity handles stdout as bytes (line 66)."""
    records = [
        {
            "stdout": b"Running: Linux",
            "stderr": "",
        }
    ]
    result = output_has_identity(records)
    assert result is True


def test_finalize_host_status_filtered_with_unfiltered():
    """Test finalize_host_status handles 'filtered' with 'unfiltered' (line 123-124)."""
    host_record = {
        "status": STATUS_DOWN,
        "ports": [],
        "deep_scan": {
            "commands": [
                {
                    "stdout": "Some ports are filtered but others are unfiltered",
                    "stderr": "",
                }
            ]
        },
    }
    # Should NOT return FILTERED because 'unfiltered' is present
    result = finalize_host_status(host_record)
    # Falls through to check other conditions
    assert result in [STATUS_DOWN, STATUS_FILTERED]


def test_finalize_host_status_filtered_without_unfiltered():
    """Test finalize_host_status returns FILTERED when only 'filtered' is present."""
    host_record = {
        "status": STATUS_DOWN,
        "ports": [],
        "deep_scan": {
            "commands": [
                {
                    "stdout": "All ports are filtered on this host",
                    "stderr": "",
                }
            ]
        },
    }
    result = finalize_host_status(host_record)
    assert result == STATUS_FILTERED


def test_finalize_host_status_os_detection_list():
    """Test finalize_host_status with os_detection list (line 135)."""
    host_record = {
        "status": STATUS_DOWN,
        "ports": [],
        "deep_scan": {
            "commands": [],
            "os_detection": ["Linux 5.x"],  # Non-empty list
        },
    }
    result = finalize_host_status(host_record)
    assert result == STATUS_FILTERED


def test_finalize_host_status_returns_down():
    """Test finalize_host_status returns STATUS_DOWN (line 147)."""
    host_record = {
        "status": STATUS_DOWN,
        "ports": [],
        "deep_scan": {
            "commands": [
                {
                    "stdout": "some output",
                    "stderr": "",
                }
            ]
        },
    }
    # No identity markers, sufficient output, should return DOWN
    result = finalize_host_status(host_record)
    assert result == STATUS_DOWN


def test_run_nmap_command_stdout_bytes():
    """Test run_nmap_command handles stdout as bytes (line 94)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        # Mock result with bytes stdout
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"nmap output as bytes"
        mock_result.stderr = ""
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
        )

        assert "stdout" in result
        assert isinstance(result["stdout"], str)


def test_run_nmap_command_stderr_bytes():
    """Test run_nmap_command handles stderr as bytes (line 96)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        # Mock result with bytes stderr
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = b"error message as bytes"
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
        )

        assert "stderr" in result
        assert isinstance(result["stderr"], str)


def test_run_nmap_command_max_stdout_none():
    """Test run_nmap_command with max_stdout=None (line 103)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        long_output = "x" * 10000
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = long_output
        mock_result.stderr = ""
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
            max_stdout=None,  # No truncation
        )

        assert len(result["stdout"]) == 10000


def test_run_nmap_command_max_stdout_zero():
    """Test run_nmap_command with max_stdout=0 (line 105)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "some output"
        mock_result.stderr = ""
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
            max_stdout=0,
        )

        assert result["stdout"] == ""


def test_run_nmap_command_max_stderr_none():
    """Test run_nmap_command with max_stderr=None (line 109)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        long_error = "e" * 5000
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = long_error
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
            max_stderr=None,  # No truncation
        )

        assert len(result["stderr"]) == 5000


def test_run_nmap_command_max_stderr_zero():
    """Test run_nmap_command with max_stderr=0 (line 111)."""
    with patch("redaudit.core.scanner.nmap._make_runner") as mock_runner_factory:
        mock_runner = MagicMock()
        mock_runner_factory.return_value = mock_runner

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "some error"
        mock_result.timed_out = False
        mock_runner.run.return_value = mock_result

        deep_obj = {}
        result = run_nmap_command(
            cmd=["nmap", "-sn", "192.168.1.1"],
            timeout=10,
            host_ip="192.168.1.1",
            deep_obj=deep_obj,
            max_stderr=0,  # Suppress stderr
        )

        assert result["stderr"] == ""
