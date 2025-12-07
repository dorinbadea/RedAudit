# RedAudit Report Schema

RedAudit generates reports in JSON format. Below is the structure of the `redaudit_report_<timestamp>.json` files found in the output directory.

This schema documents RedAudit JSON reports.  
The implementation is licensed under GPLv3 – see [LICENSE](../LICENSE).

> **Note**: If encryption was enabled during the scan, the output will be a `.json.enc` file (binary AES encrypted). This schema applies to the **decrypted** content obtained via `redaudit_decrypt.py`.

## Root Object

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | ISO 8601 timestamp of the scan start |
| `version` | string | Version of RedAudit used (e.g., "2.5") |
| `network_info` | array | List of detected network interfaces and their CIDRs |
| `hosts` | array | List of `Host` objects discovered and scanned |
| `vulnerabilities` | array | List of web vulnerability findings (if web scanning was enabled) |
| `summary` | object | High-level statistics |

## Host Object

Represents a single discovered device.

```json
{
  "ip": "192.168.1.10",
  "hostname": "workstation-01",
  "status": "up",
  "ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "product": "Apache",
      "version": "2.5",
      "is_web_service": true
    }
  ],
  "web_ports_count": 1,
  "total_ports_found": 5,
  "dns": {
    "reverse": ["workstation-01.local"],
    "whois_summary": "OrgName: Example Corp..."
  },
  "deep_scan": {
    "strategy": "adaptive_v2.5",
    "mac_address": "00:11:22:33:44:55",
    "vendor": "Vendor Name",
    "phase2_skipped": false,
    "commands": [
      {
        "command": "nmap -A -sV -Pn -p- --open --version-intensity 9 192.168.1.10",
        "returncode": 0,
        "stdout": "...",
        "stderr": "",
        "duration_seconds": 105.2
      }
    ],
    "pcap_capture": {
      "pcap_file": "/abspath/to/traffic_192_168_1_10_TIMESTAMP.pcap",
      "iface": "eth0",
      "tshark_summary": "Active protocols: TCP(90%), UDP(10%)...",
      "tshark_error": null
    }
  }
}
```

### Deep Scan Object (Optional)
This field appears only if automatic deep scan was triggered.

| Field | Type | Description |
|---|---|---|
| `strategy` | string | Strategy used ("adaptive_v2.5") |
| `mac_address` | string | (Optional) MAC address if detected |
| `vendor` | string | (Optional) Hardware vendor if detected |
| `phase2_skipped` | boolean | True if Phase 2 (UDP/OS) was skipped because Phase 1 found identity |
| `commands` | array | List of executed Nmap commands, logs, and durations |
| `commands[].command` | string | Full command line executed |
| `commands[].returncode` | integer | Exit code of the command |
| `commands[].stdout` | string | Standard output (truncated to 8000 chars) |
| `commands[].stderr` | string | Standard error (truncated to 2000 chars) |
| `commands[].duration_seconds` | float | Execution time in seconds |
| `commands[].error` | string | (Optional) Error message if command failed |
| `pcap_capture` | object | (Optional) Details about the micro-traffic capture |
| `pcap_capture.pcap_file` | string | Absolute path to the generated .pcap file |
| `pcap_capture.iface` | string | Network interface used for capture |
| `pcap_capture.tshark_summary` | string | (Optional) High-level protocol stats if tshark is installed |
| `pcap_capture.tshark_error` | string | (Optional) Error from tshark if it failed |
| `pcap_capture.tcpdump_error` | string | (Optional) Error from tcpdump if it failed |

### DNS Object (Optional)
Appears in host records when DNS/whois enrichment was performed.

| Field | Type | Description |
|---|---|---|
| `reverse` | array | List of reverse DNS PTR records |
| `whois_summary` | string | (Optional) Whois information for public IPs (first 25 lines) |

## Vulnerabilities Array
List of web vulnerability findings. Each entry contains:

| Field | Type | Description |
|---|---|---|
| `host` | string | IP address of the host |
| `vulnerabilities` | array | List of vulnerability findings per URL |
| `vulnerabilities[].url` | string | Full URL tested |
| `vulnerabilities[].port` | integer | Port number |
| `vulnerabilities[].service` | string | Service name |
| `vulnerabilities[].findings` | array | List of vulnerability strings |
| `vulnerabilities[].whatweb` | string | (Optional) WhatWeb output |
| `vulnerabilities[].nikto_findings` | array | (Optional) Nikto findings (if FULL mode) |
| `vulnerabilities[].curl_headers` | string | (Optional) HTTP headers from curl |
| `vulnerabilities[].wget_spider` | string | (Optional) Wget spider output |
| `vulnerabilities[].tls_info` | string | (Optional) OpenSSL TLS certificate info |

## Scan Summary Object

```json
{
  "networks": 1,
  "hosts_found": 15,
  "hosts_scanned": 12,
  "vulns_found": 3,
  "duration": "0:02:05"
}
```

| Field | Type | Description |
|---|---|---|
| `networks` | integer | Number of target networks scanned |
| `hosts_found` | integer | Total hosts discovered (up) |
| `hosts_scanned` | integer | Hosts that underwent full port scanning |
| `vulns_found` | integer | Total web vulnerabilities found |
| `duration` | string | Total scan duration (HH:MM:SS format) |

## Network Info Array
List of detected network interfaces.

```json
[
  {
    "interface": "eth0",
    "ip": "192.168.1.100",
    "network": "192.168.1.0/24",
    "hosts_estimated": 253,
    "type": "Ethernet"
  }
]
```
