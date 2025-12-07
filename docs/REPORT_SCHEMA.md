# RedAudit Report Schema

RedAudit generates reports in JSON format. Below is the structure of the `redaudit_report_<timestamp>.json` files found in the output directory.

This schema documents RedAudit JSON reports.  
The implementation is licensed under GPLv3 – see [LICENSE](../LICENSE).

> **Note**: If encryption was enabled during the scan, the output will be a `.json.enc` file (binary AES encrypted). This schema applies to the **decrypted** content obtained via `redaudit_decrypt.py`.

## Root Object

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | ISO 8601 timestamp of the scan start |
| `version` | string | Version of RedAudit used (e.g., "2.3") |
| `scanned_networks` | array | List of CIDRs that were targeted |
| `hosts` | array | List of `Host` objects discovered and scanned |
| `scan_summary` | object | High-level statistics |

## Host Object

Represents a single discovered device.

```json
{
  "ip": "192.168.1.10",
  "status": "up",
  "hostnames": [
    {
      "name": "workstation-01",
      "type": "PTR"
    }
  ],
  "ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "version": "Apache 2.4.41"
    }
  ],
  "os_match": [
    {
      "name": "Linux 5.4",
      "accuracy": 98
    }
  ],
  "web_analysis": {
    "whatweb": "summary of technologies...",
    "nikto": "summary of vulnerabilities..."
  },
  "deep_scan": {
    "commands": [
      {
        "command": "nmap -A -sV -Pn -p- --open 192.168.1.10",
        "returncode": 0,
        "stdout": "..."
      }
    ],
    "pcap_capture": {
      "pcap_file": "/abspath/to/traffic_192_168_1_10_TIMESTAMP.pcap",
      "iface": "eth0",
      "tshark_summary": "Active protocols: TCP(90%), UDP(10%)..."
    }
  }
}
```

### Deep Scan Object (Optional)
This field appears only if automatic deep scan was triggered.

| Field | Type | Description |
|---|---|---|
| `commands` | array | List of executed Nmap commands and their outputs |
| `pcap_capture` | object | Details about the micro-traffic capture |
| `pcap_capture.pcap_file` | string | Absolute path to the generated .pcap file |
| `pcap_capture.tshark_summary` | string | (Optional) High-level protocol stats if tshark is installed |

## Scan Summary Object

```json
{
  "total_hosts_up": 15,
  "total_open_ports": 42,
  "duration_seconds": 125.5
}
```
