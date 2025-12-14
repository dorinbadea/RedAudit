# RedAudit Report Schema

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](../es/REPORT_SCHEMA.md)

## Overview

RedAudit generates machine-readable reports in JSON format. This document describes the schema structure for `redaudit_<timestamp>.json` artifacts.

**Data Types**: Standard JSON types (`string`, `number`, `boolean`, `array`, `object`).
**Nullable**: Fields are nullable unless specified otherwise.
**Source Module**: `redaudit/core/reporter.py`

## Additional Export Views (v3.1)

In the same output directory, RedAudit can also generate flat export files optimized for SIEM and AI pipelines:

- `findings.jsonl`: One finding per line
- `assets.jsonl`: One asset per line
- `summary.json`: Compact dashboard summary

These exports are generated only when report encryption is **disabled**, to avoid creating plaintext artifacts alongside encrypted reports.

## Schema Definition

### Root Object

The top-level container for the scan session.

| Field | Type | Description |
| :--- | :--- | :--- |
| `schema_version` | `string` | Schema version ("3.1") |
| `generated_at` | `string` | Report generation timestamp (ISO 8601) **(v3.1)** |
| `event_type` | `string` | Event type for SIEM ingestion ("redaudit.scan.complete") |
| `session_id` | `string` | Unique UUID for this scan session |
| `timestamp` | `string` | Scan start timestamp (ISO 8601) |
| `timestamp_end` | `string` | Scan end timestamp (ISO 8601) |
| `version` | `string` | RedAudit version |
| `scanner` | `object` | Scanner metadata: `name`, `version`, `mode` |
| `scanner_versions` | `object` | Detected tool versions (nmap, nikto, testssl, etc.) **(v3.1)** |
| `targets` | `array` | List of target networks scanned |
| `network_info` | `array` | List of network interface objects |
| `topology` | `object` | (Optional) Best-effort topology discovery output (ARP/VLAN/LLDP + gateway/routes) **(v3.1+)** |
| `hosts` | `array` | List of `Host` objects (see below) |
| `vulnerabilities` | `array` | List of vulnerability findings |
| `summary` | `object` | Aggregated statistics |

### Host Object

Represents a single targeted IP address.

```json
{
  "ip": "192.168.1.10",
  "status": "up",
  "ports": [
    {
      "port": 80,
      "state": "open",
      "protocol": "tcp",
      "service": "http",
      "product": "Apache httpd",
      "version": "2.4.41",
      "banner": "Apache/2.4.41 (Ubuntu)",
      "ssl_cert": {
        "subject": "CN=example.com",
        "issuer": "Let's Encrypt"
      },
      "known_exploits": [
        {
          "title": "Apache 2.4.41 - Remote Code Execution",
          "id": "EDB-12345",
          "url": "https://www.exploit-db.com/exploits/12345"
        }
      ]
    }
  ]
}
```

**Host Status Types**:

- `up`: Host responded and has open ports
- `down`: No response at all
- `filtered`: MAC/vendor detected but ports filtered
- `no-response`: Deep scan attempted but no meaningful data

### Deep Scan Object (Optional)

This field appears only if automatic deep scan was triggered.

| Field | Type | Description |
|---|---|---|
| `strategy` | string | Strategy identifier (e.g., `adaptive_v2.8`) |
| `mac_address` | string | (Optional) MAC address if detected |
| `vendor` | string | (Optional) Hardware vendor if detected |
| `phase2_skipped` | boolean | True if Phase 2 (UDP/OS) was skipped because Phase 1 found identity |
| `phase2b_skipped` | boolean | True if extended UDP identity scan was skipped (quick mode) |
| `udp_mode` | string | UDP scan mode used: `quick` or `full` |
| `udp_top_ports` | integer | (Optional) Top UDP ports count used in full mode Phase 2b (50-500) **(v3.1+)** |
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

### Topology Object (Optional) (v3.1+)

This field appears only if topology discovery was enabled (CLI: `--topology` / `--topology-only`, or interactive prompt).

Topology discovery is **best-effort**: missing tools, permissions, or lack of traffic will reduce visibility but should not fail the scan.

| Field | Type | Description |
|---|---|---|
| `enabled` | boolean | Always true when the block is present |
| `generated_at` | string | Timestamp (ISO 8601) |
| `tools` | object | Tool availability flags (`ip`, `tcpdump`, `arp-scan`, `lldpctl`) |
| `routes` | array | Output of `ip route show` parsed into objects |
| `default_gateway` | object | (Optional) Default gateway object with `ip`, `interface`, `metric` |
| `interfaces` | array | Per-interface topology objects (ARP, VLAN, LLDP, etc.) |
| `candidate_networks` | array | Route-table networks not in scan targets or local interface nets |
| `errors` | array | Best-effort errors encountered during discovery |

**interfaces[]** entries (high level):

| Field | Type | Description |
|---|---|---|
| `interface` | string | Interface name (e.g., `eth0`) |
| `ip` | string | (Optional) Interface IP address |
| `networks` | array | Local networks associated with the interface |
| `arp` | object | ARP discovery output (`method`, `hosts`, `error`) |
| `neighbor_cache` | object | `ip neigh` parsed entries (if available) |
| `vlan` | object | Observed VLAN IDs (`ids`, `sources`) |
| `lldp` | object | LLDP neighbor summaries (if available) |
| `cdp` | object | CDP raw observations (best-effort, if captured) |

### CVE Enrichment Fields (Optional)

These fields appear only when CVE correlation is enabled (e.g., `--cve-lookup`) and enrichment data is available.
Enrichment is performed only for services with detected version information (or a versioned CPE).

**Port-level fields** (inside `hosts[].ports[]`):

| Field | Type | Description |
|---|---|---|
| `cves` | array | (Optional) List of CVEs (top 10) mapped to the service |
| `cves[].cve_id` | string | CVE identifier (e.g., `CVE-2024-12345`) |
| `cves[].cvss_score` | number | (Optional) CVSS base score |
| `cves[].cvss_severity` | string | (Optional) CVSS severity (LOW/MEDIUM/HIGH/CRITICAL) |
| `cves[].description` | string | (Optional) Short description (truncated) |
| `cves[].published` | string | (Optional) Published timestamp (ISO 8601) |
| `cve_count` | integer | (Optional) Total number of matched CVEs (may be >10) |
| `cve_max_severity` | string | (Optional) Max severity across matched CVEs |

**Host-level fields** (inside `hosts[]`):

| Field | Type | Description |
|---|---|---|
| `cve_summary` | object | (Optional) Aggregated CVE statistics for the host |
| `cve_summary.total` | integer | Total CVEs across all ports |
| `cve_summary.critical` | integer | Count of ports with max severity CRITICAL |
| `cve_summary.high` | integer | Count of ports with max severity HIGH |

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
| `vulnerabilities[].testssl_analysis` | object | (Optional) TestSSL.sh results (if FULL mode and HTTPS) |
| `vulnerabilities[].severity` | string | Severity enum: critical/high/medium/low/info |
| `vulnerabilities[].severity_score` | integer | Numeric severity (0-100) |
| `vulnerabilities[].finding_id` | string | Deterministic hash for deduplication **(v3.1)** |
| `vulnerabilities[].category` | string | Classification: surface/misconfig/crypto/auth/info-leak/vuln **(v3.1)** |
| `vulnerabilities[].normalized_severity` | float | CVSS-like score (0.0-10.0) **(v3.1)** |
| `vulnerabilities[].original_severity` | object | Preserved tool-native severity **(v3.1)** |
| `vulnerabilities[].parsed_observations` | array | Structured findings from Nikto/TestSSL **(v3.1)** |
| `vulnerabilities[].raw_tool_output_sha256` | string | (Optional) Hash of raw output **(v3.1)** |
| `vulnerabilities[].raw_tool_output_ref` | string | (Optional) Path to externalized output **(v3.1)** |
| `vulnerabilities[].curl_headers` | string | (Optional) HTTP headers from curl |
| `vulnerabilities[].wget_spider` | string | (Optional) Wget spider output |
| `vulnerabilities[].tls_info` | string | (Optional) OpenSSL TLS certificate info |
| `vulnerabilities[].nikto_filtered_count` | integer | Number of Nikto false positives filtered |

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
| `unified_asset_count` | integer | Number of unified assets after entity resolution |
| `multi_interface_devices` | integer | Devices detected with multiple network interfaces |
| `max_risk_score` | integer | Highest risk score across all hosts (0-100) |
| `avg_risk_score` | float | Average risk score (0-100) |
| `high_risk_hosts` | integer | Hosts with risk score >= 70 |

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

## New Features (v3.0.0)

### SIEM Enhancement (ECS Compliance)

```json
{
  "ecs": {"version": "8.11"},
  "event": {
    "kind": "enrichment",
    "category": ["network", "host"],
    "module": "redaudit"
  }
}
```

### Host Enrichment

| Field | Type | Description |
|---|---|---|
| `risk_score` | integer | Risk score (0-100) based on ports, services, exploits |
| `tags` | array | Auto-generated tags (web, database, iot, admin, etc.) |
| `observable_hash` | string | SHA256 hash for SIEM deduplication |
| `ecs_host` | object | ECS-compliant host object with `ip`, `mac`, `name` |

### Unified Assets Array (Entity Resolution)

```json
{
  "unified_assets": [
    {
      "asset_name": "msi-laptop",
      "asset_type": "workstation",
      "interfaces": [
        {"ip": "192.168.1.10", "mac": "D8:43:AE:...", "type": "WiFi"},
        {"ip": "192.168.1.15", "mac": "10:91:D1:...", "type": "Ethernet"}
      ],
      "interface_count": 2,
      "consolidated_ports": [...],
      "source_ips": ["192.168.1.10", "192.168.1.15"]
    }
  ]
}
```
