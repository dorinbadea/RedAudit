# SIEM Integration Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](SIEM_INTEGRATION.es.md)

RedAudit produces SIEM-friendly JSONL exports and provides Filebeat/Logstash configs for ECS-aligned ingestion into Elastic Stack and other platforms.

## Quick Start (Elastic Stack)

### 1. Configure Filebeat

Copy the bundled configuration:

```bash
sudo cp siem/filebeat.yml /etc/filebeat/filebeat.yml
```

Edit the paths and credentials, then:

```bash
sudo filebeat setup
sudo systemctl restart filebeat
```

### 2. Configure Logstash (Optional)

For additional processing (severity normalization, CVE extraction):

```bash
sudo cp siem/logstash.conf /etc/logstash/conf.d/redaudit.conf
sudo systemctl restart logstash
```

### 3. Import Sigma Rules

Convert Sigma rules to your SIEM format:

```bash
# For Elasticsearch/Kibana
sigma convert -t elasticsearch -p ecs_windows siem/sigma/*.yml

# For Splunk
sigma convert -t splunk siem/sigma/*.yml

# For QRadar
sigma convert -t qradar siem/sigma/*.yml
```

## RedAudit JSONL Schema

JSONL exports are generated only when report encryption is disabled.

### findings.jsonl

Each line contains a vulnerability finding:

```json
{
  "finding_id": "b6c5c8b5...",
  "asset_id": "7f3a2d1c...",
  "asset_ip": "192.168.1.100",
  "asset_hostname": "webserver",
  "port": 443,
  "url": "https://192.168.1.100/",
  "severity": "high",
  "normalized_severity": 8.2,
  "category": "vuln",
  "title": "Weak TLS cipher",
  "descriptive_title": "Weak TLS cipher suite detected",
  "source": "testssl",
  "cve_ids": ["CVE-2021-12345"],
  "timestamp": "2025-12-18T12:00:00Z",
  "scan_mode": "normal",
  "session_id": "9db9b6b1-2c4c-4b2a-8d42-0b0a6f0b0a3f",
  "schema_version": "3.10.0",
  "scanner": "RedAudit",
  "scanner_version": "3.10.0"
}
```

Notes:
- `asset_hostname` uses best-effort fallback order: `hostname`, then `dns.reverse`, then `phase0_enrichment.dns_reverse`.

### assets.jsonl

Each line contains a discovered host/service:

```json
{
  "asset_id": "7f3a2d1c...",
  "ip": "192.168.1.100",
  "hostname": "webserver",
  "status": "up",
  "risk_score": 72,
  "asset_type": "server",
  "os_detected": "Linux 5.x",
  "total_ports": 6,
  "web_ports": 2,
  "finding_count": 3,
  "tags": ["web", "linux"],
  "mac": "00:11:22:33:44:55",
  "vendor": "Dell Inc.",
  "timestamp": "2025-12-18T12:00:00Z",
  "scan_mode": "normal",
  "session_id": "9db9b6b1-2c4c-4b2a-8d42-0b0a6f0b0a3f",
  "schema_version": "3.10.0",
  "scanner": "RedAudit",
  "scanner_version": "3.10.0"
}
```

Notes:
- `hostname` uses best-effort fallback order: `hostname`, then `dns.reverse`, then `phase0_enrichment.dns_reverse`.

### Nuclei Raw Streams (NDJSON Contract)

RedAudit also writes raw Nuclei streams in the scan folder:

- `nuclei_output.json`: NDJSON stream (one JSON object per non-empty line).
- `nuclei_output_resume.json`: optional NDJSON stream for resume appends.

These are raw scanner streams (not ECS-normalized SIEM exports), and they are validated by the artifact gate:

```bash
python scripts/check_scan_artifacts.py --run-dir <scan_folder> --strict
```

Expected behavior:
- `nuclei_output.json` must parse as NDJSON.
- `nuclei_output_resume.json` can be empty when no new records were appended.

## Included Sigma Rules

| Rule | Description |
|------|-------------|
| `redaudit_critical_vuln.yml` | Critical/high severity findings |
| `redaudit_missing_headers.yml` | Web security header issues |
| `redaudit_ssl_tls_vuln.yml` | SSL/TLS vulnerabilities |

## Splunk Integration

For Splunk, use the HTTP Event Collector (HEC) or your preferred ingestion pipeline. RedAudit does not ship Splunk-specific configs.

1. Create a HEC token in Splunk
2. Configure your shipper to send JSONL events to HEC
3. Map RedAudit fields to your index/sourcetype conventions

## Troubleshooting

- **No data in Elasticsearch?** Check Filebeat logs: `journalctl -u filebeat -f`
- **Parsing errors?** Validate line-delimited streams explicitly:
  - `jq -c . findings.jsonl >/dev/null`
  - `jq -c . assets.jsonl >/dev/null`
  - `jq -c . nuclei_output.json >/dev/null`
- **Missing fields?** Verify Filebeat/Logstash transformations and ECS mapping
