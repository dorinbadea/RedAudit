# RedAudit Usage Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](USAGE_ES.md)

## CLI Reference

RedAudit is designed for stateless execution via command-line arguments.

### Syntax

```bash
sudo redaudit [OPTIONS]
# Or via Python module (v2.6+)
sudo python -m redaudit [OPTIONS]
```

### Core Arguments

| Flag | Description |
| :--- | :--- |
| `-t`, `--target` | Target IP, subnet (CIDR), or comma-separated list. |
| `-m`, `--mode` | Scan intensity: `fast` (discovery), `normal` (top ports), `full` (all ports + scripts). |
| `-o`, `--output` | Specify output directory. Default: `~/Documents/RedAuditReports`. |
| `--lang` | Interface language: `en` (default), `es`. |
| `-y`, `--yes` | Skip legal warning confirmation (use with caution). |

### Performance & Evasion

| Flag | Description |
| :--- | :--- |
| `-j`, `--threads <N>` | Set thread pool size for concurrent host scanning (1-16, default: 6). |
| `--rate-limit` | Seconds to sleep between host scans (float). Includes ±30% jitter (v2.7). |
| `--prescan` | Enable fast asyncio pre-scan before nmap (v2.7). |
| `--prescan-ports` | Port range for pre-scan (default: 1-1024). |
| `--prescan-timeout` | Pre-scan connection timeout in seconds (default: 0.5). |
| `--udp-mode` | UDP scan mode: `quick` (default) or `full` (v2.8). |
| `--skip-update-check` | Skip update check at startup (v2.8). |
| `--no-deep-scan` | Disable adaptive deep scan. |
| `--no-vuln-scan` | Disable web vulnerability scanning. |
| `--no-txt-report` | Disable TXT report generation. |
| `--max-hosts` | Maximum number of hosts to scan (default: all). |

### Security

| Flag | Description |
| :--- | :--- |
| `-e`, `--encrypt` | Encrypt output artifacts with AES-128. Prompts for password if not provided. |
| `--encrypt-password` | Password for encryption (non-interactive mode). |
| `-V`, `--version` | Display version information and exit. |

## Examples

**1. Standard Subnet Audit**
Enumerates services on a Class C subnet with default concurrency.

```bash
sudo redaudit -t 192.168.1.0/24 --mode normal --yes
```

**2. High-Stealth Targeted Scan**
Scans a single host with rate limiting enabled to reduce noise.

```bash
sudo redaudit -t 10.0.0.50 --rate-limit 1.5 --mode normal --yes
```

**3. Full Audit with Encryption**
Deep scan with encrypted reporting for chain-of-custody.

```bash
sudo redaudit -t 192.168.1.100 --mode full --encrypt --yes
```

**4. Fast Pre-scan on Large Range (v2.7)**
Use asyncio pre-scan for fast port discovery before nmap.

```bash
sudo redaudit -t 192.168.1.0/24 --prescan --prescan-ports 1-1024 --yes
```

### Reports & Encryption

Reports are saved in timestamped subfolders (v2.8+): `RedAudit_YYYY-MM-DD_HH-MM-SS/`

Each scan session creates its own folder with:

- **Plain**: `.json` and `.txt`.
- **Encrypted**: `.json.enc`, `.txt.enc`, and `.salt`.
- **PCAP**: Traffic capture files.

To decrypt results:

```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```

This will generate `.decrypted` files (or restore original extension) after password verification.

### Logging

Debug logs are stored in `~/.redaudit/logs/`. Check these files if the scan fails or behaves unexpectedly.

## Performance & Stealth

### Rate Limiting

RedAudit allows you to set a delay (in seconds) between scanning hosts. **v2.7 adds ±30% random jitter** to this delay for IDS evasion.

- **0s (Default)**: Maximum speed. Best for internal audits where noise is not a concern.
- **1-5s**: Moderate stealth. Reduces the chance of triggering simple rate-limit firewalls.
- **>10s**: High stealth. Significantly slows down the audit but minimizes network congestion and detection risk.

### Pre-scan (v2.7)

Enable `--prescan` to use asyncio TCP connect for fast port discovery before invoking nmap:

```bash
sudo redaudit -t 192.168.1.0/24 --prescan --prescan-ports 1-1024 --yes
```

**Note on Heartbeat**: If you set a very high delay (e.g., 60s) with many threads, the scan might seem "frozen". Check the logs or the heartbeat status.

### CLI Execution Markers

RedAudit v2.8.0 strictly informs you about the commands being executed:

- **`[nmap] 192.168.x.x → nmap ...`**: Standard port scan.
- **`[deep] 192.168.x.x → combined ...`**: Deep Identity Scan execution (expect 90-140s duration).

### Adaptive Deep Scan & Traffic Capture

RedAudit automatically attempts an "Adaptive Deep Scan" on hosts that:

1. **Have >8 open ports**
2. **Have suspicious services** (socks, proxy, vpn, tor, nagios, etc.)
3. **Have very few ports (<=3)**
4. **Have open ports but no version information detected**

- **Adaptive Strategy**: Runs a 2-phase scan (TCP aggressive first, then UDP/OS fallback only if Phase 1 didn't find MAC/OS identity) to fingerprint complex hosts.
- **Traffic Capture**: As part of Deep Scan, if `tcpdump` is available, the tool captures a **50-packet snippet** (max 15s) from the host's traffic.
  - Saves `.pcap` files in your report directory.
  - If `tshark` is installed, a text summary of protocols is included in the JSON report.
  - *Defense*: The capture duration is strictly capped to prevent hanging.

---

RedAudit is licensed under **GPLv3**. See [LICENSE](../LICENSE) for details.
