# RedAudit Usage Guide

[![Ver en español](https://img.shields.io/badge/Ver%20en%20español-red?style=flat-square)](USAGE_ES.md)

## CLI Reference

RedAudit is designed for stateless execution via command-line arguments.

### Syntax

```bash
sudo redaudit [TARGET] [OPTIONS]
# Or via Python module (v2.6+)
sudo python -m redaudit [TARGET] [OPTIONS]
```

### Core Arguments

| Flag | Description |
| :--- | :--- |
| `-t`, `--target` | Target IP, subnet (CIDR), or comma-separated list. |
| `-m`, `--mode` | Scan intensity: `fast` (ICMP), `normal` (Top ports), `full` (All ports + scripts). |
| `--deep` | Enable aggressive vulnerability scanning (Web/NSE). Equivalent to `-m full`. |
| `-o`, `--output` | Specify output directory. Default: `~/RedAuditReports`. |
| `-l`, `--lang` | Interface language: `en` (default), `es`. |

### Performance & Evasion

| Flag | Description |
| :--- | :--- |
| `--threads <N>` | Set size of thread pool for concurrent host scanning. |
| `-r`, `--rate-limit` | Seconds to sleep between thread operations (float). |
| `--pcap` | Enable raw packet capture (`tcpdump`) during scan. |

### Security

| Flag | Description |
| :--- | :--- |
| `--encrypt` | Encrypt output artifacts with AES-128. Prompts for password if not provided. |
| `--version` | Display version information and exit. |

## Examples

**1. Standard Subnet Audit**
Enumerates services on a Class C subnet with default concurrency.

```bash
sudo redaudit -t 192.168.1.0/24
```

**2. High-Stealth Targeted Scan**
Scans a single host with rate limiting enabled to reduce noise.

```bash
sudo redaudit -t 10.0.0.50 --rate-limit 1.5 --mode normal
```

**3. Forensics Mode**
Deep scan with full traffic capture and encrypted reporting for chain-of-custody.

```bash
sudo redaudit -t 192.168.1.100 --deep --pcap --encrypt
```

### 3. Reports & Encryption

Reports are saved with a timestamp `redaudit_YYYYMMDD_HHMMSS`.

- **Plain**: `.json` and `.txt`.
- **Encrypted**: `.json.enc`, `.txt.enc`, and `.salt`.

To decrypt results:

```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```

This will generate `.decrypted` files (or restore original extension) after password verification.

### 4. Logging

Debug logs are stored in `~/.redaudit/logs/`. Check these files if the scan fails or behaves unexpectedly.

## Performance & Stealth

### Rate Limiting

RedAudit allows you to set a delay (in seconds) between scanning hosts.

- **0s (Default)**: Maximum speed. Best for internal audits where noise is not a concern.
- **1-5s**: Moderate stealth. Reduces the chance of triggering simple rate-limit firewalls.
- **>10s**: High stealth. Significantly slows down the audit but minimizes network congestion and detection risk.

**Note on Heartbeat**: If you set a very high delay (e.g., 60s) with many threads, the scan might seem "frozen". Check the "Active hosts" log or the heartbeat status.

### CLI Execution Markers

RedAudit v2.6 strictly informs you about the commands being executed:

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
