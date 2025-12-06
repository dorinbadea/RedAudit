<div align="center">
  <img src="assets/header.png" alt="RedAudit Banner" width="100%">

  <br>

  [ 🇬🇧 English ](README.md) | [ 🇪🇸 Español ](README_ES.md)

  <br>

  ![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)
  ![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
  ![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
</div>

<br>

**RedAudit** is an interactive, automated network auditing tool designed for Kali Linux and Debian-based systems. It streamlines the reconnaissance process by combining network discovery, port scanning, and vulnerability assessment into a single, easy-to-use CLI workflow.

## 🖥️ Preview

```text
    ____          _    _   _           _ _ _
   / __ \___  ___| |  / \  _   _  __| (_) |_
  / /_/ / _ \/ __| | / _ \| | | |/ _` | | __|
 / _, _/  __/ (__| |/ ___ \ |_| | (_| | | |_
/_/ |_|\___|\___|_|/_/   \_\__,_|\__,_|_|\__|
                                      v2.3
══════════════════════════════════════════════════════
   INTERACTIVE NETWORK AUDIT     ::  KALI LINUX
══════════════════════════════════════════════════════

? SCAN CONFIGURATION
============================================================

? TARGET SELECTION
--------------------------------------------------
✓ Interfaces detected:
   1. 192.168.1.0/24 (eth0) - ~253 hosts
   2. Enter manual
   3. Scan ALL

? Select network: [1-3] (1): 
```

## Features

- **Interactive CLI** with guided menus for target selection, scan mode and options.
- **Automatic local network discovery** (`ip` / `netifaces`) to suggest sensible CIDR ranges.
- **Multi-mode scanning**:
  - **FAST** – host discovery only (`-sn`), minimal noise.
  - **NORMAL** – top ports + service/version detection (balanced coverage).
  - **FULL** – all ports, scripts, OS and service detection, plus optional web checks.
- **Automatic deep scans** for “quiet” or error-prone hosts (extra Nmap passes, UDP probing and optional `tcpdump` capture).
- **Web reconnaissance** via `whatweb` and `nikto` when available, plus optional `curl` / `wget` / `openssl` enrichment.
- **Traffic & DNS enrichment**: small PCAP captures (`tcpdump` + `tshark`) and reverse DNS / whois for public IPs.
- **Resilience for long runs**: a heartbeat thread that periodically prints activity and detects potential hangs, plus graceful signal handling with partial report saving on Ctrl+C.
- **Professional Logging**: Rotating logs stored in `~/.redaudit/logs` for audit trails and debugging.
- **Security Hardening**: Strict input sanitization (IP/Hostname/Interface) to prevent injection, plus optional report encryption (Fernet/AES).
- **Rate Limiting**: Configurable delay between hosts for stealthier scans.
- **Reporting**: structured JSON + human-readable TXT reports written by default to `~/RedAuditReports` (or a custom directory chosen at runtime). Encrypted variants (`.json.enc`) available.

## Requirements

RedAudit is designed for **Debian-based systems with `apt`** (Kali, Debian, Ubuntu…).

### Core (required)

These are mandatory for the tool to run:

- `nmap`
- `python3-nmap`
- `python3-cryptography` (for report encryption)

### Recommended (enrichment)

Optional but strongly recommended if you want the full web / traffic / DNS features:

- `whatweb`
- `nikto`
- `curl`, `wget`, `openssl`
- `tcpdump`, `tshark`
- `whois`, `bind9-dnsutils` (for `dig`)

You can install everything in one go on Kali/Debian/Ubuntu:

```bash
sudo apt update
sudo apt install nmap python3-nmap python3-cryptography whatweb nikto \
  curl wget openssl tcpdump tshark whois bind9-dnsutils
```

The installer and the Python core will check these dependencies at runtime and adapt behaviour (reduced features when something is missing). Even though the installer can help you install some packages via apt, the documented, supported way is to manage them yourself using the commands above.

## Architecture & Flow

At a high level, a run looks like this:

1.	**Initialisation**
	-	Detect local interfaces and networks.
	-	Ask the user to select one or more target ranges.
	-	Pick scan mode (FAST / NORMAL / FULL) and thread count.
	-	Optionally enable web checks and customise the output directory.
2.	**Discovery phase**
	-	Run a fast Nmap discovery (-sn) on each selected range.
	-	Build a list of responsive hosts; this is the input for deeper scans.
3.	**Per-host scanning**
	-	Iterate over live hosts concurrently using a thread pool.
	-	For each host, run the configured Nmap flags for the chosen mode.
	-	Record open ports, service names, versions and whether they look like web services.
4.	**Automatic Deep Scan logic**
	-	If a host returns very few ports or suspicious errors, trigger a dedicated Deep Scan:
	-	Aggressive Nmap scan (-A -sV -Pn -p- --open) plus optional UDP probing.
	-	Optional short PCAP capture around the host with tcpdump (and a summary via tshark if available).
5.	**Enrichment**
	-	For web-looking ports (HTTP/HTTPS, proxies, admin panels, etc.), optionally:
		-	Run whatweb for quick fingerprinting.
		-	Run nikto in FULL mode for basic misconfiguration / vuln pattern checks.
		-	Pull HTTP headers and TLS details via curl, wget and openssl.
	-	For public IPs, optionally:
		-	Perform reverse lookups with dig.
		-	Add a trimmed whois summary.
6.	**Reporting**
	-	Aggregate everything under a single JSON structure plus a textual report.
	-	Write the files to `~/RedAuditReports` by default, or to the directory selected during setup.
	-	On interruption (Ctrl+C), a partial report is still written so previous work is not lost.

## Installation

1.	Clone the repository:

    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.	Make the installer executable and run it as root (or via sudo):

    ```bash
    chmod +x redaudit_install.sh

    # Interactive mode (asks about installing recommended tools when relevant)
    sudo bash redaudit_install.sh

    # Non-interactive: assume “yes” to the optional tools question
    sudo bash redaudit_install.sh -y
    ```

3.	Reload your shell configuration so the redaudit alias is available:

    ```bash
    source ~/.bashrc    # or ~/.zshrc
    ```

## Usage

After installation, you can launch RedAudit from any terminal:

```bash
redaudit
```

The interactive wizard will guide you through:
1.	**Target selection**: choose one of the detected local networks or manually enter a CIDR.
2.	**Scan mode**: FAST, NORMAL or FULL.
3.	**Options**: number of threads, whether to include web vulnerability checks, and where to store reports.
4.	**Legal confirmation**: explicit confirmation that you are authorised to scan the selected targets.
5.  **Encryption**: Option to encrypt the output reports with a password.

Reports will be stored in `~/RedAuditReports` by default. If encryption is enabled, files will have extensions `.json.enc` and `.txt.enc` along with a `.salt` file.

### Decrypting Reports

If you chose to encrypt your reports, use the provided helper script:

```bash
python3 redaudit_decrypt.py ~/RedAuditReports/redaudit_...json.enc
```

You will be prompted for the password used during the audit.

## ⚠️ Legal & Ethical Notice

RedAudit is a security tool intended only for authorised auditing and educational purposes. Scanning systems or networks without explicit permission is illegal and may be punishable under criminal and civil law.

By using this tool you agree that:
-	You will only run it against assets you own or for which you have documented permission.
-	You will not use it for malicious, intrusive or disruptive activities.
-	You, as the operator, are solely responsible for complying with all applicable laws and policies.

The author(s) decline all responsibility for any misuse or damage arising from this software.

## License

This project is distributed under the MIT license. See the LICENSE file for details.