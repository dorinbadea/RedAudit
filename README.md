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

## 🚀 Features

*   **Interactive CLI:** User-friendly menus for configuration and execution.
*   **Smart Discovery:** Automatically detects local networks and interfaces.
*   **Multi-Mode Scanning:**
    *   **FAST:** Quick discovery (`-sn`), no port scanning, low noise.
    *   **NORMAL:** Top ports + Service Versioning (`-F -sV`). Balanced speed/coverage.
    *   **FULL:** All ports (`-p-`) + Scripts + Vulnerability checks + Web Analysis.
*   **Automated Deep Scans:** Automatically triggers aggressive scans (`-A -sV -Pn` + UDP) and traffic capture (`tcpdump`) for suspicious or unresponsive hosts.
*   **Web Analysis:** Integrates `whatweb`, `nikto` (recommended) for web service reconnaissance.
*   **Resilience:** Includes a heartbeat monitor and signal handling for long-running scans.
*   **Reporting:** Generates detailed JSON and TXT reports in `~/RedAuditReports` (or custom folder).

## 📦 Dependencies

RedAudit is designed for **apt-based systems** (Kali, Debian, Ubuntu).

### Required (Core)
These are critical for the tool to function:
*   `nmap` (The core scanning engine)
*   `python3-nmap` (Python binding for Nmap)

### Recommended (Enrichment)
These tools are optional but highly recommended for full functionality (Web Analysis, Traffic Capture, DNS):
*   `whatweb`
*   `nikto`
*   `curl`, `wget`, `openssl`
*   `tcpdump`, `tshark`
*   `whois`, `bind9-dnsutils` (for `dig`)

To install everything manually:
```bash
sudo apt update
sudo apt install nmap python3-nmap whatweb nikto curl wget openssl tcpdump tshark whois bind9-dnsutils
```

## 🏗️ Architecture & Flow

1.  **Initialization:** The script detects network interfaces and prompts the user for targets.
2.  **Discovery:** Runs a quick Nmap discovery (`-sn`) on selected ranges.
3.  **Host Scanning:**
    *   Iterates through active hosts using concurrent threads.
    *   Performs the selected scan (FAST/NORMAL/FULL).
    *   **Deep Scan Logic:** If a host yields few results or errors, a specialized Deep Scan is triggered automatically.
4.  **Enrichment:**
    *   **Web:** If HTTP/HTTPS is found, runs WhatWeb and Nikto (if enabled).
    *   **Traffic:** If `tcpdump` is available, captures a small snippet of traffic for analysis.
    *   **DNS/Whois:** Resolves public IPs.
5.  **Reporting:** All data is aggregated into JSON and TXT reports in the output directory.

## 🛠️ Installation

RedAudit v2.3 uses a Bash installer that wraps the Python core.

1.  Clone the repository:
    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.  Run the installer (must be **root**):
    ```bash
    chmod +x redaudit_install.sh
    
    # Interactive installation (asks to install recommended tools)
    sudo bash redaudit_install.sh
    
    # Non-interactive mode (installs recommended tools automatically)
    sudo bash redaudit_install.sh -y
    ```

3.  Reload your shell to use the `redaudit` alias:
    ```bash
    source ~/.bashrc  # Or ~/.zshrc
    ```

## 💻 Usage

Once installed, simply run:

```bash
redaudit
```

Follow the interactive wizard:
1.  **Select Network**: Choose a detected local network or enter a CIDR manually.
2.  **Scan Mode**:
    *   **FAST**: Discovery only.
    *   **NORMAL**: Standard reconnaissance.
    *   **FULL**: Comprehensive audit.
3.  **Options**: Set thread count, enable web vuln scan, choose output directory.
4.  **Authorization**: Confirm you have permission to scan the target.

## ⚠️ Legal & Ethical Warning

**RedAudit is a security auditing tool for authorized use only.**

scanning networks or systems without explicit permission is illegal and punishable by law.
*   **Do not** use this tool on networks you do not own or have written consent to audit.
*   **Do not** use this tool for malicious purposes.

The developers assume no liability for misuse of this software. The user is solely responsible for complying with all applicable local, state, and federal laws.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.