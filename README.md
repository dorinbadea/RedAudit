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

**RedAudit** is an interactive, automated network auditing tool designed for Kali Linux. It streamlines the reconnaissance process by combining network discovery, port scanning, and vulnerability assessment into a single, easy-to-use CLI workflow.

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
    *   **Fast:** Quick discovery (ping sweep).
    *   **Normal:** Top ports + Service Versioning.
    *   **Full:** All ports + Scripts + Vulnerability checks.
*   **Automated Deep Scans:** Automatically triggers aggressive scans and traffic capture (`tcpdump`) for suspicious or unresponsive hosts.
*   **Web Analysis:** Integrates `whatweb`, `nikto`, and `openssl` for web service reconnaissance.
*   **Resilience:** Includes a heartbeat monitor and signal handling for long-running scans.
*   **Reporting:** Generates detailed JSON and TXT reports.

## 📋 Requirements

*   **OS:** Kali Linux (or Debian-based distros).
*   **Privileges:** Root/Sudo access required.
*   **Dependencies:** `nmap`, `python3-nmap`, `curl`, `wget`, `tcpdump`, `tshark`, `whois`, `bind9-dnsutils`, `whatweb`, `nikto`.

## 🛠️ Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.  Run the installer:
    ```bash
    chmod +x redaudit_install.sh
    sudo ./redaudit_install.sh
    ```

3.  Reload your shell:
    ```bash
    source ~/.bashrc  # Or ~/.zshrc if using ZSH
    ```

## 💻 Usage

Simply run the command from any terminal:

```bash
redaudit
```

Follow the interactive prompts to select your target network, scan intensity, and other options.

## ⚠️ Disclaimer

**RedAudit is for educational and authorized testing purposes only.**
Usage of this tool for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.