# RedAudit Installation Manual v2.3.1

**Role:** Pentester / Senior Programmer

## 1. Prerequisites

**Target System:**
*   Kali Linux (or similar Debian-based distro)
*   User with `sudo` privileges
*   Internet connection for package installation

**Packages used:**
The installer can automatically install these for you if requested (interactive mode or `-y` flag).

*   **Core (Required):** `nmap`, `python3-nmap`, `python3-cryptography`
*   **Recommended (Optional):** `whatweb`, `nikto`, `curl`, `wget`, `openssl`, `tcpdump`, `tshark`, `whois`, `bind9-dnsutils`

To install manually:
```bash
sudo apt update
sudo apt install -y nmap python3-nmap whatweb nikto curl wget openssl tcpdump tshark whois bind9-dnsutils
```

> **Note:** `nmap` and `python3-nmap` are critical. The others are recommended for full functionality (Web scans, traffic capture, DNS enrichment).

*   **Automatic Deep Scan:** The tool automatically detects "quiet" or suspicious hosts and launches a deep scan (`-A -p- -sV`) including packet capture to identify firewalls or hidden services.

---

## 2. Prepare Working Directory

We use a standard directory for tools:

```bash
mkdir -p ~/security_tools
cd ~/security_tools
```

---

## 3. Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.  Run the installer:
    ```bash
    chmod +x redaudit_install.sh
    sudo ./redaudit_install.sh
    
    # Or for non-interactive installation:
    # sudo ./redaudit_install.sh -y
    ```

The installer will:
1.  Offer to install recommended network utilities.
2.  Install RedAudit to `/usr/local/bin/redaudit`.
3.  Set up the necessary shell alias.

---

## 4. Activate the Alias

After installation:

```bash
source ~/.bashrc
```

From now on, in any terminal as your normal user:

```bash
redaudit
```

---
## 5. 🔒 Security Features (NEW in v2.3)

RedAudit v2.3 introduces enterprise-grade security hardening:

- **Input Sanitization**: All user inputs and command outputs are validated.
- **Encrypted Reports**: Optional **AES-128 (Fernet)** encryption with PBKDF2-HMAC-SHA256 (480k iterations).
- **Thread Safety**: All concurrent operations use proper locking mechanisms.
- **Rate Limiting**: Configurable delays to avoid detection and network saturation.
- **Audit Logging**: Comprehensive logging with automatic rotation (10MB, 5 backups).

[→ Full Security Documentation](SECURITY.md)

To decrypt reports:
```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```

---

## 6. Quick Verification

Useful commands to check everything is in place:

```bash
# Where is the binary?
which redaudit
# → should point to /usr/local/bin/redaudit (via alias)

# Check binary permissions
ls -l /usr/local/bin/redaudit

# Confirm alias
grep "alias redaudit" ~/.bashrc
```

---

## 7. Updating RedAudit

To update the code (e.g., from 2.3 to 2.4):
1.  Edit the installer `redaudit_install.sh` with the new code.
2.  Run it again:
    ```bash
    sudo ./redaudit_install.sh
    source ~/.bashrc  # Or ~/.zshrc
    ```

The binary `/usr/local/bin/redaudit` will be overwritten with the new version.

---

## 8. Uninstallation

To remove the binary and alias:

```bash
sudo rm -f /usr/local/bin/redaudit
sed -i '/alias redaudit=/d' ~/.bashrc  # Or ~/.zshrc
source ~/.bashrc  # Or ~/.zshrc
```
