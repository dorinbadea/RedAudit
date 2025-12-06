# RedAudit Installation Manual v2.3

**Role:** Pentester / Senior Programmer

## 1. Prerequisites

**Target System:**
*   Kali Linux (or similar Debian-based distro)
*   User with `sudo` privileges
*   Internet connection for package installation

**Packages used** (installed automatically by the script, but listed here for reference):

```bash
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-nmap \
  curl wget openssl nmap tcpdump tshark whois bind9-dnsutils \
  whatweb nikto
```

> **Note:** `whatweb`, `nikto`, and `nmap` are the core requirements for RedAudit. The others are utilities that the script prepares for future modules (tcpdump/tshark/WHOIS/DNS/etc).

---

## 2. Prepare Working Directory

We use a standard directory for tools:

```bash
mkdir -p ~/security_tools
cd ~/security_tools
```

---

## 3. Create the RedAudit Installer

In that directory, create the installer (a bash script that generates/updates `/usr/local/bin/redaudit`):

```bash
nano redaudit_install.sh
```

Paste the entire script found at the end of this document (or in the repository). Save and close.

Then:

```bash
chmod +x redaudit_install.sh
```

---

## 4. Run Installation / Update

Launch the installer as root (via sudo):

```bash
sudo ./redaudit_install.sh
```

The installer will:
1.  Offer to install the recommended network utilities pack.
2.  Create or replace `/usr/local/bin/redaudit` with the Python v2.3 version.
3.  Adjust permissions (755, root owner).
4.  Add the alias to your `~/.bashrc` or `~/.zshrc` (depending on your shell).

---

## 5. Activate the Alias

After installation:

```bash
source ~/.bashrc
```

From now on, in any terminal as your normal user:

```bash
redaudit
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
