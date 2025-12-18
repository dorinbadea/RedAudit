# RedAudit Troubleshooting Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](TROUBLESHOOTING.es.md)

**Audience:** All Users
**Scope:** Common errors, exit codes, dependency issues.
**Source of Truth:** `redaudit/utils/constants.py` (Exit Codes)

---

## Error Codes and Resolution

### 1. `Permission denied` / "Root privileges required"

**Symptom**: The script exits immediately with a privilege error.
**Cause**: The application requires raw socket access for `nmap` (SYN scans/OS detection) and `tcpdump`.
**Resolution**:

- Always execute with `sudo`.
- Verify user matches sudoers policy.

### 2. `nmap: command not found`

**Symptom**: Scanning engine fails to initialize.
**Cause**: The `nmap` binary is not in the system `$PATH`.
**Resolution**:

```bash
sudo apt update && sudo apt install nmap
```

### 3. `ModuleNotFoundError: No module named 'cryptography'`

**Symptom**: Script fails during imports.
**Cause**: Python dependencies are missing or installed in a different environment.
**Resolution**:

```bash
# Run the installer to install all dependencies
sudo bash redaudit_install.sh

# Or install Python packages manually
sudo apt install python3-nmap python3-cryptography python3-netifaces
```

### 4. `Heartbeat warnings in logs`

**Symptom**: You see "Activity Monitor" warnings in the console output.
**Cause**: The main thread may be blocked by a subprocess hanging (e.g., a stalled `nikto` scan). RedAudit monitors scan activity and prints warnings when no output is detected for extended periods.
**Resolution**:

- Check system load: `top`
- Inspect logs: `tail -f ~/.redaudit/logs/redaudit_*.log`
- Terminate process if unresponsive > 5 minutes.

### 5. `Decryption failed: Invalid Token`

**Symptom**: `redaudit_decrypt.py` rejects the password.
**Cause**: Incorrect password derived key does not match the file signature.
**Resolution**:

- Ensure correct case sensitivity.
- Verify file integrity (check file size > 0). Do not abort immediately; deep scans on filtered hosts can take time.

### 6. "Scans seem to hang" / Slow progress

**Symptom**: The tool pauses for 1-2 minutes on a single host.
**Explanation**: RedAudit can perform **Deep Scans / identity refinement** on complex hosts (combined TCP/UDP/OS fingerprinting).

- **Duration**: These scans can legitimately take **90–150 seconds** per host.
- **Why**: Essential for identifying IoT boxes, firewalls, or filtered servers that hide their OS.
- **Check**: Look for the `[deep]` marker in the CLI output.

### 6b. System sleep / screen blanking during long scans (v3.5+)

**Symptom**: Your VM/laptop goes to sleep or the screen blanks while RedAudit is running.
**Explanation**: RedAudit attempts a **best-effort** sleep/display inhibition while a scan is running to avoid long scans being paused.
**Notes**:

- This depends on what tools are available on the system (e.g., `systemd-inhibit` on Linux, `xset` for X11/DPMS).
- You can disable it with `--no-prevent-sleep`.

### 7. "Cryptography not available" warning

**Symptom**: You see a warning about `python3-cryptography` not being available.
**Explanation**: Encryption feature requires `python3-cryptography`. The tool gracefully degrades if it's missing.
**Solution**:

```bash
sudo apt install python3-cryptography
```

**Note**: If cryptography is unavailable, encryption options are automatically disabled. No password prompts will appear.

### 8. Non-interactive mode errors

**Symptom**: `--target` argument not working or "Error: --target is required".
**Solution**:

- Ensure you provide `--target` with a valid CIDR (e.g., `--target 192.168.1.0/24`)
- Multiple targets: `--target "192.168.1.0/24,10.0.0.0/24"`
- Check CIDR format is correct
- See `redaudit --help` for all available options

**Symptom**: The script refuses to start.
**Solution**: Run the installer again to fix missing python libraries:

```bash
sudo bash redaudit_install.sh -y
```

### 8b. Version/banner not refreshed after update

**Symptom**: You updated RedAudit but the banner still shows the old version.
**Cause**: Your shell may be caching the executable path (or you're still in the same terminal session).
**Resolution**:

- Restart the terminal (recommended).
- If you must stay in the same shell session, run `hash -r` (zsh/bash) to clear the command cache.
- Verify which binary is being executed: `command -v redaudit`.

### 9. IPv6 scanning not working (v3.0)

**Symptom**: IPv6 targets return no results or errors.
**Cause**: IPv6 not enabled on system or Nmap built without IPv6 support.
**Resolution**:

- Verify IPv6 is enabled: `ip -6 addr show`
- Check Nmap supports IPv6: `nmap -6 ::1`
- Use `--ipv6` flag for IPv6-only mode

### 10. NVD API rate limit errors (v3.0)

**Symptom**: "Rate limit exceeded" or slow CVE lookups.
**Cause**: Using NVD API without a key (limited to 5 requests/30 seconds).
**Resolution**:

- Get a free NVD API key from: <https://nvd.nist.gov/developers/request-an-api-key>
- Use `--nvd-key YOUR_KEY` for faster rate limits (50 requests/30 seconds)
- RedAudit caches results for 7 days to minimize API calls

### 11. Proxy connection failed (v3.0)

**Symptom**: "Proxy connection failed" when using `--proxy`.
**Cause**: Proxy not reachable or `proxychains` not installed.
**Resolution**:

```bash
# Install proxychains
sudo apt install proxychains4

# Test proxy manually
curl --socks5 pivot-host:1080 http://example.com

# Verify proxy format
# Correct: --proxy socks5://host:port
```

### 12. Net Discovery: Missing tools / "tool_missing" (v3.2)

**Symptom**: Warnings during Network Discovery about missing tools (`nbtscan`, `netdiscover`), or skipped Red Team blocks.
**Cause**: Enhanced discovery relies on external system tools not included in standard nmap.
**Resolution**:

```bash
sudo apt update && sudo apt install nbtscan netdiscover fping avahi-utils snmp ldap-utils samba-common-bin
```

### 13. Net Discovery: "Permission denied" / L2 failures (v3.2)

**Symptom**: `scapy`, `bettercap`, or `netdiscover` modules fail or show no results.
**Cause**: L2 spoofing, sniffing, and ARP injection require root privileges and specific packet injection capabilities (`CAP_NET_RAW` is often insufficient for injection).
**Resolution**:

- Always run with `sudo`.
- Ensure no MAC filtering is blocking your interface.
- Select the correct interface explicitly: `--net-discovery-interface eth0`.

### 14. HTML Report Generation Failed (v3.3)

**Symptom**: "Error generating HTML report" or report file is 0 bytes.
**Cause**:

- Missing `jinja2` template engine (rare, installed by default).
- Permission denied when writing to output directory.
**Resolution**:

```bash
# Verify installation
python3 -c "import jinja2; print('ok')"

# Check permissions
touch ~/Documents/RedAuditReports/test_write
```

### 15. Webhook Alert Failed (v3.3)

**Symptom**: "Failed to send webhook" warning in logs.
**Cause**:

- Invalid URL format.
- Destination server down or unreachable (404/500).
- Network blocking outbound connections.
**Resolution**:
- Test URL with curl: `curl -X POST -d '{"test":true}' YOUR_WEBHOOK_URL`
- Verify URL starts with `http://` or `https://`.

### 16. Playbooks not generated / missing `playbooks/` folder (v3.4)

**Symptom**: No playbooks appear in `<output_dir>/playbooks/`, or the count is 0.
**Common causes**:

- **Encryption enabled**: plaintext artifacts (HTML/JSONL/playbooks/manifests) are skipped when `--encrypt` is used.
- **No matched categories**: playbooks are generated only when findings match the built-in categories (TLS, headers, CVE, web, ports).
- **Expected deduplication**: only one playbook per host + category is generated (you may have many findings but few playbooks).
- **Permissions**: the output directory is not writable by the current user.

**Resolution**:

- Run without encryption if you need playbooks: `sudo redaudit ... --mode normal --yes`
- Confirm output directory and permissions: `ls -la <output_dir>`

RedAudit and this troubleshooting guide are part of a GPLv3-licensed project. See [LICENSE](../../LICENSE).
