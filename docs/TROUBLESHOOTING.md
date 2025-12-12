# RedAudit Troubleshooting Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](TROUBLESHOOTING_ES.md)

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
pip3 install -r requirements.txt
# Or run the verified installer
sudo bash redaudit_install.sh
```

### 4. `Heartbeat file stuck`

**Symptom**: The timestamp in `~/.redaudit/logs/heartbeat` is older than 30 seconds.
**Cause**: The main thread may be blocked by a subprocess hanging (e.g., a stalled `nikto` scan).
**Resolution**:

- Check system load: `top`
- Inspect logs: `tail -f ~/.redaudit/logs/redaudit.log`
- Terminate process if unresponsive > 5 minutes.

### 5. `Decryption failed: Invalid Token`

**Symptom**: `redaudit_decrypt.py` rejects the password.
**Cause**: Incorrect password derived key does not match the file signature.
**Resolution**:

- Ensure correct case sensitivity.
- Verify file integrity (check file size > 0). Do not abort immediately; deep scans on filtered hosts can take time.

### 6. "Scans seem to hang" / Slow progress

**Symptom**: The tool pauses for 1-2 minutes on a single host.
**Explanation**: RedAudit v2.8.0 performs **Deep Identity Scans** on complex hosts (combined TCP/UDP/OS fingerprinting).

- **Duration**: These scans can legitimately take **90–150 seconds** per host.
- **Why**: Essential for identifying IoT boxes, firewalls, or filtered servers that hide their OS.
- **Check**: Look for the `[deep]` marker in the CLI output.

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

RedAudit and this troubleshooting guide are part of a GPLv3-licensed project. See [LICENSE](../LICENSE).
