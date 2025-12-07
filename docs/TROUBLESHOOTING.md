# RedAudit Troubleshooting Guide

## Common Issues

### 1. `Permission denied` or "Root privileges required"
**Symptom**: The script exits immediately with an error about root.
**Solution**: RedAudit requires low-level network access (nmap, tcpdump).
- Always run with: `sudo redaudit` or `sudo bash redaudit_install.sh`.

### 2. `nmap: command not found`
**Symptom**: The scan fails saying nmap binary is missing.
**Solution**: The installer should have handled this, but you can fix it manually:
```bash
sudo apt update && sudo apt install -y nmap
```

### 3. Decryption Failed
**Symptom**: `redaudit_decrypt.py` says "Mac check failed" or "Invalid token" or "Decryption failed".
**Causes**:
- **Wrong Password**: Ensure you use the exact password set during the scan.
- **Missing Salt**: The `.salt` file MUST be in the same folder as the `.enc` file.
- **File Corruption**: If you transferred the files, ensure binary mode was used.

### 4. Heartbeat Warning ("No output for X seconds")
**Symptom**: You see yellow warnings about "Activity Monitor" during a scan.
**Explanation**: This is normal during heavy Nmap scans (especially `-p-` or `-sV` on slow hosts).
**Action**: Wait. If it exceeds 300s (5 mins) with no output, verify the target host is not blocking you completely (firewall drop).
**Note**: The heartbeat message "Fail" now clarifies that Nmap is still running. Do not abort immediately; deep scans on filtered hosts can take time.

### 5. "Scans seem to hang" / Slow progress
**Symptom**: The tool pauses for 1-2 minutes on a single host.
**Explanation**: RedAudit v2.4 performs **Deep Identity Scans** on complex hosts (combined TCP/UDP/OS fingerprinting).
- **Duration**: These scans can legitimately take **90–150 seconds** per host.
- **Why**: Essential for identifying IoT boxes, firewalls, or filtered servers that hide their OS.
- **Check**: Look for the `[deep]` marker in the CLI output.
**Symptom**: The script refuses to start.
**Solution**: Run the installer again to fix missing python libraries:
```bash
sudo bash redaudit_install.sh -y
```

RedAudit and this troubleshooting guide are part of a GPLv3-licensed project. See [LICENSE](../LICENSE).
