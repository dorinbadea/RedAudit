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

### 5. "Missing critical dependencies"
**Symptom**: The script refuses to start.
**Solution**: Run the installer again to fix missing python libraries:
```bash
sudo bash redaudit_install.sh -y
```
