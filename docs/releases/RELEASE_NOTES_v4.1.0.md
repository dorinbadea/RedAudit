# RedAudit v4.1.0 Release Notes

**Release Date:** 2026-01-06

---

## 🚀 Performance Optimizations

### Sequential HyperScan-First Pre-scan

The v4.1 architecture introduces a sequential pre-scan phase that runs **before** parallel nmap fingerprinting:

1. **Problem Solved:** File descriptor exhaustion when running 65,535-port scans concurrently on multiple hosts
2. **Solution:** Run HyperScan-First sequentially with `batch_size=2000` (up from 100 in concurrent mode)
3. **Result:** Faster overall scanning with no file descriptor errors

```
┌─────────────────┐   ┌──────────────────┐   ┌─────────────────┐
│ Net Discovery   │──▶│ HyperScan-First  │──▶│ Parallel nmap   │
│ (ARP, mDNS)     │   │ (Sequential)     │   │ Fingerprinting  │
└─────────────────┘   └──────────────────┘   └─────────────────┘
```

### Masscan Port Reuse

When masscan has already discovered ports (e.g., via `--masscan` flag), HyperScan-First reuses those results instead of re-scanning.

---

## ✨ New Features

### Online OUI Vendor Lookup

When local tools (arp-scan, netdiscover) return "Unknown" vendor, RedAudit now falls back to the **macvendors.com API** for MAC vendor enrichment.

Before v4.1:

```json
{"mac": "d4:24:dd:07:7c:c5", "vendor": "(Unknown)"}
```

After v4.1:

```json
{"mac": "d4:24:dd:07:7c:c5", "vendor": "AVM GmbH"}
```

### Basic sqlmap Integration

RedAudit now integrates **sqlmap** for automatic SQL injection detection on web targets:

- Runs in batch mode (non-interactive)
- Crawls forms and parameters automatically
- Uses smart scan for quick detection
- Automatically detects sqlmap installation

**Installation:** sqlmap is now included in `redaudit_install.sh`.

---

## 🔧 Improvements

### Nmap Command Optimization

Removed redundant flags when `-A` is used:

- Before: `nmap -A -sV -sC ...`
- After: `nmap -A ...`

The `-A` flag already includes `-sV` (version detection) and `-sC` (script scanning).

### Parallel Vulnerability Tools

Increased parallel workers from 3 to 4 to accommodate sqlmap alongside testssl, whatweb, and nikto.

---

## 🐛 Bug Fixes

### Infinite Recursion Fix

Fixed a critical bug where `hasattr(self, "_hyperscan_prescan_ports")` caused infinite recursion due to custom `__getattr__` in Auditor classes.

**Solution:** Changed to `"_hyperscan_prescan_ports" in self.__dict__`.

---

## 📚 Documentation

- Updated ROADMAP.es.md with v4.2 planned features
- Added Web App Vuln Scan (sqlmap/ZAP) to roadmap

---

## 🔮 Coming in v4.2

- Full sqlmap/ZAP integration for comprehensive web app testing
- Deep Scan separation from `scan_host_ports()`
- Red Team → Agentless data passing
- Wizard UX improvements
- Session log enhancement

---

## Upgrade Instructions

```bash
git pull origin main
sudo ./redaudit_install.sh
```

The installer will now automatically install sqlmap.

---

## Test Metrics (MSI Vector i9-14th gen, 32GB RAM)

| Phase | Duration | Result |
|:------|:---------|:-------|
| Net Discovery | 191s | 48 hosts |
| HyperScan-First | 331s | 19 ports |
| nmap Fingerprint | ~16 min | 25 hosts |
| Vuln Scan | ~17 min | 16 web hosts |
| **Total** | ~1h01m | 25 assets, 14 findings |
