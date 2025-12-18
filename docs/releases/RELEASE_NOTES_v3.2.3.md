# RedAudit v3.2.3 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.2.3_ES.md)

**Release Date**: December 16, 2025
**Type**: Feature Release (HyperScan + Stealth Mode)
**Previous Version**: v3.2.2

---

## Overview

Version 3.2.3 introduces two major capabilities: **HyperScan** for ultra-fast parallel network discovery, and **Stealth Mode** for enterprise networks with IDS/rate limiters. Additionally, progress spinners now provide visual feedback during long-running discovery phases.

---

## What's New in v3.2.3

### 1. HyperScan Module

New `redaudit/core/hyperscan.py` (~1000 lines) provides ultra-fast parallel discovery using Python asyncio:

| Component | Description |
|-----------|-------------|
| TCP Batch | 3000 concurrent connections with semaphore control |
| UDP Sweep | 45+ ports with protocol-specific payloads |
| IoT Broadcast | WiZ bulbs, SSDP, Chromecast, Yeelight, LIFX |
| Aggressive ARP | 3-retry sweep with arp-scan + arping fallback |
| Backdoor Detection | Flags suspicious ports (31337, 4444, 6666, etc.) |
| Deep Scan | Full 65535-port scan on suspicious hosts |

### 2. Stealth Mode

New `--stealth` CLI flag for enterprise networks with strict security policies:

```bash
sudo python3 -m redaudit --target 10.0.0.0/24 --stealth --yes
```

| Parameter | Normal | Stealth |
|-----------|--------|---------|
| Timing | `-T4` | `-T1` (paranoid) |
| Threads | 6-14 | 1 (sequential) |
| Delay | 0s | 5s+ minimum |

### 3. Progress Spinners

Animated spinners now show elapsed time during:

- Topology discovery phase
- Net discovery phase (DHCP/NetBIOS/mDNS/UPNP)

This replaces the previous \"no output\" warnings during long-running operations.

### 4. Bug Fixes

- **Network Deduplication**: "Scan ALL" now correctly removes duplicate CIDRs when the same network is detected on multiple interfaces
- **Defaults Display**: Interactive configuration review shows 10 fields (was 6)
- **Config Persistence**: `DEFAULT_CONFIG` expanded to 12 fields

---

## Usage Examples

```bash
# Standard scan with HyperScan (auto-enabled in full mode)
sudo python3 -m redaudit --mode full --yes

# Enterprise stealth scan
sudo python3 -m redaudit --target 10.0.0.0/24 --stealth --mode full --yes

# Check version
python3 -m redaudit --version
```

---

## Upgrade Instructions

```bash
# Update from any previous version
cd ~/RedAudit
git pull origin main

# Or reinstall
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/v3.2.3/redaudit_install.sh | sudo bash
```

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
- **Usage Guide**: [docs/en/USAGE.en.md](../USAGE.en.md) / [docs/es/USAGE.en.md](../USAGE.en.md)
- **Manual**: [docs/en/MANUAL.en.md](../MANUAL.en.md) / [docs/es/MANUAL.en.md](../MANUAL.en.md)
