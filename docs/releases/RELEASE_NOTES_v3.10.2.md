# RedAudit v3.10.2 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/main/docs/releases/RELEASE_NOTES_v3.10.2_ES.md)

**Release Date:** 2026-01-04

## Summary

VPN Vendor Detection & Documentation Accuracy

## Highlights

### VPN/Firewall Vendor Detection

New heuristic in `entity_resolver.py` classifies devices from 12 known VPN/Firewall vendors:

- Palo Alto, Fortinet, Cisco, Juniper, SonicWall
- Check Point, WatchGuard, Sophos, Pulse Secure
- F5 Networks, Barracuda

**Logic:**

- Vendor + VPN ports (500/4500/1194/51820) → `"vpn"`
- Vendor + Web ports (80/443/8443) → `"firewall"`

### Documentation Cleanup

- **Removed zombie prescan flags** (`--prescan`, `--prescan-ports`, `--prescan-timeout`) - superseded by HyperScan since v3.0
- **Documented hidden CLI flags** in READMEs: `--max-hosts`, `--no-deep-scan`, `--no-txt-report`, `--nvd-key`
- **Fixed "Subnet Leak" wording** → "Network Leak Hints" to reflect DHCP-based detection
- **Fixed VPN description** → "vendor OUI matching" instead of "MAC heuristics"

## Upgrade

```bash
sudo bash redaudit_install.sh
```

---

[Full Changelog](../../CHANGELOG.md)
