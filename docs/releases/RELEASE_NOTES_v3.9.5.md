# RedAudit v3.9.5 Release Notes

[![Versión en Español](https://img.shields.io/badge/ES-Español-blue)](./RELEASE_NOTES_v3.9.5_ES.md)

**Release Date**: 2025-12-28

## Highlights

This release introduces the **IoT Signature Pack** for smart home device detection, plus minor fixes.

---

## New Features

### IoT Signature Pack

Protocol-specific UDP payloads for automatic smart home device detection:

| Protocol | Port(s) | Devices |
|----------|---------|---------|
| WiZ | 38899 | Smart bulbs |
| Yeelight | 1982, 55443 | Smart bulbs |
| Tuya/SmartLife | 6666, 6667 | Various IoT |
| CoAP/Matter | 5683 | Matter-enabled devices |

Devices are automatically tagged with `asset_type: iot` in reports.

### Reverse DNS Hostname Fallback

HTML reports now display IoT device hostnames from reverse DNS lookup when the standard hostname is empty (e.g., `wiz-9df9a6.fritz.box`).

---

## Bug Fixes

### NVD Product Names

- Relaxed regex sanitization in CVE lookup to preserve dots in product names
- `node.js` is no longer incorrectly stripped to `nodejs`
- Fixes CPE generation for many frameworks

---

## Installation

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh
```

---

## Links

- [Full Changelog](../../CHANGELOG.md)
- [Documentation](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
