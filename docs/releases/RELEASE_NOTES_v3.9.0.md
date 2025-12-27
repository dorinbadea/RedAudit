# RedAudit v3.9.0 Release Notes

[![Versión en Español](https://img.shields.io/badge/🇪🇸-Español-blue)](./RELEASE_NOTES_v3.9.0_ES.md)

**Release Date**: 2025-12-27

## Highlights

This release focuses on **wizard usability**, **scan accuracy**, and **false positive detection**.

---

## ✨ New Features

### Wizard Navigation

- Added **"< Go Back"** option when selecting timing mode
- Users can now return to the profile selector without restarting

### Real Timing Differences

Nmap timing templates are now correctly applied based on selected mode:

| Mode | Template | Threads | Delay |
|------|----------|---------|-------|
| Stealth | `-T1` | 4 | 300ms |
| Normal | `-T4` | 16 | 0ms |
| Aggressive | `-T5` | 32 | 0ms |

### UDP Port Coverage Increase

- **Exhaustive profile** now scans top **500 UDP ports** (was 200)
- Improves coverage from ~95% to ~98%

### Nuclei False Positive Detection

- Findings now include `suspected_false_positive` field
- Detection based on Server header vs expected vendor
- Example: CVE-2022-26143 (Mitel) flagged as FP on FRITZ!Box routers

### Session Log Filtering

- Improved noise reduction by filtering spinner/progress updates
- Cleaner session logs for review

---

## 🐛 Bug Fixes

### nmap_timing Not Applied

- **Fixed**: `get_nmap_arguments()` now receives config object
- Stealth/Normal/Aggressive modes correctly use T1/T4/T5

### Playbooks Not in HTML Report

- **Fixed**: Playbook generation now occurs before HTML rendering
- Playbook data properly injected into report template

---

## ⚡ Changes

### `save_playbooks()` Return Type

- Now returns `tuple[int, list]` instead of `int`
- Returns `(count, playbook_data)` for HTML report integration

---

## 🗑️ Removed

### `prescan.py` Module

- Removed as dead code
- Functionality superseded by `hyperscan.py` which offers:
  - Parallel TCP/UDP sweeps
  - ARP aggressive scanning
  - IoT device discovery (SSDP, mDNS, WiZ)

---

## 📦 Installation

```bash
pip install --upgrade redaudit
# or
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.0
```

---

## 🔗 Links

- [Full Changelog](../../CHANGELOG.md)
- [Documentation](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
