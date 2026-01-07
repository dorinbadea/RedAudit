# RedAudit v4.3.0 Release Notes

[![Versión en Español](https://img.shields.io/badge/ES-Español-blue)](./RELEASE_NOTES_v4.3.0_ES.md)

**Release Date**: 2026-01-07

## Highlights

This release introduces **Enterprise Risk Scoring V2** for accurate configuration-based risk assessment and significant **Docker Scanning Optimizations** (H2) for deep container analysis, transforming RedAudit into a true audit-grade decision engine.

---

## New Features

### Enterprise Risk Scoring V2

The risk calculation engine has been overhauled to treat **Configuration Findings** (from Nikto, Nuclei, Zap) as primary risk drivers alongside CVEs.

- **Previous behavior**: Risk score was heavily weighted by CVSS/CVEs. A host with zero CVEs but an exposed admin panel (Critical finding) often received a low risk score.
- **New behavior**: Findings with `high` or `critical` severity directly impact the Density Bonus and Exposure Multiplier. A host with critical misconfigurations now correctly scores in the 80-100 (High/Critical) range, ensuring accurate prioritization.

### Docker & Deep Scan Optimization (H2)

Optimized the "Deep Scan" phase to better handle Docker containers and ephemeral services often found in modern stacks:

- **Nikto Unchained**: Removed default tuning constraints (`-Tuning x`) and increased timeout to 5 minutes (`300s`). This ensures Nikto completes full checks against complex web apps.
- **Nuclei Expanded**: The scanner now processes findings with `severity="low"`, capturing critical information leaks (e.g., exposed logs, status pages, .git config) that were previously filtered out.

### HyperScan SYN Mode

New optional SYN-based port scanning mode for privileged users:

- **Speed**: ~10x faster than connect scans.
- **Usage**: Automatically selected when running as root with scapy installed, or force with `--hyperscan-mode syn`.

---

## Improvements

### Noise Reduction

Cleaned up `arp-scan` and `scapy` error output (redundant "Mac address to reach destination not found" warnings) for a professional, noise-free terminal experience.

### Identity Visualization

HTML reports now color-code the `identity_score` to clearly show which hosts are fully identified vs. those needing manual review.

### PCAP Management

Automated cleanup and organization of packet capture artifacts.

---

## Bug Fixes

### Smart-Check Validation

Enhanced false positive filtering using CPE cross-validation.

### Risk Logic Regression

Fixed a critical regression where non-CVE findings resulted in a 0 risk score.

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
