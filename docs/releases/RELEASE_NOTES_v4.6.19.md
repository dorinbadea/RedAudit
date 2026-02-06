[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.19/docs/releases/RELEASE_NOTES_v4.6.19_ES.md)

# RedAudit v4.6.19 - Prioritization & Backdoor Detection

## Summary

- Adds **Finding Prioritization** and **Confidence Scoring** for better report quality.
- Introduces **Classic Vulnerability Detection** for known backdoors.
- Improves **Reporting Titles** and **Wizard UI** (spray count display).

## Added

- **Finding Prioritization**: New `priority_score` (0-100) and `confirmed_exploitable` fields to better rank vulnerabilities. Weighted system prioritizes CVEs and verified findings.
- **Classic Vulnerability Detection**: Automatic detection of known backdoored services (vsftpd 2.3.4, UnrealIRCd 3.2.8.1, Samba, distcc, etc.) from banner analysis.
- **Report Quality**: New `confidence_score` (0.0-1.0) for findings based on verification signals (e.g., CVE matching, Nuclei confirmation).
- **Improved Titles**: Better title generation, detecting specific vulnerabilities (BEAST, POODLE) and providing clearer fallback titles (e.g., "HTTP Service Finding").
- **JSONL Export**: Added quality fields (`confidence_score`, `priority_score`, `confirmed_exploitable`) to JSONL output for SIEM ingestion.

## Improved

- **Wizard UI**: Credential summary now displays the count of spray list entries (e.g., `(+5 spray)`).
- **Severity Mapping**: Refined mapping for generic scanner findings to reduce noise (e.g., lowering severity for version disclosures).

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
