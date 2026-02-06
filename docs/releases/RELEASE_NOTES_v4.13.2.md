# Release Notes v4.13.2

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.13.2/docs/releases/RELEASE_NOTES_v4.13.2_ES.md)

**Release Date:** 2026-01-18

## Summary

This release focuses on **scan results quality improvements**, ensuring that HTML reports display complete technical details and that false positives are correctly filtered.

## Fixed

- **HTML Report References**: Fixed key mismatch (`reference` vs `references`) causing "No additional technical details available" in the Findings section. Nuclei outputs the `reference` key, but the HTML reporter was looking for `references`.

- **CVE-2022-26143 False Positive**: Enhanced FRITZ!OS detection to include the first 2000 characters of the response body, not just the Server header. This prevents Mitel MiCollab vulnerabilities from being incorrectly reported on FRITZ!Box/FRITZ!OS devices.

- **Nuclei Rich Data Extraction**: Now extracts additional fields from Nuclei findings:
  - `impact` - Description of potential attack impact
  - `remediation` - Recommended fix steps
  - `cvss_score` - CVSS score (0.0-10.0)
  - `cvss_metrics` - Full CVSS vector string
  - `extracted_results` - Data extracted by Nuclei from responses

- **Empty Observations Fallback**: Added fallback logic to use the vulnerability description when `parsed_observations` is empty, ensuring findings always display meaningful technical details.

- **Source Attribution**: Changed default source from `unknown` to `redaudit` for auto-generated findings (e.g., HTTP service discoveries). Added WhatWeb detection in the source attribution chain.

## Testing

- All changes include unit tests
- 1919 tests passed, 1 skipped
- Pre-commit hooks pass (black, flake8, bandit, mypy)

## Upgrade

```bash
git pull origin main
pip install -e .
```

Or reinstall:

```bash
sudo bash redaudit_install.sh
```
