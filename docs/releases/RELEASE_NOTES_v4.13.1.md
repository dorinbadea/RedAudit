[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.13.1/docs/releases/RELEASE_NOTES_v4.13.1_ES.md)

# Release Notes v4.13.1 (Enhancement Release)

**Release Date:** 2026-01-18

This release focuses on significantly enhancing the HTML reporting capabilities and refining device identification logic, providing auditors with richer, more actionable data.

## Key Changes

### HTML Report Enhancements

- **Rich Technical Details:** The findings table now features an expandable "Technical Details" section. This includes:
  - **Description:** A detailed explanation of the vulnerability or open port.
  - **References:** Links to relevant CVEs or documentation.
  - **Evidence:** Raw output from the scanner (e.g., XML/JSON payloads, Nmap script output) helping to validate the finding manually.
- **Interactive Remediation Playbooks:** Playbooks are now presented as interactive cards containing:
  - Step-by-step remediation instructions.
  - Precise command blocks for verifying and fixing issues.
  - External reference links for deep dives.

### Device Identification Refinements

- **Improved Deep Scan Analysis:** The identification logic now parses Nmap script outputs (specifically `http-title`) to accurately classify devices that were previously generic.
- **FRITZ!Repeater Support:** Specific signatures for AVM FRITZ!Repeaters have been added, ensuring they are correctly identified with the proper Vendor (AVM), Model (FRITZ!Repeater), and Device Type (IoT/Network Device).

## Update Instructions

To update to the latest version, pull the changes from the repository:

```bash
git pull origin main
```

No new dependencies are required for this update.
