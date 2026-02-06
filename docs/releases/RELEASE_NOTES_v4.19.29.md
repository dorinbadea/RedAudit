[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.29/docs/releases/RELEASE_NOTES_v4.19.29_ES.md)

# RedAudit v4.19.29 - Playbook Remediation Persistence

## Summary
- Remediation playbooks now persist in JSON reports and are reconstructed for HTML regeneration when missing.

## Added
- None.

## Improved
- HTML regeneration now reconstructs remediation playbooks if they are absent from the JSON report.

## Fixed
- The Playbook Remediation section now renders consistently in regenerated HTML reports.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- No action required.
