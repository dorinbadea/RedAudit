# RedAudit v4.19.3 - Audit Consistency and SNMP v3 Fixes

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.3/docs/releases/RELEASE_NOTES_v4.19.3.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.3/docs/releases/RELEASE_NOTES_v4.19.3_ES.md)

## Summary

This release strengthens SNMP v3 protocol handling, aligns defaults, and fixes diff/reporting and documentation gaps found during audit review.

## Added

- Offline OUI lookups now support /28 and /36 prefixes from the local manuf database.

## Improved

- SNMP v3 auth/priv protocol names now map to PySNMP objects and respect explicit auth/priv keys.
- CI quality gate now enforces 80% coverage and ShellCheck.

## Fixed

- SNMP topology CVE enrichment no longer relies on an uninitialized NVD API key.
- Differential reports count WhatWeb results using the correct key.
- ConfigurationContext uses the same 300s default Nuclei timeout as the CLI.
- ES timing presets, thread fallback details, and Docker/Security docs now align with policy.
- ShellCheck warnings resolved in installer and Docker helper scripts.

## Testing

- `pytest tests/core/test_auth_snmp.py tests/utils/test_oui_offline.py tests/core/test_diff.py tests/core/test_config_context.py tests/core/test_auditor_run_complete_scan.py -v`

## Upgrade

No breaking changes. Update to v4.19.3.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.3/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.3/docs/INDEX.md)
