# RedAudit v4.4.2 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/main/docs/releases/RELEASE_NOTES_v4.4.2_ES.md)

**Release Date**: 2026-01-08

## Summary

This hotfix addresses a critical false positive issue where FRITZ!Box routers were incorrectly flagged as vulnerable to CVE-2022-26143 (Mitel MiCollab Information Disclosure).

## Fixed

### CVE-2022-26143 False Positive on FRITZ!Box Routers

The Nuclei false positive filter was not receiving complete host data, causing the Smart-Check validation to fail for AVM FRITZ!Box devices.

**Root Cause**: The `filter_nuclei_false_positives()` function in `auditor.py` was not passing `host_records` to the filter pipeline, preventing CPE-based and Server header validation from working correctly.

**Changes**:

- Added `fritz!os` to the explicit false positive vendor list for improved header matching
- Removed duplicate `server_header` variable assignment in `check_nuclei_false_positive()`
- New `host_records` parameter in `filter_nuclei_false_positives()` enables full host data flow for accurate validation
- Updated `auditor.py` to pass `host_records=results` to the filter function

## Testing

- Pre-commit: All hooks passed
- Test suite: 1467 passed across Python 3.9, 3.10, 3.11, 3.12

## Upgrade

Standard upgrade via pip or the install script:

```bash
pip install --upgrade redaudit
# or
bash redaudit_install.sh
```

## Full Changelog

See [CHANGELOG.md](https://github.com/dorinbadea/RedAudit/blob/v4.4.2/CHANGELOG.md) for the complete list of changes.
