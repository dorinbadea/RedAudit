[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.7.2/docs/releases/RELEASE_NOTES_v4.7.2_ES.md)

# RedAudit v4.7.2

**Release Date:** 2026-01-15

## Summary

This hotfix release addresses critical issues discovered during v4.7.1 scan analysis: Nuclei batch timeouts and unnecessary NVD API retries.

## Fixed

### Nuclei Timeout (Critical)

- **Problem**: Nuclei batch scans were timing out at 100% rate (5/5 batches failed)
- **Root Cause**: `command_runner.py` default timeout was 60 seconds, too short for Nuclei
- **Fix**: Increased timeout to 600 seconds (10 minutes) for Nuclei commands

### NVD API 404 Handling

- **Problem**: 404 responses (CPE not found) were retried 3 times unnecessarily
- **Root Cause**: 404 was not in the non-retryable error list
- **Fix**: Skip retries immediately on 404 responses (CPE not in NVD is not retryable)

## Verification

- Pre-commit: All hooks passed
- Tests: 40/40 targeted tests passed
- Session log analysis confirmed timeout was 60s (now 600s)

## Upgrade

```bash
git pull
sudo redaudit --version  # Should show 4.7.2
```

## Related Files

- [command_runner.py](../../redaudit/core/command_runner.py) - Nuclei timeout fix
- [nvd.py](../../redaudit/core/nvd.py) - 404 skip fix
- [CHANGELOG.md](../../CHANGELOG.md) - Full changelog
