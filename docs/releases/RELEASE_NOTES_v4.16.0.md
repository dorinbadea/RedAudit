# Release Notes - v4.16.0

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.16.0/docs/releases/RELEASE_NOTES_v4.16.0_ES.md)

## Summary

RedAudit v4.16.0 introduces **Nuclei Audit-Focus Mode**, a performance optimization for networks with multi-port hosts. This release also includes a color rendering fix from v4.15.1.

## What's New

### Nuclei Audit-Focus Mode

When hosts with 3+ HTTP ports are detected, RedAudit now automatically limits Nuclei scanning to a maximum of **2 URLs per host**, prioritizing standard ports (80, 443, 8080, 8443).

**Benefits:**

- Reduces scan time significantly (~25min vs 1.5h for complex hosts)
- Focuses on main services where critical CVEs are most likely
- Maintains audit effectiveness while avoiding timeout issues

**User Visibility:**

```
[INFO] Nuclei: 25 -> 8 targets (audit focus)
```

### Color Bug Fix (from v4.15.1)

- `[INFO]` messages now render correctly (cyan) during progress bar display
- Root cause: Rich markup `[INFO]` was being interpreted as an unknown tag
- Fix: Use Rich `Text()` objects for reliable color output

## Upgrade Instructions

```bash
pip install --upgrade redaudit
# or
git pull && pip install -e .
```

## Full Changelog

See [CHANGELOG.md](../../CHANGELOG.md) for complete details.
