# RedAudit v3.9.1a Release Notes

[![Versión en Español](https://img.shields.io/badge/Español-blue)](./RELEASE_NOTES_v3.9.1a_ES.md)

**Release Date**: 2025-12-27

## Highlights

This hotfix focuses on **reporting fidelity** and **dashboard metadata**.

---

## Bug Fixes

### Spanish HTML Finding Titles

- Fixed regex matching so common finding titles are properly localized in `report_es.html`.

### summary.json Metadata

- Added `scan_mode_cli`, compact `options`, and `severity_counts` alias for dashboards and integrations.

---

## Installation

```bash
pip install --upgrade redaudit
# or
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.1a
```

---

## Links

- [Full Changelog](../../CHANGELOG.md)
- [Documentation](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
