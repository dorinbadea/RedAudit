# RedAudit v3.9.3 Release Notes

[![Versión en Español](https://img.shields.io/badge/Español-blue)](./RELEASE_NOTES_v3.9.3_ES.md)

**Release Date**: 2025-12-27

## Highlights

This hotfix improves **report fidelity** and **finding titles**.

---

## 🐛 Bug Fixes

### Consolidated Findings Keep TestSSL Data

- Preserves `testssl_analysis` and related observations when multiple findings are merged.
- Prevents TLS warnings from being lost in HTML/JSON outputs.

### HTML Titles for Tool-Only Findings

- If a finding lacks `descriptive_title`, HTML now derives a meaningful title (e.g., `Web Service Finding on Port 443`) instead of a raw URL.

---

## 📦 Installation

```bash
pip install --upgrade redaudit
# or
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.3
```

---

## 🔗 Links

- [Full Changelog](../../CHANGELOG.md)
- [Documentation](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
