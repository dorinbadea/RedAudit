# RedAudit v3.9.2 Release Notes

[![Versión en Español](https://img.shields.io/badge/Español-blue)](./RELEASE_NOTES_v3.9.2_ES.md)

**Release Date**: 2025-12-27

## Highlights

This hotfix ensures **accurate version display** after script-based updates.

---

## 🐛 Bug Fixes

### Script Install Version Detection

- Accepts letter suffixes like `3.9.1a` in `redaudit/VERSION`, preventing the `0.0.0-dev` fallback after auto-update.

---

## 📦 Installation

```bash
pip install --upgrade redaudit
# or
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.2
```

---

## 🔗 Links

- [Full Changelog](../../CHANGELOG.md)
- [Documentation](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
