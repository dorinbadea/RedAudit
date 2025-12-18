# RedAudit v3.5.3

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.5.3_ES.md)

**Date**: 2025-12-18
**Type**: Patch Release (Documentation & Code Quality)

## 📌 Highlights

### Documentation Integrity & Normalization

This release focuses on ensuring the documentation accurately reflects the codebase ("smoke-free" documentation), repairing broken links, and optimizing the project structure.

- **Docs Normalization**: Consolidates documentation into the root `docs/` folder (removing `docs/en/` and `docs/es/`) using `.en.md` and `.es.md` suffixes.
- **Roadmap Verification**: The roadmap has been audited to strictly separate *Planned* features from *Implemented* ones, ensuring no "vaporware" claims.
- **Didactic Guide Rewrite**: Completely restructured `DIDACTIC_GUIDE` (EN/ES) to be a true pedagogical resource for instructors, removing duplication with the manual.
- **Link Fixes**: Repaired broken internal links in `pyproject.toml`, `README`, and release templates.

## 🛠 Fixes

- **Docs**: Fixed `pyproject.toml` pointing to non-existent documentation paths.
- **Docs**: Fixed redundant headers and missing language specifiers in Markdown files (Linting compliance).
- **Structure**: Formalized the use of `docs/INDEX.md` as the documentation entry point.

## 📦 Changes

| Component | Change |
| :--- | :--- |
| **Docs** | Flattened structure (`docs/MANUAL.en.md`, etc.) |
| **Roadmap** | Verified implementation status of Red Team features |
| **Didactic** | New instructor-focused format with session plans |

## 🔗 Quick Links

- [Manual (EN)](../../MANUAL.en.md)
- [Usage Guide (EN)](../../USAGE.en.md)
- [Changelog](../../../CHANGELOG.md)
