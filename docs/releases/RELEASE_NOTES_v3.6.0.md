# RedAudit v3.6.0

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.6.0_ES.md)

**Date**: 2025-12-18
**Type**: Minor Release

## 📌 Highlights

### Nuclei is now properly reachable (opt-in)

Nuclei support is now consistent with the UX and the docs:

- Enable via wizard (full scan) or CLI flags: `--nuclei` / `--no-nuclei`
- Can be saved as a persistent default (`~/.redaudit/config.json`)
- Installer includes `nuclei` in the recommended dependencies list (apt)

### Cleaner output without losing context

- Host and vulnerability phases reduce noisy status lines while progress bars are active.
- The progress line now shows what’s happening (tool/technique) using the suppressed status as detail.
