# RedAudit v4.0.3 Release Notes

[![Version en Espanol](https://img.shields.io/badge/Espa%C3%B1ol-blue)](./RELEASE_NOTES_v4.0.3_ES.md)

**Release Date**: 2026-01-05

## Highlights

- Proxy routing is now applied end-to-end via proxychains for external tools (TCP connect only).
- CLI validates proxychains availability and reports proxy usage during scans.
- Documentation and tests aligned with the real proxy scope and behavior.

---

## Changes

### Proxy Routing

- Added a command wrapper in `CommandRunner` and wired it through nmap, agentless verification,
  HTTP/TLS enrichment, Nikto/WhatWeb/TestSSL, and Nuclei execution paths.
- Added cleanup for temporary proxychains configuration files at the end of scans.

### CLI

- `--proxy` now enforces proxychains availability and documents TCP-only behavior.

---

## Documentation

- Updated EN/ES README, usage, manual, and security docs to reflect proxychains requirements
  and TCP-only scope.

---

## Tests

- Added tests for proxy wrapper wiring and CLI proxychains gating.

---

## Installation

```bash
pip install --upgrade redaudit
# or
pip install git+https://github.com/dorinbadea/RedAudit.git@v4.0.3
```

---

## Links

- [Full Changelog](../../CHANGELOG.md)
- [Documentation](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
