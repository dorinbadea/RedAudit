[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.28/docs/releases/RELEASE_NOTES_v4.19.28_ES.md)

# RedAudit v4.19.28 - HTML Reports and Documentation Hygiene

## Summary
- Ships Chart.js locally with HTML reports so charts render under CSP.
- Refreshes README architecture/toolchain details and aligns Nuclei warning language.
- Removes emojis from historical release notes to enforce documentation style.

## Added
- None.

## Improved
- HTML report reliability by bundling Chart.js locally.
- README accuracy for architecture and toolchain references.
- Documentation style compliance (emoji-free release notes).

## Fixed
- HTML chart rendering blocked by CSP when using the CDN.

## Testing
- pre-commit run --all-files
- pytest tests/ -v

## Upgrade
- Standard upgrade; no breaking changes.
