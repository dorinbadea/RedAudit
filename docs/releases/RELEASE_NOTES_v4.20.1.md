# RedAudit v4.20.1 - Wizard Composition and Interrupt UX

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.1/docs/releases/RELEASE_NOTES_v4.20.1_ES.md)

## Summary

This release finalizes the wizard composition hardening track and improves interruption clarity for operators during active scans.

## Added

- No new runtime features were introduced in this patch release.

## Improved

- Profile-aware Scope Expansion controls in the interactive wizard are now explicitly documented and aligned across EN/ES docs.
- Interrupt handling messaging now clearly tells operators that partial progress is being saved and cleanup is in progress after `Ctrl+C`.
- Documentation architecture references now reflect the wizard-first composition split (`wizard_service.py` and `scan_wizard_flow.py`).

## Fixed

- Documentation drift between implemented wizard composition changes and roadmap/changelog/readme references.
- Inconsistent release metadata after post-`v4.20.0` changes by synchronizing version sources and release documentation.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
