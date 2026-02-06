# RedAudit v4.5.2 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.2/docs/releases/RELEASE_NOTES_v4.5.2_ES.md)

## Summary

This release introduces **Phase 4.1.1: Multi-Credential Support**, a significant enhancement that allows spraying universal credentials across multiple protocols (SSH, SMB, SNMP, RDP, WinRM) with automatic protocol detection.

It also includes critical usability fixes identified during a "Zero-Context Audit", ensuring safe navigation in the interactive wizard and robust integration of credentials.

## Added

- **Multi-Credential Support**:
  - **Universal Mode**: Configure username/password pairs once, and RedAudit automatically tries them against all discovered open ports (22, 445, 161, 3389, 5985).
  - **Credentials Manager**: New `CredentialsManager` module handles secure loading and testing of credentials.
  - **New Flags**:
    - `--credentials-file PATH`: Load credentials from a JSON file.
    - `--generate-credentials-template`: Create a secure template at `~/.redaudit/credentials.json`.
  - **UI Hints**: Wizard now displays protocol detection strategy (e.g., "Trying SSH (22), SMB (445)...").

- **Audit & Usability Fixes**:
  - **Safe Navigation**: Added `< Go Back` option in critical wizard menus (Auth Mode, Windows Verification) to prevent user entrapment.
  - **Unified Logic**: Refactored `auditor.py` to use a single, unified authentication setup flow, eliminating legacy code duplication.

## Improved

- **Wizard Experience**:
  - Clear distinction between "Universal" (Auto) and "Advanced" (Legacy/Manual) modes.
  - Enhanced prompts and feedback for multi-credential configuration.

## Testing

- Added 39 new tests covering:
  - CLI flags and file loading permissions.
  - Interactive wizard navigation (regression tests for back-button logic).
  - Credential looping and fallback logic in the core auditor.
- Full regression suite passed (unit + integration).

## Upgrade

```bash
cd RedAudit
git pull
sudo bash redaudit_install.sh
```
