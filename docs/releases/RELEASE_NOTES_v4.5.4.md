# Release Notes v4.5.4

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.4/docs/releases/RELEASE_NOTES_v4.5.4_ES.md)

**Release Date:** 2026-01-10

## Summary

This release implements B5: Credential Loading from Keyring. The wizard now detects saved credentials and offers to load them at scan start, eliminating the need to re-enter credentials for subsequent scans.

## Added

- **B5: Credential Loading from Keyring**
  - Wizard detects if credentials were saved in previous scans
  - Prompts user: "Saved credentials found. Load them?"
  - Loads SSH, SMB, and SNMP credentials from OS keychain
  - Skips manual credential entry if user accepts

### Implementation Details

- `KeyringCredentialProvider.has_saved_credentials()` - Checks if any protocol has saved credentials
- `KeyringCredentialProvider.get_saved_credential_summary()` - Returns list of (protocol, username) tuples
- `Wizard._check_and_load_saved_credentials()` - Orchestrates detection and loading flow

## Testing

- 22 credential tests passing (4 new for credential detection)
- Full pre-commit validation

## Upgrade

```bash
cd ~/RedAudit && git pull && sudo bash redaudit_install.sh
```

## Workflow

1. First scan: Enter credentials, optionally save to keyring
2. Second scan: Wizard detects saved credentials and offers to load them
3. Accept: Credentials are loaded automatically
4. Decline: Proceed with manual credential entry
