# Release v4.5.14

[![Ver en Español](https://img.shields.io/badge/lang-es-red)](https://github.com/dorinbadea/RedAudit/blob/v4.5.14/docs/releases/RELEASE_NOTES_v4.5.14_ES.md)

## Summary

This maintenance release resolves two critical scanning issues identified in production environments: an SSH connection failure caused by strict host key policies, and a logic gap in the Smart Scan engine that prevented Deep Scans on hosts with valid identity signals but zero open ports ("Ghost Identities").

## Fixed

- **SSH Authentication**: Implemented `PermissivePolicy` for `paramiko` to forcefully accept host keys in memory without attempting to write to `known_hosts`. This fixes `SSH error: Server not found in known_hosts` in read-only or restricted environments (Docker/CI).
- **Smart Scan Logic**: Adjusted `should_trigger_deep_scan` to force a Deep Scan (UDP) when a host has a high identity score (e.g., from Phase 0 SNMP/Broadcast hints) but zero detected open ports. This resolves the "Ghost Identity" issue where reachable assets were skipped.

## Testing

Verified with:

- **Unit Tests**: Pass (60 tests), including new regression tests for `NetworkScanner` logic.
- **Manual Verification**: Validated logic using `scripts/verify_fix_scanner.py` simulating "Ghost Identity" conditions (Score 4, Ports 0).

## Upgrade

Update via git:

```bash
git pull origin main
pip install -e .
```
