# Release v4.5.15

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.15/docs/releases/RELEASE_NOTES_v4.5.15_ES.md)

## Summary

This hotfix corrects the v4.5.14 fixes which were applied to the wrong code path. The Ghost Identity detection now works correctly for hosts with zero open ports, and SSH key trust is enabled by default for automated scanning.

## Fixed

- **Smart Scan (Ghost Identity)**: Added `ghost_identity` trigger condition to `auditor_scan.py:_should_trigger_deep()` for hosts with `total_ports == 0` and weak identity. The v4.5.14 fix was incorrectly applied to `network_scanner.py` which is not used in the actual orchestration flow.
- **SSH Authentication**: Changed default value of `auth_ssh_trust_keys` from `False` to `True` in `auditor_scan.py`, ensuring the `PermissivePolicy` is used by default in automated scanning environments.

## Testing

Verified with:

- **Unit Tests**: 17/17 deep scan tests passed.
- **Scan Analysis**: Identified root cause via scan `RedAudit_2026-01-10_19-38-50` showing Host .40 with `trigger_deep: false` despite `identity_score: 3 < threshold: 4`.

## Upgrade

```bash
git pull origin main
pip install -e .
```
