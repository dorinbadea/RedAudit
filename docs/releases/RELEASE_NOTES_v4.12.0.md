[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.12.0/docs/releases/RELEASE_NOTES_v4.12.0.md) [![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.12.0/docs/releases/RELEASE_NOTES_v4.12.0_ES.md)

# RedAudit v4.12.0 Release Notes

## Summary

RedAudit v4.12.0 is a **performance optimization release** that introduces **profile-based tool gating** for Nikto. This release significantly reduces scan time on networks with many infrastructure devices (routers, switches, access points) by intelligently skipping Nikto scans based on the selected Nuclei profile.

## Added

- **Profile-Based Nikto Gating**: The Nuclei profile (`--profile`) now controls Nikto execution:
  - `fast`: Skips Nikto entirely for maximum scan speed.
  - `balanced`: Skips Nikto on detected infrastructure devices (routers, switches, APs).
  - `full`: Runs Nikto on all web hosts (original behavior).
- **Enhanced Infrastructure Detection**: Improved `is_infra_identity()` to detect more network device patterns (Fritz!Box, MikroTik, Ubiquiti, Synology, QNAP, and others).

## Improved

- **Scan Performance**: Networks with many infrastructure devices (like home routers, NAS devices, and access points) will see significantly reduced scan times when using `balanced` profile.
- **Code Architecture**: Nikto gating logic moved to dedicated `_should_run_nikto()` method for better separation of concerns.

## Fixed

- **Spanish Changelog**: Added missing v4.12.0 entry to `ES/CHANGELOG_ES.md`.

## Testing

- **Automated**: Full `pytest` suite passed (1816 tests).
- **Expected Behavior**:
  - `balanced` profile: Fritz!Box and similar routers should show `nikto_skipped: infra_keyword:fritz` in logs.
  - `fast` profile: Nikto skipped entirely with `nikto_skipped: profile_fast`.
  - `full` profile: Nikto runs on all web hosts as before.

## Upgrade

No breaking changes. Update and install dependencies:

```bash
git pull origin main
pip install -e .
```
