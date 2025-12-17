# Release Notes v3.5.1 - Dry-run Completion (Hotfix)

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.5.1_ES.md)

RedAudit v3.5.1 is a hotfix release focused on completing `--dry-run` behavior and improving the updater UX.

## Highlights

- **Full `--dry-run` support**: `--dry-run` now propagates across modules so **no external commands are executed**, while planned commands are still printed.
- **Updater reliability**: If the system install is updated but `~/RedAudit` has local git changes, RedAudit now skips updating the home copy instead of failing the whole update.
- **Post-update refresh hint**: After updating, RedAudit prints a reminder to restart the terminal or run `hash -r` if the banner/version does not refresh.
- **Output provenance**: When encryption is disabled, RedAudit writes `run_manifest.json` (artifact list + counts) and adds provenance fields to `findings.jsonl` / `assets.jsonl` for easier SIEM ingestion.
- **Silent progress UI**: Host and vuln phases show Rich progress bars with ETA, and heartbeat "no output" clocking messages no longer clutter the terminal.
