# Release Notes v3.5.0 - Reliability & Execution

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.5.0_ES.md)

RedAudit v3.5.0 is a minor release focused on stability during long-running audits and safer external command execution.

## Highlights

- **Prevent sleep during scans (default)**: RedAudit now attempts a best-effort system/display sleep inhibition while a scan is running. Opt out with `--no-prevent-sleep`.
- **Centralized CommandRunner**: A new internal module (`redaudit/core/command_runner.py`) centralizes external command execution (args-only, timeouts, retries, redaction).
- **Better `--dry-run` coverage**: More modules respect `--dry-run`. This remains an **incremental rollout**: until migration is 100% complete, some external tools may still execute.

## CLI Changes

- Added: `--no-prevent-sleep`
- Improved: `--dry-run` (incremental rollout)

## Notes

- If you updated and your banner still shows an older version, restart the terminal or run `hash -r` (zsh/bash).

