# Release Notes v3.5.2 - Output UX & Safer Updates (Hotfix)

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.5.2_ES.md)

RedAudit v3.5.2 is a hotfix release focused on operator experience (clear progress/ETA) and a safer post-update workflow.

## Highlights

- **Restart required after update**: After installing an update, RedAudit displays a large "restart the terminal" notice, waits for confirmation, and exits to ensure the next run loads the new version cleanly.
- **Net Discovery feedback**: Network discovery phases now show visible activity so the terminal doesn't look stuck during long discovery steps.
- **Cleaner progress output**: Progress UI reduces noisy logs while active and displays a conservative upper bound (`ETA≤ …`) that accounts for configured timeouts.
