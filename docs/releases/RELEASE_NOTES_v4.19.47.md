# RedAudit v4.19.47 - Updater and HyperScan Robustness

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.47/docs/releases/RELEASE_NOTES_v4.19.47_ES.md)

## Summary

This patch improves runtime reliability and update-path resilience without changing normal user workflows.

## Added

- No new user-facing features.

## Improved

- Update cloning now uses non-blocking output handling, keeping timeout enforcement reliable when command output stalls.

## Fixed

- HyperScan full-port fallback now closes pending async coroutines safely when event-loop execution fails.
- Updater diagnostics now distinguish missing `git` from other missing-file failures.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
