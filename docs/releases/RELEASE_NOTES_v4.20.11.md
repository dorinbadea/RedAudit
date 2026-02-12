# RedAudit v4.20.11 - Nuclei Resume Prompt Stability

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.11/docs/releases/RELEASE_NOTES_v4.20.11_ES.md)

## Summary

This patch release hardens Nuclei runtime usability during long scans by fixing resume prompt timeout behavior and reducing routine timeout noise in live terminal output.

## Added

- No new features in this patch release.

## Improved

- Reduced repetitive Nuclei timeout progress noise during long-running retries.

## Fixed

- Fixed a blocking edge case in resume timeout prompts where auto-continue could stall waiting for Enter.
- Improved prompt input handling so single-key `y`/`n` responses are accepted immediately in terminal mode.

## Testing

Internal validation completed.

## Upgrade

No action required.
