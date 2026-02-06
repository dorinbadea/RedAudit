# Release Notes v4.19.10

**Release Date:** 2026-01-29

## Summary

Hotfix release addressing a visual bug in session log output where countdown prompts appeared concatenated.

## Bug Fixes

### Session Log Countdown Display

**Issue:** When the Nuclei resume prompt displayed its 15-second countdown timer, the text would appear repeated/concatenated in session logs (`cli.txt`) instead of updating in-place.

**Root Cause:** The `TeeStream._write_lines` method in `session_log.py` handled carriage return (`\r`) frames correctly by keeping only the last segment, but the ANSI line-clearing codes (`\x1b[2K`) were not stripped. These codes have no effect in log files, causing the visual concatenation.

**Fix:** Added `ANSI_LINE_CLEAR` pattern to strip `\x1b[2K` and `\x1b[K` escape codes when processing carriage return frames.

## Technical Details

### Files Changed

- `redaudit/utils/session_log.py` - Added ANSI line-clear pattern and updated `_write_lines` method
- `tests/utils/test_session_log.py` - Added test case for new behavior

### Verification

```bash
pytest tests/utils/test_session_log.py -v -k "test_lines_mode_strips_ansi_line_clear_codes"
```

## Upgrade Notes

No breaking changes. This is a backwards-compatible hotfix.
