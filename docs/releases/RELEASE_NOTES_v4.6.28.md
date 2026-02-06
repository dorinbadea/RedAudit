# RedAudit v4.6.28 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver_en_Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.28/docs/releases/RELEASE_NOTES_v4.6.28_ES.md)

## Summary

**RedAudit v4.6.28** fixes a **CRITICAL** stability issue discovered during a performance audit. It removes "Global Socket Timeout Pollution" which was affecting the reliability of all parallel modules (Nuclei, SSH, HTTP).

## Fixed

- **Global Socket Timeout Pollution**:
  - **Previous Behavior**: The `reverse_dns` function used `socket.setdefaulttimeout(timeout)` to enforce a timeout on DNS lookups. Because `setdefaulttimeout` affects the **global Python process**, this inadvertently changed the default timeout for **all other threads** running concurrently.
  - **Impact**: If a DNS lookup happened while a Nuclei batch or SSH spray was initializing, those connections would inherit the DNS timeout (e.g., 2 seconds) instead of their intended timeout. This explains sporadic timeouts and connection failures in otherwise healthy scans.
  - **New Behavior**: DNS lookups now use `ThreadPoolExecutor` with handled timeouts, ensuring **ZERO** side effects on the global socket state.

## Upgrade

```bash
git pull origin main
```
