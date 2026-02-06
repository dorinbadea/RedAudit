# RedAudit v4.6.26 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver_en_Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.26/docs/releases/RELEASE_NOTES_v4.6.26_ES.md)

## Summary

**RedAudit v4.6.26** fixes a specific User Interface issue introduced by the new parallel Nuclei engine. It ensures that the scan progress bar remains smooth and accurate when multiple batches are running simultaneously.

## Fixed

- **Progress Bar "Jitter"**: In parallel mode, individual batches were reporting their *local* progress to the main progress bar, causing it to jump wildly (e.g., 10% -> 5% -> 12%). Use of a centralized, thread-safe aggregation logic now ensures the progress bar accurately reflects the *total* combined progress of all running batches.

## Upgrade

```bash
git pull origin main
```
