[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.12/docs/releases/RELEASE_NOTES_v4.6.12_ES.md)

# RedAudit v4.6.12 - Nuclei Intra-batch Progress

## Summary

- Adds time-based progress movement inside each Nuclei batch to avoid frozen bars during long runs.

## Added

- None.

## Improved

- Nuclei batches now report elapsed-time progress within the batch, while still marking batch completion explicitly.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
