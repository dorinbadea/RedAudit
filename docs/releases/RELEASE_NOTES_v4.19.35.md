[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.35/docs/releases/RELEASE_NOTES_v4.19.35_ES.md)

# RedAudit v4.19.35 - Nuclei Resume & Profile Transparency

## Summary

This release makes Nuclei resumes easier to distinguish, and reports now show both the selected and effective Nuclei profile when auto-switching occurs.

## Added

- Resume menu entries now display how many times a Nuclei run has been resumed.
- Reports capture `profile_selected`, `profile_effective`, and auto-switch status for Nuclei runs.

## Improved

- Documentation clarifies Nuclei auto-switch behavior and the new report schema fields.

## Fixed

- Spanish documentation wording aligned to ES-ES terminology and accents.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No special steps required. Existing resume artifacts will show counts the next time they are resumed.
