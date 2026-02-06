[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.37/docs/releases/RELEASE_NOTES_v4.19.37_ES.md)

# RedAudit v4.19.37 - Nuclei Consistency and Runtime Hardening

## Summary

This release tightens Nuclei reporting consistency and improves runtime robustness in scope-expansion metadata handling.

## Added

- None.

## Improved

- Spanish HTML report terminology in scope-expansion metadata is now fully localized.
- Full-coverage status messaging now states explicitly that auto-switch safeguards are skipped to honor the selected profile.

## Fixed

- Nuclei target accounting now stays coherent when leak-follow appends extra targets.
- Scope-expansion runtime counters now parse safely when persisted numeric fields are malformed.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

```bash
pip install --upgrade redaudit
# Or via source
git pull origin main
sudo bash redaudit_install.sh
```
