# RedAudit v4.20.2 - Scope Expansion Wizard UX Polish

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.2/docs/releases/RELEASE_NOTES_v4.20.2_ES.md)

## Summary

This patch improves the Scope Expansion wizard experience for non-expert operators while keeping runtime scanning semantics unchanged.

## Added

- No new runtime scanners or protocol packs were introduced in this patch release.

## Improved

- Advanced Scope Expansion setup is now guided with explicit `Automatic (Recommended)` and `Manual` choices.
- Leak Following policy-pack labels are now human-readable (`Safe Default`, `Safe Strict`, `Safe Extended`) in interactive prompts.
- Choosing `No (default)` on advanced Scope Expansion now explicitly confirms that automatic recommended defaults are in effect.
- Empty manual CSV entries in advanced Scope Expansion prompts now resolve deterministically to automatic safe defaults.

## Fixed

- Ambiguous advanced wizard prompt flow for Scope Expansion controls.
- Operator uncertainty around what happens when advanced CSV fields are left empty.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
