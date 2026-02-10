# RedAudit v4.20.0 - Scope Expansion Hardening

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.0/docs/releases/RELEASE_NOTES_v4.20.0_ES.md)

## Summary

This release delivers the completed scope-expansion hardening track with deterministic leak-follow policies, bounded protocol-specific IoT probes, and auditable expansion evidence in reports and exports.

## Added

- Leak-follow policy controls: `--leak-follow-policy-pack`, `--leak-follow-allowlist-profile`, and `--leak-follow-denylist`.
- Protocol/vendor IoT probe packs: `--iot-probe-pack` with `ssdp`, `coap`, `wiz`, `yeelight`, and `tuya`.
- `scope_expansion_evidence` payloads with `feature`, `classification`, `source`, `signal`, `decision`, `reason`, `host`, `timestamp`, and `raw_ref`.

## Improved

- Deterministic scope-expansion decision precedence with explicit runtime reasons.
- Per-host budget and per-probe timeout governance for IoT expansion probes.
- Report and schema visibility through `config_snapshot`, `pipeline.scope_expansion`, HTML/TXT summaries, and `summary.json`.
- EN/ES documentation parity for CLI flags, behavior, and reporting contract.

## Fixed

- Runtime/report drift between expansion decisions and exported evidence counters.
- Ambiguous expansion outcomes by enforcing corroboration guardrails before promotion to stronger evidence classes.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
