[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.11/docs/releases/RELEASE_NOTES_v4.6.11_ES.md)

# RedAudit v4.6.11 - HTTP Identity Guardrails and Nuclei Feedback

## Summary

- Refines HTTP identity handling to avoid UPnP-only signals triggering web scans, and adds continuous Nuclei batch feedback in the CLI.

## Added

- Agentless fingerprints now track `http_source` and `upnp_device_name` to clarify how HTTP identity hints were derived.

## Improved

- Nuclei progress shows heartbeat updates with elapsed time during long batches.

## Fixed

- HTTP identity gating ignores UPnP-only titles and allows real HTTP probes to override them.
- Web vulnerability enrichment now propagates HTTP server headers into agentless fingerprints.

## Testing

- `pytest tests/core/test_network_scanner.py -v`
- `pytest tests/core/test_auditor_vuln.py -v`
- `pytest tests/core/test_nuclei_helpers.py -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
