[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.11/docs/releases/RELEASE_NOTES_v4.6.11.md)

# RedAudit v4.6.11 - Salvaguardas de Identidad HTTP y Feedback de Nuclei

## Summary

- Refina la gestión de identidad HTTP para evitar que señales solo UPnP activen escaneos web, y añade feedback continuo de batches de Nuclei en la CLI.

## Added

- Los fingerprints sin agente ahora registran `http_source` y `upnp_device_name` para aclarar el origen de las pistas HTTP.

## Improved

- El progreso de Nuclei muestra actualizaciones de latido con tiempo transcurrido durante lotes largos.

## Fixed

- El gating de identidad HTTP ignora títulos solo UPnP y permite que probes HTTP reales los sobrescriban.
- El enriquecimiento de vulnerabilidades web propaga cabeceras HTTP Server a los fingerprints sin agente.

## Testing

- `pytest tests/core/test_network_scanner.py -v`
- `pytest tests/core/test_auditor_vuln.py -v`
- `pytest tests/core/test_nuclei_helpers.py -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
