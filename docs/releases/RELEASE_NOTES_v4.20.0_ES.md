# RedAudit v4.20.0 - Endurecimiento de expansion de alcance

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.0/docs/releases/RELEASE_NOTES_v4.20.0.md)

## Resumen

Esta version entrega la pista completa de endurecimiento de expansion de alcance con politicas deterministas de leak-follow, sondas IoT especificas por protocolo con ejecucion acotada y evidencia auditable en informes y exportes.

## Anadido

- Controles de politica leak-follow: `--leak-follow-policy-pack`, `--leak-follow-allowlist-profile` y `--leak-follow-denylist`.
- Packs IoT por protocolo/fabricante: `--iot-probe-pack` con `ssdp`, `coap`, `wiz`, `yeelight` y `tuya`.
- Payloads `scope_expansion_evidence` con `feature`, `classification`, `source`, `signal`, `decision`, `reason`, `host`, `timestamp` y `raw_ref`.

## Mejorado

- Precedencia determinista en decisiones de expansion de alcance con razones explicitas en runtime.
- Gobernanza de presupuesto por host y timeout por sonda para sondas de expansion IoT.
- Visibilidad en reportes y esquema mediante `config_snapshot`, `pipeline.scope_expansion`, resumenes HTML/TXT y `summary.json`.
- Paridad documental EN/ES para flags CLI, comportamiento y contrato de reporting.

## Corregido

- Deriva entre decisiones runtime de expansion y contadores de evidencia exportados.
- Resultados ambiguos de expansion mediante guardarrailes de corroboracion antes de promover a clases de evidencia mas fuertes.

## Pruebas

- Validacion interna completada.

## Actualizacion

- No se requiere ninguna accion.
