# RedAudit v4.20.11 - Estabilidad del Prompt de Reanudacion de Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.11/docs/releases/RELEASE_NOTES_v4.20.11.md)

## Resumen

Esta version patch refuerza la usabilidad de Nuclei en escaneos largos corrigiendo el timeout del prompt de reanudacion y reduciendo ruido rutinario por timeouts en la salida live de terminal.

## Anadido

- No se incluyen nuevas funcionalidades en esta version patch.

## Mejorado

- Se reduce el ruido repetitivo de progreso de Nuclei por timeouts en ciclos largos de reintento.

## Corregido

- Se corrige un caso bloqueante en prompts de timeout de reanudacion donde la auto-continuacion podia quedarse esperando Enter.
- Se mejora el manejo de entrada para aceptar respuestas rapidas `y`/`n` de forma inmediata en modo terminal.

## Testing

Validacion interna completada.

## Upgrade

No se requiere accion.
