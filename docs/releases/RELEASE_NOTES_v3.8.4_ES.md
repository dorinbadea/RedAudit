# Notas de Versión v3.8.4 — Verificación sin Agente y Corrección de Colores

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.8.4.md)

**Fecha de lanzamiento:** 2025-12-21

## Resumen

Esta versión introduce **Verificación sin agente**, una nueva etapa de fingerprinting para el enriquecimiento de identidad, junto con correcciones visuales para la barra de progreso CLI.

---

## Añadido

### Verificación sin agente

Una nueva etapa opcional que ejecuta scripts Nmap seguros y no intrusivos contra servicios descubiertos (SMB, RDP, LDAP, SSH, HTTP) para recopilar información de identidad más detallada sin credenciales.

- **Habilitar:** Seleccione "Sí" en el asistente cuando se le solicite "Verificación sin agente", o use `--agentless-verify`.
- **Control:** Limite el número de objetivos con `--agentless-verify-max-targets` (predeterminado: 20).
- **Beneficio:** Proporciona pistas sobre el SO, nombres de dominio y encabezados de servicio que ayudan a aclarar la "identidad" de un host.

---

## Corregido

### Colores de Estado Durante el Progreso

Cuando Rich Progress estaba activo (durante las fases de escaneo de hosts), los mensajes de estado impresos mediante `print_status()` podían perder su formato de color ANSI. Esto ocurría porque el manejo de salida de Rich interfería con las llamadas directas a `print()` usando códigos ANSI sin procesar.

**Solución:** Cuando `_ui_progress_active` es verdadero, el método `print_status()` ahora usa `console.print()` de Rich con markup apropiado:

| Estado | Estilo Rich |
|--------|-------------|
| INFO | `bright_blue` |
| OK | `green` |
| WARN | `yellow` |
| FAIL | `red` |

Esto asegura una visualización de color consistente independientemente del estado de la barra de progreso.

---

## Detalles Técnicos

- **Archivo modificado:** `redaudit/core/auditor.py`
- **Método:** `InteractiveNetworkAuditor.print_status()`
- **Fallback:** Los códigos ANSI estándar aún se usan cuando el progreso no está activo o Rich no está disponible

---

## Actualización

```bash
cd /ruta/a/RedAudit
git pull origin main
```

No se requieren cambios de configuración.

---

[Volver al README](../../README_ES.md) | [Changelog completo](../../CHANGELOG_ES.md)
