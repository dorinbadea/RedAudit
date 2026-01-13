# RedAudit v4.3.3 - Corrección Crítica: Integridad de Datos y UI

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.3.3/docs/releases/RELEASE_NOTES_v4.3.3.md)

Este es un lanzamiento de corrección crítico que soluciona un problema de integridad de datos en el pipeline de informes (artefacto JSON) y un error visual en el asistente de descubrimiento de red.

Esta versión reemplaza a la v4.3.2 para asegurar que los hallazgos de vulnerabilidades se adjunten correctamente a los artefactos de informe.

## Corregido

### Integridad de Datos

- **Vulnerabilidades faltantes en JSON**: Se corrigió un error donde los hallazgos de herramientas como Nikto y TestSSL eran descubiertos pero no se adjuntaban correctamente a la estructura interna del objeto `Host`. Esto resultaba en arrays `findings` vacíos en los informes JSON y Risk Scores incorrectos (calculados como 0) a pesar de la presencia de vulnerabilidades.

### UI / UX

- **Glitch en Barra de Progreso**: Resuelto un problema visual en el Wizard donde el mensaje de estado "heartbeat" (*"Net Discovery en progreso..."*) se imprimía directamente en stdout en lugar de usar la consola de progreso, causando que las líneas de direcciones IP se duplicaran en pantalla.

## Cambios

- **Core**: Actualizado el modelo `Host` para incluir un campo dedicado `findings`.
- **Auditor**: Refactorizado `scan_vulnerabilities_concurrent` para mapear y adjuntar correctamente los hallazgos a los objetos Host padres.
- **Reporting**: Actualizada la serialización JSON para incluir la lista `findings` poblada.
