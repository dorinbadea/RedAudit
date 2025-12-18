# Notas de la versión v3.5.2 - UX de Salida y Actualizaciones Más Seguras (Hotfix)

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.5.2.md)

RedAudit v3.5.2 es una hotfix centrada en la experiencia del operador (progreso/ETA claros) y un flujo post-actualización más seguro.

## Highlights

- **Reinicio obligatorio tras actualizar**: Tras instalar una actualización, RedAudit muestra un aviso grande de "reinicia el terminal", espera confirmación y sale para asegurar que la siguiente ejecución cargue la nueva versión limpiamente.
- **Feedback en Net Discovery**: Las fases de descubrimiento de red muestran actividad visible para que el terminal no parezca bloqueado durante pasos largos.
- **Progreso más limpio**: La UI de progreso reduce el ruido de logs mientras está activa y muestra una cota superior conservadora (`ETA≤ …`) que considera los timeouts configurados.
