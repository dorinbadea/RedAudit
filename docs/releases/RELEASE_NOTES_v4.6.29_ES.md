# Notas de Lanzamiento v4.6.29

![Versión](https://img.shields.io/badge/versión-v4.6.29-blue?style=flat-square) [![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v4.6.29.md)

##  Rendimiento Desbloqueado: Límites de Hilos

En respuesta a las capacidades del hardware moderno (chips M2/M3, Threadrippers), se aumentaron significativamente los límites de concurrencia de RedAudit.

### ⚡ Aspectos Destacados

- **Límite de Hilos Aumentado (16 → 100)**: Se ha eliminado el límite artificial de 16 hilos. Ahora puedes usar hasta **100 hilos** para el escaneo profundo, permitiendo a RedAudit utilizar al máximo CPUs de alto rendimiento.
- **Concurrencia Deep Scan**: La fase de Deep Scan ahora respeta el límite global `MAX_THREADS`, eliminando el tope hardcoded anterior de 50.
- **Integridad de Configuración**: Corregido un problema de consistencia donde faltaba `nuclei_timeout` en los valores por defecto del contexto de configuración.

---

### ️ Cambios Clave

#### Rendimiento

- **Hilos Desbloqueados**: Constante `MAX_THREADS` actualizada a 100.
- **Deep Scan**: Lógica actualizada para usar límites de hilos dinámicos.

#### Correcciones

- **Config**: Añadido `nuclei_timeout` a `ConfigurationContext`.

#### Verificación

- **Tests**: Añadido `tests/core/test_thread_limits.py` para verificar el cumplimiento de los límites de hilos.

---

*[Volver al Changelog](../../ES/CHANGELOG_ES.md)*
