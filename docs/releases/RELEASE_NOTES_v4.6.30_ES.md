# v4.6.30: Seguridad Primero (Zombie Reaper) ‍♂️️

**Fecha:** 15-01-2026

Esta versión se centra en la **robustez y seguridad** para entornos de alta concurrencia. Tras la liberación de hilos en v4.6.29, identificamos un riesgo de subprocesos huérfanos durante interrupciones. Esta actualización protege los recursos de su sistema.

## ️ Seguridad y Fiabilidad

- **Zombie Reaper**: Implementado un mecanismo nativo de limpieza (`pkill -P <PID>`) que termina fiablemente **todos** los procesos hijos (Nmap, Nuclei, etc.) cuando RedAudit se interrumpe (ej. `Ctrl+C`).
- **Protección de Recursos**: Con `MAX_THREADS=100`, esto evita dejar docenas de escaneos "zombie" en segundo plano si el proceso principal se mata abruptamente.
- **Auditoría de FDs**: Verificado que todas las operaciones de archivo internas usan gestores de contexto (`with open(...)`) para evitar fugas de descriptores de archivo bajo carga.

## ⚡ Mejoras

- **Seguridad de Excepciones**: Auditado el uso de `ThreadPoolExecutor` para asegurar que todas las excepciones de los workers se capturan y registran, evitando fallos silenciosos en hilos.

##  Verificación

- Añadido `tests/core/test_auditor_cleanup.py` para verificar la nueva lógica del Zombie Reaper.
- Suite de regresión completa superada.
