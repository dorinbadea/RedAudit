# Notas de Versión RedAudit v4.9.1

**Fecha de Lanzamiento:** 16 de Enero de 2026
**Tema:** Victorias Rápidas y Fiabilidad (Visibilidad IoT + Etiquetado Mejorado)

## Implementación de Quick Wins

Esta versión pule la precisión del descubrimiento y la granularidad de los reportes con mejoras de alto impacto ("low-hanging fruit").

- **Visibilidad UDP IoT**: Los puertos UDP especializados (ej. WiZ 38899) descubiertos durante la fase HyperScan ahora se inyectan correctamente en los reportes finales. Anteriormente, se detectaban pero no se atribuían formalmente al activo host.
- **Detección de Honeypot**: Nueva etiqueta `honeypot` añadida para hosts que exponen un número excesivo de puertos abiertos (>100), ayudando a identificar nodos engañosos rápidamente.
- **Granularidad Sin Respuesta**: Los hosts descubiertos que fallan en la fase Deep Scan (Nmap) ahora se etiquetan con `no_response:nmap_failed` en lugar de un estado genérico, facilitando el diagnóstico.

## Corrección de Errores

- **Prompt Asistente Nuclei**: Corregida una clave de internacionalización faltante (`nuclei_enable_q`) que causaba que apareciera el texto crudo de la clave en el asistente interactivo en lugar de la pregunta traducida.
- **Limpieza de Código**: Eliminado el legado `masscan_scanner.py`, completando la migración a la arquitectura pura RustScan.

## Documentación

- **Limitaciones VLAN**: Documentada explícitamente la limitación respecto a la detección de VLANs 802.1Q cuando se escanea desde un puerto de acceso (aislamiento L2), clarificando las expectativas de alcance del escaneo.
