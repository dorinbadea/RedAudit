# Notas de Lanzamiento v4.13.1 (Lanzamiento de Mejoras)

**Fecha de Lanzamiento:** 18-01-2026

Este lanzamiento se centra en mejorar significativamente las capacidades de reporte HTML y refinar la lógica de identificación de dispositivos, proporcionando a los auditores datos más ricos y accionables.

## Cambios Clave

### Mejoras en el Reporte HTML

- **Detalles Técnicos Ricos:** La tabla de hallazgos ahora presenta una sección expandible de "Detalles Técnicos". Esto incluye:
  - **Descripción:** Una explicación detallada de la vulnerabilidad o puerto abierto.
  - **Referencias:** Enlaces a CVEs o documentación relevante.
  - **Evidencia:** Salida cruda del escáner (ej. payloads XML/JSON, salida de scripts Nmap) ayudando a validar el hallazgo manualmente.
- **Playbooks de Remediación Interactivos:** Los playbooks ahora se presentan como tarjetas interactivas que contienen:
  - Instrucciones de remediación paso a paso.
  - Bloques de comandos precisos para verificar y corregir problemas.
  - Enlaces de referencia externos para profundizar.

### Refinamientos en Identificación de Dispositivos

- **Análisis de Escaneo Profundo Mejorado:** La lógica de identificación ahora analiza las salidas de scripts Nmap (específicamente `http-title`) para clasificar con precisión dispositivos que antes eran genéricos.
- **Soporte para FRITZ!Repeater:** Se han añadido firmas específicas para repetidores AVM FRITZ!, asegurando que se identifiquen correctamente con el Fabricante (AVM), Modelo (FRITZ!Repeater) y Tipo de Dispositivo (IoT/Dispositivo de Red) adecuados.

## Instrucciones de Actualización

Para actualizar a la última versión, descargue los cambios del repositorio:

```bash
git pull origin main
```

No se requieren nuevas dependencias para esta actualización.
