# RedAudit v3.3.0 Notas de la Versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.3.0.md)

**Fecha:** 17 de Diciembre, 2025
**Nombre Clave:** "Visual Insight"
**Enfoque:** Experiencia de Desarrollador (DX), Visualización y Alertas

## Resumen

RedAudit v3.3.0 representa un salto significativo en usabilidad y conciencia operativa. Mientras que las versiones anteriores se centraban en capacidades de escaneo profundo, esta versión se centra en cómo se consumen y actúan esos datos. Introducimos dashboards HTML de grado profesional, alertas por webhook en tiempo real y análisis diferencial visual.

## Características Clave

### 1. Dashboard HTML Interactivo (`--html-report`)

Anteriormente, los analistas tenían que parsear JSON o leer archivos de texto estáticos. v3.3 introduce un informe HTML interactivo y autocontenido:

- **Cero Dependencias**: No requiere JS/CSS externo; seguro para redes aisladas (air-gapped).
- **Visualización de Datos**: Gráficos para distribución de SO, desglose de Severidad y Top Puertos.
- **Búsqueda y Filtro**: Búsqueda instantánea en cientos de hallazgos.

### 2. Alertas Webhook (`--webhook`)

Para flujos de trabajo DevSecOps y monitoreo continuo, RedAudit ahora puede enviar hallazgos en tiempo real a:

- Slack / Microsoft Teams / Discord
- Pipelines SOAR personalizados
- Endpoints de logging centralizado
**Datos Enviados**: Severidad, Título, IP Objetivo y Descripción.

### 3. Análisis Diferencial Visual (`--diff` con HTML)

El motor diferencial introducido en v3.0 ha sido mejorado. El comando `--diff old.json new.json` ahora produce un informe HTML visual resaltando:

- **Nuevos Hallazgos**: Marcados en Rojo.
- **Problemas Resueltos**: Marcados en Verde.
- **Regresiones**: Detecta fácilmente vulnerabilidades reabiertas.

## Mejoras

- **CLI DX**: Banner mejorado, mensajes de heartbeat más limpios y mejor manejo de errores.
- **Seguridad**: Añadida configuración `[tool.bandit]` para suprimir falsos positivos en escaneos.
- **Rendimiento**: Generación HTML optimizada para ser instantánea incluso con grandes conjuntos de datos.

## Correcciones de Errores

- Corregido falso positivo B101 de `bandit` en pipeline CI.
- Corregida caída potencial cuando falta el directorio `templates/` (ahora degrada graciosamente).

## Actualización

Los usuarios existentes pueden actualizar usando el instalador o git:

```bash
cd RedAudit
git pull
sudo bash redaudit_install.sh
```

## Contribuidores

- @dorinbadea (Desarrollador Principal)
