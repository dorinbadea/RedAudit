# RedAudit v4.2.0 - Versión de Escaneo Profundo y Web

## Visión General

Esta versión principal desacopla la fase de Escaneo Profundo para una ejecución paralela real, integra capacidades avanzadas de escaneo web (sqlmap, ZAP) y mejora significativamente la experiencia de usuario con progreso multi-barra y correcciones de robustez.

[![English](https://img.shields.io/badge/lang-English-blue.svg)](https://github.com/dorinbadea/RedAudit/blob/v4.2.0/docs/releases/RELEASE_NOTES_v4.2.0.md)

## Características Clave

### 🚀 Arquitectura de Escaneo Profundo Paralelo

- **Fase Desacoplada**: El Escaneo Profundo (detección de SO, versiones, banners) es ahora una fase independiente tras el Descubrimiento de Hosts.
- **Concurrencia Real**: Elimina cuellos de botella secuenciales anteriores. Ahora usa todos los hilos configurados (hasta 50) para escanear hosts simultáneamente.
- **UI Multi-Barra**: Visualización del progreso paralelo para cada host activo durante la fase de Escaneo Profundo.

### 🌐 Seguridad de Aplicaciones Web

- **Integración de sqlmap**: Soporte nativo para `sqlmap` para detectar vulnerabilidades de inyección SQL (nivel 3/riesgo 3 en perfiles exhaustivos).
- **Soporte OWASP ZAP**: Integración básica para spidering y escaneo con ZAP.
- **Correlación de Vulnerabilidades**: Los hallazgos web ahora se correlacionan con datos NVD (si está configurado).

### 🛠️ Mejoras del Núcleo

- **Deduplicación Robusta**: Implementada sanitización agresiva para prevenir hosts duplicados "fantasma" causados por caracteres invisibles en herramientas upstream.
- **Lógica Smart-Check**: Mejora en `compute_identity_score` para aprovechar mejor los datos de HyperScan.
- **Política Estricta de Emojis**: La interfaz ahora usa un conjunto estandarizado de iconos de estado (✅, ⚠️, ❌) para claridad y cumplimiento de política.

### 🌍 Internacionalización

- **Soporte Completo en Español**: Los mensajes de estado de Escaneo Profundo y HyperScan están totalmente localizados.
- **Manual Unificado**: Documentación actualizada en inglés y español.

## Correcciones

- Solucionado el informe de hosts duplicados en CLI y informes HTML.
- Solucionada la infrautilización de hilos en redes pequeñas.
- Corregidas referencias heredadas a "prescan" en la documentación.

## Instalación / Actualización

```bash
git pull
sudo bash redaudit_install.sh
```
