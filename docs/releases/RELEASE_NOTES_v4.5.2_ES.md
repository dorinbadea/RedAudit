# Notas de la Versión v4.5.2 de RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.2/docs/releases/RELEASE_NOTES_v4.5.2.md)

## Resumen

Esta versión introduce **Fase 4.1.1: Soporte Multi-Credencial**, una mejora significativa que permite el "spraying" de credenciales universales a través de múltiples protocolos (SSH, SMB, SNMP, RDP, WinRM) con detección automática de protocolo.

También incluye correcciones críticas de usabilidad identificadas durante una "Auditoría Zero-Context", asegurando una navegación segura en el asistente interactivo y una integración robusta de credenciales.

## Añadido

- **Soporte Multi-Credencial**:
  - **Modo Universal**: Configura pares usuario/contraseña una vez, y RedAudit los prueba automáticamente contra todos los puertos abiertos descubiertos (22, 445, 161, 3389, 5985).
  - **Gestor de Credenciales**: Nuevo módulo `CredentialsManager` maneja la carga segura y prueba de credenciales.
  - **Nuevos Flags**:
    - `--credentials-file PATH`: Cargar credenciales desde un fichero JSON.
    - `--generate-credentials-template`: Crear una plantilla segura en `~/.redaudit/credentials.json`.
  - **Pistas en UI**: El asistente ahora muestra la estrategia de detección de protocolo (ej. "Probando SSH (22), SMB (445)...").

- **Auditoría y Mejoras de Usabilidad**:
  - **Navegación Segura**: Añadida opción `< Volver` en menús críticos del asistente (Modo Auth, Verificación Windows) para evitar atrapar al usuario.
  - **Lógica Unificada**: Refactorizado `auditor.py` para usar un flujo de configuración de autenticación único y unificado, eliminando duplicación de código legado.

## Mejorado

- **Experiencia del Asistente**:
  - Distinción clara entre modos "Universal" (Auto) y "Avanzado" (Legado/Manual).
  - Prompts y feedback mejorados para la configuración multi-credencial.

## Pruebas

- Añadidos 39 nuevos tests cubriendo:
  - Flags de CLI y permisos de carga de ficheros.
  - Navegación interactiva del asistente (tests de regresión para lógica del botón volver).
  - Bucle de credenciales y lógica de respaldo en el auditor central.
- Suite completa de regresión aprobada (unitarios + integración).

## Actualización

```bash
cd RedAudit
git pull
sudo bash redaudit_install.sh
```
