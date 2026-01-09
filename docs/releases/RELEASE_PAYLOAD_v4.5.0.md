# RedAudit v4.5.0 - Authenticated Scanning & Red Team Toolkit

[![English](https://img.shields.io/badge/EN-English-blue?style=flat-square)](#english) [![Español](https://img.shields.io/badge/ES-Español-red?style=flat-square)](#español)

## English

### Authenticated Scanning & Red Team Toolkit

This release completes **Phase 4**, introducing comprehensive Authenticated Scanning capabilities and advanced Red Team modules. RedAudit can now dive deeper into hosts using valid credentials to uncover internal misconfigurations, vulnerabilities, and hardening gaps.

#### New Features

- **Authenticated Scanning (Phase 4)**: Deep credentialed audits across SSH (Linux), SMB/WMI (Windows), and SNMPv3.
- **SSH Integration**: OS/Kernel/Pkg enumeration and **Lynis** remote audits.
- **SMB/WMI**: Deep Windows asset inventory and security policy checks.
- **SNMPv3 Support**: Support for MD5/SHA authentication and DES/AES privacy.
- **Wizard Integration**: Improved step-by-step interactive flow with direct authentication configuration.
- **Keyring Support**: Secure credential storage via system keyring.

#### Improvements

- **Interactive Wizard**: Completely redesigned flow (Steps 1-9) with "Go Back" functionality.
- **Documentation**: Full update to MANUAL and USAGE guides with authenticated workflows.

#### Fixes

- Resolved StopIteration crashes in interactive tests.
- Fixed Bandit security findings and Mypy type-checking issues.
- Fixed pyproject.toml version mismatch.

---

## Español

### Escaneo Autenticado & Toolkit Red Team

Esta versión completa la **Fase 4**, introduciendo capacidades integrales de Escaneo Autenticado y módulos avanzados de Red Team. RedAudit ahora puede profundizar en los hosts utilizando credenciales válidas para descubrir configuraciones erróneas internas, vulnerabilidades y brechas de hardening.

#### Nuevas Características

- **Escaneo Autenticado (Fase 4)**: Auditorías profundas con credenciales en SSH (Linux), SMB/WMI (Windows) y SNMPv3.
- **Integración SSH**: Enumeración de SO/Kernel/Paquetes y auditorías remotas con **Lynis**.
- **SMB/WMI**: Inventario profundo de activos Windows y comprobación de políticas de seguridad.
- **Soporte SNMPv3**: Soporte para autenticación MD5/SHA y privacidad DES/AES.
- **Integración con el Asistente**: Flujo interactivo mejorado paso a paso con configuración directa de autenticación.
- **Soporte de Keyring**: Almacenamiento seguro de credenciales mediante el anillo de claves del sistema.

#### Mejoras

- **Asistente Interactivo**: Flujo completamente rediseñado (Pasos 1-9) con funcionalidad "Volver".
- **Documentación**: Actualización completa de las guías MANUAL y USAGE con flujos de trabajo autenticados.

#### Correcciones

- Resueltos cierres inesperados (StopIteration) en pruebas interactivas.
- Corregidos hallazgos de seguridad Bandit y errores de tipo Mypy.
- Corregida discrepancia de versión en pyproject.toml.
