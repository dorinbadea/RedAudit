# RedAudit v4.5.0 - Escaneo Autenticado & Toolkit Red Team

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v4.5.0.md)

Esta versión completa la **Fase 4**, introduciendo capacidades integrales de Escaneo Autenticado y módulos avanzados de Red Team. RedAudit ahora puede profundizar en los hosts utilizando credenciales válidas para descubrir configuraciones erróneas internas, vulnerabilidades y brechas de hardening.

## Nuevas Características

### Escaneo Autenticado (Fase 4)

RedAudit ahora soporta auditorías profundas con credenciales en tres protocolos principales:

- **SSH (Linux/Unix)**:
  - Recupera versiones exactas del Kernel, distribución del SO y tiempo de actividad (uptime).
  - Enumera paquetes instalados (DEB/RPM).
  - **Integración con Lynis**: Automatiza auditorías remotas de Lynis para puntuación CIS/Hardening.
- **SMB/WMI (Windows)**:
  - Enumera versión del SO, Dominio/Grupo de Trabajo, Recursos Compartidos y Usuarios.
  - Verifica políticas de contraseñas y acceso de Invitado.
  - Requiere `impacket` (dependencia opcional).
- **SNMP v3**:
  - Soporte completo para SNMPv3 cripto-ágil (Auth: MD5/SHA, Priv: DES/AES).
  - Extrae tablas de enrutamiento, interfaces y descripciones del sistema.

### Módulos Red Team

- **Integración con el Asistente**: Un nuevo flujo interactivo guía a los usuarios a través de la configuración de autenticación y opciones de Red Team.
- **Soporte de Keyring**: Las credenciales se pueden almacenar de forma segura en el anillo de claves del sistema, evitando contraseñas en texto plano en scripts.

## Mejoras

- **Asistente Interactivo**: Flujo del Asistente completamente rediseñado (Pasos 1-9) con funcionalidad "Volver" y nuevos menús de Autenticación.
- **Documentación**: Actualizaciones completas en `MANUAL.es.md` y `USAGE.es.md` detallando flujos de trabajo autenticados.
- **Estabilidad**: Se corrigieron errores de recursión en `AuditorRuntime` y se mejoraron las secuencias de mocks de pruebas.

## Correcciones

- Resuelto cierres inesperados (`StopIteration`) en pruebas del asistente interactivo.
- Corregidos errores de comprobación de tipos (Mypy) en módulos de autenticación.
- Corregida dependencia circular en `AuditorRuntime`.

## Actualización

```bash
cd RedAudit
git pull origin main
# Instalar nuevas dependencias (impacket, pysnmp)
pip install -r requirements.txt
```
