# Arquitectura de Seguridad y Hardening

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](SECURITY.md)

## Visión General

RedAudit implementa una filosofía de "seguro por diseño", asumiendo la ejecución en entornos hostiles o no confiables. Este documento describe los controles de seguridad relacionados con el manejo de entrada, criptografía y seguridad operacional.

## 1. Sanitización de Entrada

Todas las entradas externas—rangos objetivo, nombres de host, nombres de interfaz—se tratan como no confiables y se someten a validación estricta.

- **Tipado Estricto**: Solo se aceptan tipos `str` para parámetros críticos.
- **Allowlisting con Regex**: IPs y nombres de host deben coincidir con patrones estrictos (`^[a-zA-Z0-9\\.\\-\\/]+$`).
- **Prevención de Inyección de Comandos**: `subprocess.run` se usa exclusivamente con listas de argumentos; la expansión de shell (`shell=True`) está deshabilitada.
- **Ubicación del Módulo**: `redaudit/core/scanner.py` (`sanitize_ip`, `sanitize_hostname`)

## 2. Implementación Criptográfica

El cifrado de reportes se gestiona mediante la librería `cryptography` para asegurar la confidencialidad de los resultados de auditoría.

- **Primitiva**: AES-128-CBC (especificación Fernet).
- **Gestión de Claves**: Las claves se derivan de contraseñas proporcionadas por el usuario usando PBKDF2HMAC-SHA256 con 480,000 iteraciones y un salt aleatorio por sesión.
- **Integridad**: Fernet incluye una firma HMAC para prevenir la manipulación del texto cifrado.
- **Ubicación del Módulo**: `redaudit/core/crypto.py`

## 3. Seguridad Operacional (OpSec)

- **Permisos de Artefactos**: RedAudit aplica `0o600` (lectura/escritura solo para el propietario) en todos los reportes generados para prevenir filtración de información a otros usuarios del sistema.
- **Evasión**: Limitación de velocidad configurable suprime el ruido de red para evadir sistemas de detección de intrusiones (IDS) basados en umbrales.
- **Heartbeat**: Monitoreo en segundo plano asegura la integridad del proceso sin requerir acceso interactivo a la shell.
- **Ubicación del Módulo**: `redaudit/core/reporter.py` (permisos de archivo), `redaudit/core/auditor.py` (heartbeat)

## 4. Pista de Auditoría

Todas las operaciones se registran en `~/.redaudit/logs/` con políticas de rotación (máx 10MB, 5 backups). Los logs contienen marcas de tiempo de ejecución, identificadores de hilos e invocaciones de comandos raw para rendición de cuentas.

## 5. Arquitectura Modular (v2.6)

El código está organizado en módulos enfocados para mejorar la mantenibilidad y auditabilidad:

- **Módulos core** (`redaudit/core/`): Funcionalidad crítica de seguridad
- **Utilidades** (`redaudit/utils/`): Constantes e internacionalización
- **Cobertura de tests**: 34 tests automatizados con pipeline CI/CD

## 6. Licencia

Este modelo de seguridad es parte del proyecto RedAudit y está cubierto por la  
**GNU General Public License v3.0 (GPLv3)**. Consulta [LICENSE](../LICENSE) para el texto completo.
