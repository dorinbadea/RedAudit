# Arquitectura de Seguridad y Hardening

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](SECURITY.md)

## Visión General

RedAudit implementa una filosofía de "seguro por diseño", asumiendo la ejecución en entornos hostiles o no confiables. Este documento describe los controles de seguridad relacionados con el manejo de entrada, criptografía y seguridad operacional.

## 1. Sanitización de Entrada

Todas las entradas externas—rangos objetivo, nombres de host, nombres de interfaz—se tratan como no confiables y se someten a validación estricta.

- **Tipado Estricto**: Solo se aceptan tipos `str` para parámetros críticos.
- **Validación de Direcciones IP**: Usa el módulo `ipaddress` de Python para validar direcciones IPv4 e IPv6. Las IPs inválidas devuelven `None`.
- **Validación de Nombres de Host**: Allowlisting con regex (`^[a-zA-Z0-9\.\-]+$`) asegura solo caracteres alfanuméricos, puntos y guiones.
- **Límites de Longitud**: Todas las entradas se truncan a `MAX_INPUT_LENGTH` (1024 caracteres) para prevenir ataques basados en buffer.
- **Prevención de Inyección de Comandos**: `subprocess.run` se usa exclusivamente con listas de argumentos; la expansión de shell (`shell=True`) está deshabilitada.
- **Ubicación del Módulo**: `redaudit/core/scanner.py` (`sanitize_ip`, `sanitize_hostname`)

## 2. Implementación Criptográfica

El cifrado de reportes se gestiona mediante la librería `cryptography` para asegurar la confidencialidad de los resultados de auditoría.

- **Primitiva**: AES-128-CBC (especificación Fernet).
- **Gestión de Claves**: Las claves se derivan de contraseñas proporcionadas por el usuario usando PBKDF2HMAC-SHA256 con 480,000 iteraciones y un salt aleatorio por sesión.
- **Integridad**: Fernet incluye una firma HMAC para prevenir la manipulación del texto cifrado.
- **Ubicación del Módulo**: `redaudit/core/crypto.py`

## 3. Seguridad Operacional (OpSec)

- **Permisos de Artefactos**: RedAudit aplica `0o600` (lectura/escritura solo para el propietario) a los artefactos generados (reportes, vistas JSONL/JSON, evidencia externalizada) para reducir filtraciones a otros usuarios del sistema.
- **Seguridad en Modo Cifrado**: Si el cifrado de reportes está activado, RedAudit evita generar vistas adicionales en texto plano (JSONL/summary y evidencia externalizada) junto a reportes `.enc`.
- **Rate-Limiting con Jitter**: Limitación de velocidad configurable con varianza aleatoria ±30% para evadir IDS basados en umbrales y análisis de comportamiento.
- **Discreción Pre-scan**: Descubrimiento de puertos basado en asyncio minimiza las invocaciones de nmap, reduciendo la huella de red.
- **Heartbeat**: Monitoreo en segundo plano asegura la integridad del proceso sin requerir acceso interactivo a la shell.
- **Ubicación del Módulo**: `redaudit/core/reporter.py` (permisos), `redaudit/core/auditor.py` (heartbeat, jitter), `redaudit/core/prescan.py` (descubrimiento rápido)

## 4. Pista de Auditoría

Todas las operaciones se registran en `~/.redaudit/logs/` con políticas de rotación (máx 10MB, 5 backups). Los logs contienen marcas de tiempo de ejecución, identificadores de hilos e invocaciones de comandos raw para rendición de cuentas.

## 5. Seguridad CI/CD

Controles de seguridad automatizados integrados en el pipeline de desarrollo:

- **Bandit**: Linting de seguridad estático para código Python en cada push/PR
- **Dependabot**: Escaneos semanales de dependencias vulnerables (pip, GitHub Actions)
- **CodeQL**: Análisis estático de vulnerabilidades de seguridad en cada push/PR
- **Testing Multi-versión**: Compatibilidad verificada en Python 3.9-3.12

## 6. Arquitectura Modular

El código está organizado en módulos enfocados para mejorar la mantenibilidad y auditabilidad:

- **Módulos core** (`redaudit/core/`): Funcionalidad crítica de seguridad
- **Utilidades** (`redaudit/utils/`): Constantes e internacionalización
- **Tests**: La suite automatizada se ejecuta en GitHub Actions (`.github/workflows/tests.yml`) en Python 3.9–3.12; el número exacto de tests lo reporta CI y no se fija en la documentación.

## 7. Auto-Actualización Segura

RedAudit incluye un mecanismo de actualización seguro que verifica GitHub para nuevas versiones:

- **Sin descargas arbitrarias**: Usa `git clone` desde el repositorio oficial
- **Fijado a tags**: El flujo de actualización resuelve el tag publicado y verifica el hash del commit antes de instalar
- **Verificación de integridad**: La verificación de hash integrada de Git asegura autenticidad
- **Confirmación del usuario**: Siempre pregunta antes de aplicar actualizaciones
- **Manejo de fallos de red**: Degradación elegante si GitHub no está disponible
- **Protección de cambios locales**: Rechaza actualizar si hay cambios sin commitear
- **Ubicación del módulo**: `redaudit/core/updater.py`

## 8. Almacenamiento de API Key NVD (v3.0.1+)

RedAudit soporta almacenar claves API de NVD para correlación CVE:

- **Archivo de Configuración**: `~/.redaudit/config.json` con permisos `0600`
- **Variable de Entorno**: `NVD_API_KEY` (nunca se registra en logs)
- **Prioridad**: Flag CLI → Variable de entorno → Archivo de configuración
- **Sin texto plano en logs**: Las claves API nunca se escriben en archivos de log
- **Escrituras atómicas**: Las actualizaciones de configuración usan archivo temporal + renombrar para seguridad ante fallos

Los usuarios deben tratar el archivo de configuración como sensible. La clave API otorga límites de velocidad incrementados pero no proporciona acceso a datos privados.

## 9. Licencia

Este modelo de seguridad es parte del proyecto RedAudit y está cubierto por la  
**GNU General Public License v3.0 (GPLv3)**. Consulta [LICENSE](../LICENSE) para el texto completo.
