# Arquitectura de Seguridad y Hardening

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](../en/SECURITY.md)

## Visión General

RedAudit implementa una filosofía de "seguro por diseño", asumiendo la ejecución en entornos hostiles o no confiables. Este documento describe los controles de seguridad relacionados con el manejo de entrada, criptografía y seguridad operacional.

## Versiones soportadas

| Versión | Soportada | Estado |
| ------- | --------- | ------ |
| 3.4.x   | Sí        | Estable actual |
| 3.3.x   | Sí        | Soportada |
| 3.2.x   | Solo fixes de seguridad | Mantenimiento |
| 2.9.x   | Solo fixes de seguridad | EOL: Marzo 2026 |
| 2.8.x   | No        | EOL |
| < 2.8   | No        | EOL |

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

- **Permisos de Artefactos**: RedAudit aplica `0o600` (lectura/escritura solo para el propietario) a los artefactos generados (reportes, HTML/playbooks, vistas JSONL/JSON, evidencia externalizada) para reducir filtraciones a otros usuarios del sistema.
- **Seguridad en Modo Cifrado**: Si el cifrado de reportes está activado, RedAudit evita generar artefactos adicionales en texto plano (HTML/JSONL/playbooks/resumen y evidencia externalizada) junto a reportes `.enc`.
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

## 7. Auto-Actualización Fiable

RedAudit incluye un mecanismo de actualización que verifica GitHub para nuevas versiones:

- **Sin descargas arbitrarias**: Usa `git clone` desde el repositorio oficial
- **Fijado a tags**: El flujo de actualización resuelve el tag publicado y verifica el hash del commit antes de instalar
- **Verificación de integridad**: La verificación de hash integrada de Git asegura que los datos no se corrompieron en tránsito
- **Confirmación del usuario**: Siempre pregunta antes de aplicar actualizaciones
- **Manejo de fallos de red**: Degradación elegante si GitHub no está disponible
- **Protección de cambios locales**: Rechaza actualizar si hay cambios sin commitear
- **Instalación staged**: Los nuevos ficheros se copian a un directorio temporal antes de reemplazar atómicamente la instalación actual (v3.2.3+)
- **Rollback en caso de fallo**: Si la instalación falla, la versión anterior se restaura automáticamente (v3.2.3+)
- **Ubicación del módulo**: `redaudit/core/updater.py`

> [!IMPORTANT]
> **Limitación de Seguridad**: El sistema de actualización verifica que los commits clonados coincidan con las refs de git esperadas (integridad), pero **NO** realiza verificación criptográfica de firmas de tags o releases (autenticidad). Si GitHub o el repositorio están comprometidos, código malicioso podría distribuirse. Los usuarios que requieran mayor seguridad deben verificar releases manualmente o implementar verificación de firmas GPG.

## 8. Almacenamiento de API Key NVD (v3.0.1+)

RedAudit soporta almacenar claves API de NVD para correlación CVE:

- **Archivo de Configuración**: `~/.redaudit/config.json` con permisos `0600`
- **Variable de Entorno**: `NVD_API_KEY` (nunca se registra en logs)
- **Prioridad**: Flag CLI → Variable de entorno → Archivo de configuración
- **Sin texto plano en logs**: Las claves API nunca se escriben en archivos de log
- **Escrituras atómicas**: Las actualizaciones de configuración usan archivo temporal + renombrar para seguridad ante fallos

Los usuarios deben tratar el archivo de configuración como sensible. La clave API otorga límites de velocidad incrementados pero no proporciona acceso a datos privados.

## 9. Limitaciones conocidas

- **Requiere root/sudo**: Necesario para sockets raw (nmap, tcpdump)
- **Sin sandboxing**: Las herramientas externas se ejecutan con privilegios del sistema
- **Huella de red**: Los escaneos generan tráfico significativo
- **Recon opcional**: `--net-discovery` / `--redteam` pueden invocar tooling broadcast/L2 adicional (best-effort; solo con autorización explícita)

## 11. Seguridad en Red Team y Reconocimiento Activo

RedAudit v3.2 introduce capacidades de **Reconocimiento Activo** (`--redteam`, `--net-discovery`) que difieren del escaneo estándar:

- **Difusión**: Estos modos envían paquetes L2 broadcast/multicast (ARP, mDNS, NetBIOS).
- **Sondeo**: Ocurre interacción activa con servicios (SNMP, SMB, Kerberos) si se detectan.
- **Trazabilidad**: A diferencia de la escucha pasiva, estas acciones **generarán logs** en los sistemas objetivo y pueden activar reglas IDS/IPS.
- **Autorización**: Asegúrese de tener permiso explícito para descubrimiento interno **activo**, no solo para escaneo de vulnerabilidades externo.

### Advertencias Específicas por Herramienta

| Herramienta | Capacidad | Nivel de Riesgo | Autorización Requerida |
|:------------|:----------|:----------------|:-----------------------|
| `snmpwalk` | Consulta agentes SNMP para información de dispositivos red (VLANs, tablas ARP, configs interfaces) | **Medio** - Logs en dispositivos con SNMP | ✅ Aprobación admin interno |
| `enum4linux` | Enumera recursos SMB Windows, usuarios, políticas contraseñas, info dominio | **Alto** - Activa logs seguridad, puede alertar SOC | ✅ Aprobación admin dominio |
| `masscan` | Escáner puertos ultra-rápido (capacidad 1M paquetes/seg) | **Alto** - Alto ruido red, probable trigger IDS | ✅ Aprobación equipo red + seguridad |
| `rpcclient` | Enumeración Windows RPC (usuarios, grupos, recursos) | **Alto** - Logs Active Directory, intentos auth | ✅ Aprobación admin dominio |
| `ldapsearch` | Consultas LDAP/AD para estructura organizacional | **Medio** - Servidor LDAP registra consultas | ✅ Aprobación admin directorio |
| `bettercap` | Framework multi-propósito ataques L2 (ARP spoofing, MITM, inyección) | **Crítico** - Ataques activos red, ilegal sin autorización | ✅ Aprobación ejecutiva + legal |
| `scapy` (pasivo) | Sniffing pasivo de paquetes para etiquetas VLAN 802.1Q | **Bajo** - Solo pasivo (sin inyección) | ⚠️ Requiere modo promiscuo (root) |

### Mejores Prácticas para Características Red Team

1. **Documentar Autorización**: Obtener aprobación escrita antes de usar flags `--redteam`
2. **Limitar Alcance**: Usar `--redteam-max-targets` para restringir número de hosts sondeados
3. **Evitar Horas Producción**: Programar recon activo durante ventanas de mantenimiento
4. **Monitorear Impacto**: Vigilar congestión red o degradación servicios
5. **Deshabilitar bettercap**: A menos que sea absolutamente necesario, evitar `--redteam-active-l2` (habilita ataques L2 potencialmente destructivos)

## 12. Seguridad en Dashboard HTML y Webhooks (v3.3+)

### Reportes HTML (`--html-report`)

- **Seguro Offline/Air-gap**: Los reportes HTML generados son totalmente autocontenidos. Todo el CSS (Bootstrap) y lógica JS (Chart.js) está embebido directamente en el archivo. No se realizan peticiones externas al abrir el reporte, haciéndolo seguro para estaciones de análisis aisladas (air-gapped).
- **Sin Rastreo Remoto**: No se incluyen analíticas ni píxeles de seguimiento.

### Alertas Webhook (`--webhook`)

- **Transmisión de Datos Sensibles**: Esta función envía detalles del hallazgo (IP Objetivo, Título Vulnerabilidad, Severidad) a la URL configurada.
- **HTTPS Requerido**: Usa siempre URLs de webhook `https://` para proteger estos datos en tránsito.
- **Verificación**: Asegúrate de que la URL del webhook es correcta y confiable (ej: tu instancia interna de Slack/Teams) para evitar filtrar datos de vulnerabilidades a terceros.

## 13. Licencia

Este modelo de seguridad es parte del proyecto RedAudit y está cubierto por la
**GNU General Public License v3.0 (GPLv3)**. Consulta [LICENSE](../../LICENSE) para el texto completo.
