# Arquitectura de Seguridad y Hardening

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](SECURITY.en.md)

**Audiencia:** Compliance, SecOps
**Alcance:** Modelo de privilegios, especificaciones de cifrado, validación de inputs.
**Fuente de verdad:** `redaudit/core/crypto.py`, `redaudit/core/scanner/utils.py`, `redaudit/core/command_runner.py`

---

## Auditoría de Seguridad (Resumen)

- **Fecha Auditoría**: 2025-02-14
- **Cobertura**: ~93.03% (Alta confianza)
- **Estado**: Revisión interna best-effort. Sin vulnerabilidades críticas conocidas.
- **Ver**: [SECURITY_AUDIT_ES.md](../ES/SECURITY_AUDIT_ES.md) para detalles completos.

## Visión General

RedAudit implementa una filosofía de "seguro por diseño", asumiendo la ejecución en entornos hostiles o no confiables. Este documento describe los controles de seguridad relacionados con el manejo de entrada, criptografía y seguridad operacional.

### Notificación de vulnerabilidades

**Por favor, no divulgues vulnerabilidades de seguridad mediante issues públicas de GitHub.**

Si descubres una vulnerabilidad de seguridad en RedAudit, notifícala de forma responsable:

1. **Email**: Envía los detalles a `dorinidtech@gmail.com`
2. **Incluye**:
   - Descripción de la vulnerabilidad
   - Pasos para reproducirla
   - Impacto potencial
   - Propuesta de corrección (si está disponible)
3. **Tiempo de respuesta**: Normalmente confirmamos la recepción en 48 horas laborables
4. **Divulgación**: Seguimos divulgación responsable - coordinaremos contigo el momento de divulgación pública

## Versiones soportadas

| Versión | Soportada | Estado |
| 4.6.x | Sí | Estable actual |
| 4.5.x | Sí | Soportada |
| 4.4.x | Sí | Soportada |
| 4.3.x | Sí | Soportada |
| 4.2.x | Sí | Soportada |
| 3.9.x | Sí | Soportada |
| 3.8.x | Sí | Soportada |
| 3.7.x | Sí | Soportada |
| 3.6.x | Solo correcciones de seguridad | Mantenimiento |
| 3.5.x | Solo correcciones de seguridad | EOL: Junio 2026 |
| < 3.5 | No | EOL |

## 1. Sanitización de Entrada

Todas las entradas externas—rangos objetivo, nombres de host, nombres de interfaz—se tratan como no confiables y se someten a validación estricta.

- **Tipado Estricto**: Solo se aceptan tipos `str` para parámetros críticos.
- **Validación de Direcciones IP**: Usa el módulo `ipaddress` de Python para validar direcciones IPv4 e IPv6. Las IPs inválidas devuelven `None`.
- **Validación de Nombres de Host**: Allowlisting con regex (`^[a-zA-Z0-9\.\-]+$`) asegura solo caracteres alfanuméricos, puntos y guiones.
- **Límites de Longitud**: Todas las entradas se truncan a `MAX_INPUT_LENGTH` (1024 caracteres) para prevenir ataques basados en buffer.
- **Prevención de Inyección de Comandos**: Los comandos externos se ejecutan mediante `CommandRunner` usando listas de argumentos (nunca se usa expansión de shell).
- **Ubicación del Módulo**: `redaudit/core/scanner/utils.py` (`sanitize_ip`, `sanitize_hostname`)

## 2. Implementación Criptográfica

El cifrado de informes se gestiona mediante la librería `cryptography` para asegurar la confidencialidad de los resultados de auditoría.

- **Primitiva**: AES-128-CBC (especificación Fernet).
- **Gestión de Claves**: Las claves se derivan de contraseñas proporcionadas por el usuario usando PBKDF2HMAC-SHA256 con 480,000 iteraciones y un salt aleatorio por sesión.
- **Integridad**: Fernet incluye una firma HMAC para prevenir la manipulación del texto cifrado.
- **Política de contraseña**: El prompt interactivo exige 12+ caracteres con complejidad; `--encrypt-password` no se valida.
- **Ubicación del Módulo**: `redaudit/core/crypto.py`

## 3. Seguridad Operacional (OpSec)

- **Permisos de Artefactos**: RedAudit aplica `0o600` (lectura/escritura solo para el propietario) a los artefactos generados (informes, HTML/playbooks, vistas JSONL/JSON, evidencia externalizada) para reducir filtraciones a otros usuarios del sistema.
- **Seguridad en Modo Cifrado**: Si el cifrado de informes está activado, RedAudit evita generar artefactos adicionales en texto plano (HTML/JSONL/playbooks/resumen/manifiestos y evidencia externalizada) junto a informes `.enc`.
- **Rate-Limiting con Jitter**: Limitación de velocidad configurable con varianza aleatoria ±30% para reducir predictibilidad en entornos sensibles a IDS.
- **Descubrimiento HyperScan**: Descubrimiento TCP/UDP/ARP asíncrono puede reducir invocaciones de nmap cuando está habilitado (net discovery).
- **Heartbeat**: Monitoreo en segundo plano asegura la integridad del proceso sin requerir acceso interactivo a la shell.
- **Seguridad del Archivo de Credenciales**: El archivo de credenciales universales (ej. `~/.redaudit/credentials.json`) se valida estrictamente. DEBE tener permisos `0600` (lectura/escritura solo propietario); de lo contrario, RedAudit rechaza cargarlo (v4.5.2+).
- **Ubicación del Módulo**: `redaudit/core/reporter.py` (permisos), `redaudit/core/auditor.py` (heartbeat, jitter), `redaudit/core/hyperscan.py` (descubrimiento asíncrono), `redaudit/core/credentials_manager.py` (validación de secretos)

## 4. Pista de Auditoría

Todas las operaciones se registran en `~/.redaudit/logs/` con políticas de rotación (máx 10MB, 5 backups). Los logs contienen marcas de tiempo de ejecución, identificadores de hilos e invocaciones de comandos raw para rendición de cuentas.

**Seguridad de Captura de Sesión (v3.7+)**: El directorio `session_logs/` contiene la salida raw de terminal (`session_*.log`) que puede incluir datos sensibles mostrados durante el escaneo. Los permisos dependen del directorio de salida y del umask del usuario; trata estos logs como artefactos sensibles.

## 5. Seguridad CI/CD

Controles de seguridad automatizados integrados en el pipeline de desarrollo:

- **Bandit**: Linting de seguridad estático para código Python en cada push/PR
- **CodeQL**: Análisis estático de vulnerabilidades de seguridad en cada push/PR
- **Testing Multi-versión**: Compatibilidad verificada en Python 3.9-3.12

## 6. Arquitectura Modular

El código está organizado en módulos enfocados para mejorar la mantenibilidad y auditabilidad:

- **Módulos core** (`redaudit/core/`): Funcionalidad crítica de seguridad
- **Utilidades** (`redaudit/utils/`): Constantes e internacionalización
- **Tests**: La suite automatizada se ejecuta en GitHub Actions (`.github/workflows/tests.yml`) en Python 3.9–3.12.

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
- **Prioridad**: El flag CLI sobrescribe; si no, archivo de configuración o `NVD_API_KEY`
- **Sin texto plano en logs**: Las claves API nunca se escriben en archivos de log
- **Escrituras atómicas**: Las actualizaciones de configuración usan archivo temporal + renombrar para seguridad ante fallos

Los usuarios deben tratar el archivo de configuración como sensible. La clave API otorga límites de velocidad incrementados pero no proporciona acceso a datos privados.

## 9. Limitaciones conocidas

- **Requiere root/sudo**: Necesario para sockets raw (nmap, tcpdump)
- **Sin sandboxing**: Las herramientas externas se ejecutan con privilegios del sistema
- **Alcance del proxy**: `--proxy` depende de `proxychains4` y solo envuelve tráfico TCP (connect); UDP/ARP/ICMP y escaneos raw no se proxifican
- **Huella de red**: Los escaneos generan tráfico significativo
- **Recon opcional**: `--net-discovery` / `--redteam` pueden invocar tooling broadcast/L2 adicional (best-effort; solo con autorización explícita)
- **Escaneo de apps selectivo**: sqlmap/ZAP se omiten en UIs de infraestructura cuando la evidencia de identidad indica router/switch/AP

## 10. Seguridad en Red Team y Reconocimiento Activo

RedAudit v3.2 introduce capacidades de **Reconocimiento Activo** (`--redteam`, `--net-discovery`) que difieren del escaneo estándar:

- **Difusión**: Estos modos envían paquetes L2 broadcast/multicast (ARP, mDNS, NetBIOS).
- **Sondeo**: Ocurre interacción activa con servicios (SNMP, SMB, Kerberos) si se detectan.
- **Trazabilidad**: A diferencia de la escucha pasiva, estas acciones **generarán logs** en los sistemas objetivo y pueden activar reglas IDS/IPS.
- **Autorización**: Asegúrese de tener permiso explícito para descubrimiento interno **activo**, no solo para escaneo de vulnerabilidades externo.

### Advertencias Específicas por Herramienta

| Herramienta | Capacidad | Nivel de Riesgo | Autorización Requerida |
| :--- | :--- | :--- | :--- |
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

## 11. Seguridad en Dashboard HTML y Webhooks (v3.3+)

### Informes HTML (`--html-report`)

- **Offline/Air-gap**: El informe embebe el CSS, pero las gráficas cargan Chart.js desde un CDN. En entornos aislados el HTML abre; las gráficas pueden no renderizar sin esa dependencia.
- **Sin Rastreo Remoto**: No se incluyen analíticas ni píxeles de seguimiento.

### Alertas Webhook (`--webhook`)

- **Transmisión de Datos Sensibles**: Esta función envía detalles del hallazgo (IP Objetivo, Título Vulnerabilidad, Severidad) a la URL configurada.
- **HTTPS Requerido**: Usa siempre URLs de webhook `https://` para proteger estos datos en tránsito.
- **Verificación**: Asegúrate de que la URL del webhook es correcta y confiable (ej: tu instancia interna de Slack/Teams) para evitar filtrar datos de vulnerabilidades a terceros.

## 12. Licencia

Este modelo de seguridad es parte del proyecto RedAudit y está cubierto por la
**GNU General Public License v3.0 (GPLv3)**. Consulta [LICENSE](../../LICENSE) para el texto completo.
