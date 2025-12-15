# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](ROADMAP.md)

Este documento describe el roadmap técnico, las mejoras arquitectónicas planificadas y los enfoques descartados para RedAudit.

## Roadmap Inmediato (v3.1+)

| Prioridad | Característica | Estado | Descripción |
| :--- | :--- | :--- | :--- |
| **Alta** | **Descubrimiento de Topología de Red** | ✅ Implementado (best-effort) | Descubrimiento de topología opcional (ARP/VLAN/LLDP + gateway/rutas) orientado a pistas de "redes ocultas" y contexto L2. |
| **Alta** | **Puertos UDP Configurables** | ✅ Implementado | Añadido flag CLI `--udp-ports N` (rango: 50-500, defecto: 100) para cobertura UDP ajustable en modo UDP full de identidad. |
| **Alta** | **Descubrimiento de Red Mejorado (v3.2)** | 🔄 EN PROGRESO | Descubrimiento activo de redes de invitados y VLANs vía protocolos broadcast. Módulo core implementado, Red Team pendiente. |
| **Media** | **Descubrimiento NetBIOS/mDNS** | ✅ Implementado (v3.2) | Consultas activas de hostname (puerto 137/5353) para mejorar resolución de entidades. |
| **Media** | **Contenedorización** | Aparcado | Dockerfile oficial y configuración Docker Compose para contenedores de auditoría efímeros. |
| **Baja** | **Ampliar Configuración Persistente** | ✅ Implementado (inicial) | Extendido `~/.redaudit/config.json` más allá de la clave NVD (defaults comunes: hilos/salida/rate-limit/UDP/topología/idioma). |

### Descubrimiento de Red Mejorado (Objetivo v3.2)

**Objetivo**: Detectar redes de invitados, VLANs ocultas y servidores DHCP adicionales no visibles desde el segmento de red principal.

**Progreso Actual (v3.2-dev)**:

- ✅ Módulo core: `redaudit/core/net_discovery.py`
- ✅ Flags CLI: `--net-discovery`, `--redteam`
- ✅ Descubrimiento DHCP vía nmap
- ✅ Sweep Fping
- ✅ Descubrimiento NetBIOS (nbtscan/nmap)
- ✅ Descubrimiento mDNS/Bonjour
- ✅ Descubrimiento de dispositivos UPNP
- ✅ Escaneo ARP Netdiscover
- ✅ Análisis de VLANs candidatas
- ✅ Red Team básico (v3.2): enumeración SNMP/SMB + sweep masscan con guardas

**Herramientas de Descubrimiento Estándar (Implementadas)**:

| Técnica | Herramienta | Estado |
| :--- | :--- | :--- |
| **Descubrimiento DHCP** | `nmap --script broadcast-dhcp-discover` | ✅ |
| **Descubrimiento NetBIOS** | `nbtscan` / `nmap --script nbstat` | ✅ |
| **mDNS/Bonjour** | `avahi-browse` / `nmap --script dns-service-discovery` | ✅ |
| **Netdiscover** | `netdiscover -r <rango> -P` | ✅ |
| **Sweep Fping** | `fping -a -g <rango>` | ✅ |
| **Descubrimiento UPNP** | `nmap --script broadcast-upnp-info` | ✅ |

**Técnicas Red Team / Pentesting (Planificadas/En Progreso)**:

| Técnica | Herramienta | Estado | Qué Detecta |
| :--- | :--- | :--- | :--- |
| **SNMP Walking** | `snmpwalk -v2c -c public <ip>` | ✅ Implementado (v3.2) | Mapeo de puertos de switch, asignaciones VLAN, tablas ARP |
| **Enumeración SMB** | `enum4linux -a <ip>` / `crackmapexec smb` | ✅ Implementado (v3.2) | Shares Windows, usuarios, políticas de contraseña, dominios |
| **Enumeración VLAN** | `yersinia -G` / `frogger` | 🔲 Planificado | IDs VLAN 802.1Q, negociación DTP, puertos trunk |
| **Topología STP** | `yersinia -I eth0 -G stp` | 🔲 Planificado | Root bridges Spanning Tree, topología de red |
| **Descubrimiento HSRP/VRRP** | `nmap --script broadcast-eigrp-discovery` | 🔲 Planificado | Redundancia de gateway, IPs virtuales, prioridades |
| **LLMNR/NBT-NS** | `responder --analyze` (modo pasivo) | 🔲 Planificado | Peticiones de resolución de nombres Windows (solo recon) |
| **Bettercap Recon** | `bettercap -eval "net.recon on"` | 🔲 Planificado | Descubrimiento de hosts, fingerprinting OS, análisis de tráfico |
| **Masscan** | `masscan -p1-65535 --rate 10000` | 🔄 Parcial (con guardas) | Descubrimiento de puertos ultra-rápido en rangos grandes |
| **Descubrimiento de Routers** | `nmap --script broadcast-igmp-discovery` | 🔲 Planificado | Routers multicast, IGMP snooping |
| **Descubrimiento IPv6** | `nmap -6 --script targets-ipv6-multicast-*` | 🔲 Planificado | Hosts IPv6 vía multicast (link-local) |
| **Scapy Custom** | Scripts Python Scapy | 🔲 Planificado | Paquetes 802.1Q personalizados, intentos de VLAN hopping |
| **Enumeración RPC** | `rpcclient -U "" <ip>` | 🔲 Planificado | Servicios RPC Windows, enumeración de usuarios |
| **Enumeración LDAP** | `ldapsearch` / `nmap --script ldap-*` | 🔲 Planificado | Info de Active Directory, usuarios, grupos |
| **Enumeración Kerberos** | `kerbrute` / `nmap --script krb5-enum-users` | 🔲 Planificado | Usuarios AD válidos, objetivos Kerberoasting |
| **Transferencia de Zona DNS** | `dig axfr @<dns> <dominio>` | 🔲 Planificado | Registros DNS internos, hostnames |
| **Web Fingerprint** | `whatweb` / `wappalyzer` | ✅ (scanner.py) | Tecnologías web, frameworks, versiones |
| **Análisis SSL/TLS** | `testssl.sh` | ✅ (scanner.py) | Problemas de certificados, debilidades de cifrado |

**Opciones CLI (Implementadas)**:

```bash
redaudit --net-discovery --target 192.168.0.0/16 --yes   # Descubrimiento broadcast completo
redaudit --net-discovery dhcp,netbios --target 10.0.0.0/8  # Solo protocolos específicos
redaudit --net-discovery --redteam --target 10.0.0.0/8   # Incluir técnicas Red Team (más lento, más ruido)
```

**Salida**: Nuevo bloque `net_discovery` en el reporte JSON con servidores detectados, redes de invitados, mapeos VLAN y observaciones cross-VLAN.

### Descubrimiento de Topología de Red (Objetivo v4.0)

**Objetivo**: Reconocimiento rápido pre-scan para mapear la arquitectura de red antes del escaneo profundo.

**Estado actual (v3.1+)**: Existe una implementación base best-effort (rutas/gateway por defecto, ARP scan, pistas de VLAN, LLDP/CDP best-effort). v4.0 amplía esto con descubrimiento activo más rico (scripts broadcast de nmap, mapeo por traceroute, etc.).

| Capacidad | Herramienta | Salida |
| :--- | :--- | :--- |
| **Descubrimiento L2** | `arp-scan --localnet` | Direcciones MAC + vendor OUI |
| **Detección de VLAN** | `nmap --script broadcast-dhcp-discover,broadcast-arp` | IDs de VLAN, servidores DHCP |
| **Mapeo de Gateway** | `traceroute` + análisis de ICMP redirect | Rutas de routers, detección NAT |
| **Topología L2** | Parsing CDP/LLDP via `tcpdump -nn -v -c 50 ether proto 0x88cc` | Relaciones switch/puerto |
| **Redes Ocultas** | Detección de anomalías ARP + análisis de tabla de rutas | Subredes mal configuradas |

**Opciones CLI**:

```bash
redaudit --topology-only --target 192.168.0.0/16 --yes  # Solo topología (sin escaneo de hosts)
redaudit --topology --target 10.0.0.0/8 --yes           # Integrado con auditoría completa
```

## Propuestas Arquitectónicas

### 1. Motor de Plugins Modular

**Estado**: En Consideración
**Concepto**: Desacoplar el escáner principal de las herramientas. Permitir "Plugins" basados en Python para definir nuevos wrappers de herramientas sin modificar la lógica central.
**Beneficio**: Facilita contribución de la comunidad y extensibilidad.

**Nota**: La arquitectura "plugin-first" está aparcada por ahora; la prioridad es estabilidad y coherencia del core.

### 2. Escaneo Distribuido (Coordinador/Workers)

**Estado**: Largo plazo
**Concepto**: Separar el Orquestador de los workers de verificación.

- API Central (Coordinador) distribuye objetivos.
- Workers remotos (Nodos) ejecutan escaneos y devuelven JSON.

### 3. Configuración Persistente

**Estado**: Planificado
**Concepto**: Ampliar la configuración de usuario en `~/.redaudit/config.json` para anular valores por defecto (eliminando la necesidad de flags CLI repetitivos). Opcionalmente añadir importación/exportación YAML por comodidad.

## Hitos Completados

### v3.1.4 (Completado - Diciembre 2025) -> **ACTUAL**

*Patch centrado en mejoras de calidad de salida para máximo scoring SIEM/IA.*

- [x] **Títulos descriptivos de hallazgos**: Títulos legibles basados en tipo (ej: "Cabecera X-Frame-Options Faltante" en vez de "Hallazgo en URL").
- [x] **Cross-validación Nikto**: `detect_nikto_false_positives()` compara hallazgos con cabeceras curl/wget para detectar contradicciones.
- [x] **Ajuste severidad RFC-1918**: Divulgación de IP interna en redes privadas ahora correctamente calificada como severidad "low".
- [x] **Extracción de fingerprint OS**: Nueva función `extract_os_detection()` para info OS estructurada desde salida Nmap.
- [x] **Rutas PCAP relativas**: Los reportes usan rutas relativas portables para archivos PCAP.
- [x] **Timeout TestSSL configurable**: Por defecto aumentado de 60s a 90s con parámetro configurable.
- [x] **Constante de versión de schema**: Constante `SCHEMA_VERSION` separada para claridad de versionado de reportes.

### v3.1.3 (Completado - Diciembre 2025)

*Patch centrado en mejoras de rendimiento con asyncio.*

- [x] **Sondeo UDP asíncrono**: Sondeo concurrente rápido de puertos UDP prioritarios durante deep scan.
- [x] **Topología asíncrona**: Recolección de comandos en paralelo (ARP/VLAN/LLDP + gateway).

### v3.1.2 (Completado - Diciembre 2025)

*Patch centrado en mejoras de UX del auto-update.*

- [x] **Notas de update CLI-friendly**: Renderizado amigable para terminal (sin ruido Markdown).
- [x] **Reinicio fiable**: Reinicio PATH-aware con instrucciones de fallback claras.
- [x] **Prompts más claros**: Presets UDP, clarificación topology-only, confirmación save-defaults.

### v3.1.1 (Completado - Diciembre 2025)

*Patch centrado en descubrimiento de topología, defaults persistentes y cobertura UDP configurable.*

- [x] **Descubrimiento de topología (best-effort)**: Mapping ARP/VLAN/LLDP + gateway/rutas (`--topology`, `--topology-only`).
- [x] **Defaults persistentes**: Guardado de ajustes comunes en `~/.redaudit/config.json` (`--save-defaults`).
- [x] **Cobertura UDP configurable**: `--udp-ports N` para ajustar la cobertura del UDP full de identidad.
- [x] **Docs y tests alineados**: Manuales, esquema y tests unitarios actualizados.

### v3.1.0 (Completado - Diciembre 2025)

*Release centrada en integraciones SIEM y exportaciones para pipelines de IA.*

- [x] **Exportaciones JSONL**: `findings.jsonl`, `assets.jsonl`, `summary.json` para ingesta plana.
- [x] **IDs determinísticos de hallazgo**: `finding_id` para correlación y deduplicación entre escaneos.
- [x] **Categorización de hallazgos**: surface/misconfig/crypto/auth/info-leak/vuln.
- [x] **Severidad normalizada**: `normalized_severity` (0-10) + severidad original de herramienta preservada.
- [x] **Observaciones estructuradas**: Extracción de Nikto/TestSSL (con externalización de evidencia raw cuando aplica).
- [x] **Versiones de herramientas**: Proveniencia (`scanner_versions`).

### v3.0.4 (Completado - Diciembre 2025)

*Patch centrado en mejorar la claridad del límite de hosts en modo interactivo y alinear documentación.*

- [x] **Límite de hosts por defecto = todos**: El prompt interactivo escanea todos los hosts encontrados por defecto (ENTER = todos / all).
- [x] **Texto más claro**: Los números significan un límite máximo global de hosts (no un selector de host/IP).

### v3.0.3 (Completado - Diciembre 2025)

*Patch centrado en transparencia del auto-update y preservación de idioma.*

- [x] **Idioma preservado en actualización**: El auto-update mantiene el idioma instalado (ej: Español sigue en Español).
- [x] **Salida de update más explícita**: Muestra ref/commit objetivo, cambios de ficheros (+/~/-) y pasos claros de instalación/backup.

### v3.0.2 (Completado - Diciembre 2025)

*Patch centrado en pulido del CLI, claridad de reportes y correlación CVE más segura.*

- [x] **Salida CLI thread-safe**: Evita líneas intercaladas y cortes a mitad de palabra.
- [x] **Mejoras de UX en Español**: Traducciones completadas para mensajes de estado/progreso.
- [x] **Visibilidad de PCAP**: Resumen final muestra contador de PCAP; reporte TXT incluye la ruta del PCAP si se captura.
- [x] **Seguridad en enriquecimiento NVD**: Evita CPEs comodín cuando la versión es desconocida; corrige mensajes sobre el origen de la API key.

### v3.0.1 (Completado - Diciembre 2025)

*Patch centrado en configuración, endurecimiento de update e higiene documental.*

- [x] **API Key NVD Persistente**: Guardar/leer la clave NVD vía archivo de config + variable de entorno.
- [x] **Verificación del Updater**: El auto-update resuelve el tag publicado y verifica el hash del commit antes de instalar.
- [x] **Instalación testssl.sh fijada**: El instalador fija `testssl.sh` a un tag/commit conocido y lo verifica antes de enlazar.
- [x] **Resiliencia NVD**: Reintentos con backoff en errores transitorios (429/5xx/red).
- [x] **Modo limitado sin root**: `--allow-non-root` permite ejecutar sin sudo (capacidad limitada).

### v3.0.0 (Completado - Diciembre 2025)

*Lanzamiento mayor con capacidades avanzadas.*

- [x] **Soporte IPv6**: Capacidades completas de escaneo para redes IPv6.
- [x] **Validación Magic Bytes**: Detección mejorada de falsos positivos con verificación de firmas.
- [x] **Correlación CVE (NVD)**: Inteligencia profunda de vulnerabilidades via API NIST NVD con caché de 7 días.
- [x] **Análisis Diferencial**: Comparar dos reportes JSON para detectar cambios de red.
- [x] **Proxy Chains (SOCKS5)**: Soporte para pivoting via wrapper proxychains.
- [x] **Auto-Update Mejorado**: Enfoque git clone con verificación y copia a carpeta home.

### v2.9.0 (Completado - Diciembre 2025)

*Enfoque en inteligencia, eficiencia y documentación profesional.*

- [x] **Smart-Check**: Reducción del 90% de falsos positivos en escaneo web.
- [x] **UDP Taming**: Escaneos 50-80% más rápidos mediante estrategia de 3 fases optimizada.
- [x] **Entity Resolution**: Agrupación de dispositivos multi-interfaz (Unified Assets).
- [x] **SIEM Profesional**: Cumplimiento ECS v8.11 y puntuación de riesgo.
- [x] **Documentación Limpia**: Eliminación completa de etiquetas de versión antiguas.

### v2.7-v2.8 (Completado)

*Enfoque en concurrencia, seguridad e integración de herramientas externas.*

- [x] **Deep Scan Adaptativo**: Estrategia de 3 fases (TCP agresivo → UDP prioritario → UDP completo)
- [x] **Captura PCAP Concurrente**: Tráfico capturado durante escaneos profundos
- [x] **Auto-Actualización Segura**: Integración GitHub con reinicio automático
- [x] **Motor Pre-scan**: Descubrimiento rápido asyncio antes de nmap
- [x] **Inteligencia de Exploits**: Integración SearchSploit para versiones detectadas
- [x] **Análisis SSL/TLS**: Escaneo profundo TestSSL.sh
- [x] **Endurecimiento de Seguridad**: Requisitos de contraseña fuerte (12+ chars)
- [x] **Seguridad CI/CD**: Dependabot + análisis estático CodeQL
- [x] **Mejoras UX**: Barras de progreso rich con fallback elegante

### v2.6 (Completado)

*Enfoque en calidad de código, testing y modularización.*

- [x] **Arquitectura Modular**: Refactorizado en estructura de paquete Python
- [x] **Pipeline CI/CD**: GitHub Actions para testing automatizado (Python 3.9-3.12)
- [x] **Suite de Tests**: Ampliación de tests automatizados e introducción de reporting de cobertura en CI (reportado por CI, sin fijar números aquí)
- [x] **Constantes Nombradas**: Todos los números mágicos reemplazados
- [x] **Compatibilidad hacia atrás**: `redaudit.py` original preservado como wrapper

## Conceptos Descartados

| Propuesta | Razón del Descarte |
| :--- | :--- |
| **GUI Web (Controlador)** | Incrementa superficie de ataque y peso de dependencias. RedAudit está diseñado como herramienta CLI "headless" para automatización. |
| **Explotación Activa** | Fuera de alcance. RedAudit es una herramienta de *auditoría* y *descubrimiento*, no un framework de explotación. |
| **Soporte Nativo Windows** | Demasiado complejo de mantener en solitario por requisitos de sockets raw. Usar WSL2 o Docker. |
| **Generación PDF** | Añade dependencias pesadas (LaTeX/ReportLab). La salida JSON debe ser consumida por herramientas de reporte externas. |

---

## Contribuir

Si deseas contribuir a alguna de estas features:

1. Revisa los [Issues](https://github.com/dorinbadea/RedAudit/issues) existentes.
2. Comenta antes de empezar para evitar duplicación.
3. Lee [CONTRIBUTING.md](../.github/CONTRIBUTING.md).
4. Abre una [Discusión](https://github.com/dorinbadea/RedAudit/discussions) para nuevas ideas.

---

**Mantenimiento Activo** | *Última actualización: Diciembre 2025*

*Si este documento no se actualiza en >6 meses, el proyecto puede estar pausado. En ese caso, considera hacer un fork o contactarme.*
