# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](ROADMAP.en.md)

**Audiencia:** Colaboradores, responsables
**Alcance:** Funcionalidades planificadas, capacidades verificadas y conceptos descartados.
**Fuente de verdad:** Estado del código en el repositorio y el historial Git

---

Este documento describe el roadmap técnico, verifica las capacidades ya implementadas y registra los enfoques descartados para RedAudit.

## 1. Roadmap Activo (Futuro y En Progreso)

Estos elementos representan el backlog actual de trabajo planificado o aplazado.

### v4.7 Seguimiento de Auditoria (Prioridad: Alta)

| Caracteristica | Estado | Descripcion |
| :--- | :--- | :--- |
| **Contadores de motivos de escalado** | Planificado | Reportar por que se disparo el deep scan (identity score, ambiguedad, override manual). |
| **Aclaracion documental de Smart-Check** | Planificado | Alinear la documentacion con el comportamiento real de verificacion por senales. |

### v4.7 Seguimiento de Auditoria (Prioridad: Media)

| Caracteristica | Estado | Descripcion |
| :--- | :--- | :--- |
| **Abort Budget para Hosts Muertos** | Planificado | Limite configurable de tiempo/intentos para hosts que no responden. Evita cuelgues en hosts inalcanzables. |
| **Deteccion de Honeypots** | Planificado | Heuristica para detectar hosts que responden a todos los puertos (caracteristica de honeypots). Marcar como sospechoso y limitar escaneo. |
| **Modo de pinning de dependencias** | Planificado | Opcional: tags/commits fijados para herramientas externas instaladas desde git. |
| **Diagrama de transiciones de fase** | Planificado | Diagrama conciso de la logica de escalado en fases 1-3. |
| **Etiquetado de no-respuesta** | Planificado | Distinguir errores transitorios de hosts silenciosos en informes. |

### v4.7 Seguimiento de Auditoría (Aplazado)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Refactor de auditor.py** | Aplazado | Separar orquestación y lógica de decisión solo si desbloquea tests o corrige fallos. |

### Fase 7: Pulido UX y Cosméticos (Prioridad: Baja)

Mejoras menores identificadas durante la validación Gold Master de v4.4.0.

| Tarea | Estado | Descripción |
| :--- | :--- | :--- |
| **P7.3 Informe JSON en Streaming** | Planificado | Escritura incremental para informes >500MB en redes muy grandes. |

### Infraestructura (Prioridad: Baja)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Distribución PyPI** | Aplazado | Publicar `pip install redaudit`. Bloqueado por necesidad de testing multiplataforma extensivo. |
| **Motor de Plugins** | Aplazado | Arquitectura "Plugin-first" para desacoplar el escáner core de las herramientas. |
| **Migración AsyncIO** | Aplazado | Migración completa a AsyncIO aplazada a v5.0 tras estudio de viabilidad. |

---

### Funcionalidades Futuras (v5.0.0)

| Característica | Descripción |
| :--- | :--- |
| **Sondas IoT Específicas** | Consultas profundas para protocolos específicos (Tuya, CoAP, propietarios). |
| **Seguimiento de Fugas (Leak Following)** | Expansión automatizada del alcance basada en cabeceras internas filtradas. |
| **Auditoría de Pipeline** | Visualización del flujo de descubrimiento (net_discovery -> hyperscan -> smart_scan). |

---

## 2. Hitos Completados (Histórico)

Estos elementos están ordenados cronológicamente (el más reciente primero).

### v4.11 Rendimiento y Visibilidad IoT (Hecho)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Perfiles de Escaneo Nuclei** | Hecho (v4.11.0) | Flag `--profile` (full/balanced/fast) para controlar intensidad y velocidad. |
| **Detección IoT WiZ** | Hecho (v4.11.0) | Sonda UDP especializada (38899) para bombillas inteligentes WiZ. |
| **Expansión Base de Datos OUI** | Hecho (v4.11.0) | Actualización de MACs a ~39k fabricantes (ingesta Wireshark). |
| **Optimización Lotes Nuclei** | Hecho (v4.11.0) | Reducción de lote (10) y aumento de timeouts (600s) para redes densas. |

### v4.10 Descubrimiento Avanzado (Hecho)

| Caracteristica | Estado | Descripcion |
| :--- | :--- | :--- |
| **Query SNMP a Router** | Hecho (v4.10.0) | Consultar interfaces del router y tablas ARP remotas via `snmpwalk`. |
| **Descubrimiento LLDP** | Hecho (v4.10.0) | Topologia de switches en redes gestionadas via `lldpctl`. |
| **Descubrimiento CDP** | Hecho (v4.10.0) | Parseo de Cisco Discovery Protocol para topologias Cisco. |
| **Deteccion VLAN Tagging** | Hecho (v4.10.0) | Detectar VLANs taggeadas 802.1Q en las interfaces del host auditor vía `ifconfig`/`ip link`. |

### v4.9 Deteccion de Redes Ocultas (Hecho)

| Caracteristica | Estado | Descripcion |
| :--- | :--- | :--- |
| **Descubrimiento de Redes Enrutadas** | Hecho (v4.9.0) | Detectar redes ocultas via parsing de `ip route` y `ip neigh`. |
| **Prompt Interactivo de Descubrimiento** | Hecho (v4.9.0) | El wizard pregunta si incluir redes enrutadas descubiertas en el alcance. |
| **CLI --scan-routed** | Hecho (v4.9.0) | Inclusion automatica de redes enrutadas para pipelines CI/CD. |
| **Visibilidad Puertos UDP IoT** | Hecho (v4.9.1) | Asegurar que puertos UDP especializados (ej. WiZ 38899) hallados por HyperScan se incluyan en reportes. |
| **Deteccion de Honeypot** | Hecho (v4.9.1) | Etiquetado heuristico (`honeypot`) para hosts con excesivos puertos abiertos (>100). |
| **Etiquetado Sin Respuesta** | Hecho (v4.9.1) | Etiqueta `no_response` distintiva para hosts que fallan en Nmap. |

### v4.8 RustScan y Correcciones Instalador (Hecho)

| Caracteristica | Estado | Descripcion |
| :--- | :--- | :--- |
| **RustScan Rango Completo** | Hecho (v4.8.2) | Forzar `-r 1-65535` para escanear todos los puertos en vez del top 1000 por defecto. |
| **Soporte ARM64 Instalador** | Hecho (v4.8.3) | Deteccion ARM64/aarch64 para Raspberry Pi y VMs Apple Silicon. |
| **Toggle Nuclei en Wizard** | Hecho (v4.8.1) | Restaurar prompt interactivo para activar Nuclei en perfil Exhaustivo. |

### v4.7 Integracion HyperScan Masscan (Hecho)

| Caracteristica | Estado | Descripcion |
| :--- | :--- | :--- |
| **Backend Masscan** | Reemplazado (v4.8.0) | `masscan_scanner.py` reemplazado por `RustScan` para mayor velocidad y precision. |
| **Integracion RustScan** | Hecho (v4.8.0) | Nuevo modulo primario para HyperScan. Escaneo de todos los puertos en ~3s. |
| **Fallback Redes Docker** | Hecho (v4.7.1) | Fallback automatico a Scapy cuando Masscan retorna 0 puertos (redes bridge Docker). |
| **Fix Timeout Nuclei** | Hecho (v4.7.2) | Timeout de command_runner aumentado a 600s para Nuclei (era 60s, causando timeouts de batch). |
| **Skip 404 API NVD** | Hecho (v4.7.2) | Omitir reintentos en respuestas 404 (CPE no encontrado). Reduce spam de logs. |

### v4.6 Fidelidad de Escaneo y Control de Tiempo (Hecho)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Gating de Apps Web por Infraestructura** | Hecho | Omitir sqlmap/ZAP en UIs de infraestructura cuando la evidencia de identidad indica router/switch/AP. |
| **Evidencia de Identidad en Deep Scan** | Hecho | Título/servidor HTTP y tipo de dispositivo evitan deep scan cuando la identidad ya es fuerte. |
| **Sonda HTTP Rápida de Identidad** | Hecho | Sonda HTTP/HTTPS breve en hosts silenciosos para resolver identidad antes. |
| **Informe Parcial de Nuclei** | Hecho | Marcar ejecuciones parciales y registrar lotes con timeout/fallidos en el informe. |
| **Latido por Batch de Nuclei** | Hecho (v4.6.11) | Mantener actualizaciones de progreso durante lotes largos para mostrar actividad y tiempo transcurrido. |
| **Progreso por Objetivos de Nuclei** | Hecho (v4.6.13) | Mostrar avance basado en objetivos dentro de cada batch para evitar barras congeladas. |
| **Estabilidad del progreso de Nuclei** | Hecho (v4.6.15) | Mantener el avance de objetivos sin retrocesos durante reintentos/timeouts. |
| **Endurecimiento de timeouts Nuclei** | Hecho (v4.6.16) | Timeouts adaptativos por lote y divisiones recursivas para reducir ejecuciones parciales. |
| **Contexto de keyring con sudo** | Hecho (v4.6.17) | Preservar el contexto de DBus al cargar credenciales guardadas bajo sudo. |
| **Alineación de informes de hosts** | Hecho (v4.6.15) | Rellenar hosts con nombres/interfaces unificados para consistencia. |
| **Guardia de Origen de Identidad HTTP** | Hecho (v4.6.11) | Tratar títulos solo UPnP como pistas y evitar forzar escaneo web o score de identidad. |
| **Resumen de normalización de objetivos en el wizard** | Hecho (v4.6.13) | Mostrar objetivos normalizados con hosts estimados antes de ejecutar. |
| **Spray de Credenciales SSH** | Hecho (v4.6.18) | Probar todas las credenciales de la lista spray hasta autenticar. |
| **Priorización de Hallazgos** | Hecho (v4.6.19) | Nuevos campos `priority_score` (0-100) y `confirmed_exploitable` para ranking superior de vulnerabilidades. |
| **Detección Clásica de Backdoors** | Hecho (v4.6.19) | Detección automática en banner de `vsftpd 2.3.4`, `UnrealIRCd 3.2.8.1` y otros backdoors. |
| **Puntuación de Confianza de Reporte** | Hecho (v4.6.19) | Score de confianza (`confidence_score` 0.0-1.0) basado en validación cruzada (Nuclei+CVE). |
| **Mejora de Títulos de Hallazgos** | Hecho (v4.6.19) | Títulos más descriptivos ("SSL Hostname Mismatch") en lugar de genéricos. |
| **Contador de Spray en Wizard** | Hecho (v4.6.19) | Visualización `(+N spray)` en el resumen de credenciales guardadas para mayor claridad. |

### v4.4 Cobertura de Código y Estabilidad (Hecho)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Cobertura Topology 100%** | Hecho (v4.4.5) | Alcanzada cobertura completa de tests para `topology.py`. |
| **Cobertura Updater >94%** | Hecho (v4.4.5) | Endurecido `updater.py` con tests robustos. |
| **Cobertura Proyecto ~89%** | Hecho (v4.4.5) | Cobertura total del proyecto ahora en 88.75% (1619 tests pasando). |
| **Corrección Memory Leak** | Hecho (v4.4.5) | Corregido bucle infinito en mocks de tests. |
| **Targeting basado en Generadores** | Hecho (v4.4.0) | Refactorizado HyperScan para usar generadores lazy. |
| **Informe JSON en Streaming** | Hecho | Optimizado `auditor_scan.py` para evitar materializar listas. |
| **Smart-Throttle (AIMD)** | Hecho (v4.4.0) | Control de congestión adaptativo AIMD en HyperScan. |

### v4.3 Mejoras al Risk Score (Hecho)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Algoritmo Weighted Maximum Gravity** | Hecho | Refactorizado `calculate_risk_score()` usando CVSS de NVD. |
| **Risk Score Breakdown Tooltip** | Hecho | HTML reports show detailed risk score components on hover. |
| **Identity Score Visualization** | Hecho | HTML reports display color-coded identity_score with tooltip showing identity signals. |
| **Smart-Check CPE Validation** | Hecho | Enhanced Nuclei false positive detection using host CPE data. |
| **HyperScan SYN Mode** | Hecho | Optional scapy-based SYN scanning (`--hyperscan-mode syn`). |
| **PCAP Management Utilities** | Hecho | `merge_pcap_files()`, `organize_pcap_files()`, cleanup. |

### v4.2 Optimizaciones Pipeline (Liberado en m v4.2.0)

Ver [Release Notes](../releases/RELEASE_NOTES_v4.2.0.md) para detalles.

### v4.1 Optimizaciones de Rendimiento (Hecho)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **HyperScan-First Secuencial** | Hecho | Pre-escaneo de 65.535 puertos por host secuencialmente. |
| **Escaneo Vulns Paralelo** | Hecho | nikto/testssl/whatweb concurrentemente por host. |
| **Pre-filtrado Nikto CDN** | Hecho | Omitir Nikto en Cloudflare/Akamai/AWS CloudFront. |
| **Reutilización puertos masscan** | Hecho | Pre-scan usa puertos de masscan si ya estaban descubiertos. |
| **CVE Lookup reordenado** | Hecho | CVE correlation movido después de Vuln Scan + Nuclei. |

### v4.0 Refactorización Arquitectónica (Hecho)

Refactorización interna utilizando el patrón Strangler Fig. Completado en v4.0.0.

### Infraestructura (Prioridad: Alta)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Consolidación Suite Tests** | Hecho | Refactorizado 199 archivos → 123. 1130 tests al 85%. |

---

## 3. Referencia de Capacidades Verificadas

Referencia de verificación de capacidades clave contra la base de código.

| Capacidad | Versión | Ruta del Código / Verificación |
| :--- | :--- | :--- |
| **Descubrimiento LLDP Pasivo** | v4.10.0 | `core/topology.py` (vía `tcpdump` & `lldpctl`) |
| **Descubrimiento CDP Pasivo** | v4.10.0 | `core/topology.py` (vía `tcpdump`/CISCO-CDP) |
| **Etiquetado VLAN (802.1Q)** | v4.10.0 | `core/topology.py` (vía `ip link`/`ifconfig`) |
| **Sonda IoT WiZ (UDP)** | v4.11.0 | `core/udp_probe.py`, `core/auditor.py` |
| **Perfiles Nuclei** | v4.11.0 | `core/nuclei.py`, `core/auditor.py` |
| **Base de Datos OUI** | v4.11.0 | `data/manuf` (38k+ vendors) |
| **Descubrimiento Redes Enrutadas** | v4.9.0 | `core/net_discovery.py` (`ip route`/`ip neigh`) |
| **Integración RustScan** | v4.8.0 | `core/rustscan.py` |
| **Smart-Check** | v4.3.0 | `core/scanner/enrichment.py` (Lógica CPE/Falsos Positivos) |

---

## 4. Conceptos Descartados

Ideas consideradas pero rechazadas para mantener el foco del proyecto.

| Propuesta | Razón del Descarte |
| :--- | :--- |
| **GUI Web (Controlador)** | Incrementa superficie de ataque y peso. RedAudit es una herramienta CLI "headless". |
| **Framework de Explotación** | Fuera de alcance. RedAudit es para *auditoría*, no explotación (como Metasploit). |
| **Soporte Nativo Windows** | Demasiado complejo. Usar WSL2 o Docker. |
| **Generación Informe PDF** | Añade dependencias pesadas. Se prefiere salida JSON/HTML. |
| **Escaneo Distribuido** | Demasiado complejo (FastAPI/Redis). Arquitectura rechazada. |

---

## 5. Contribuir

1. Revisa [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Lee [CONTRIBUTING.md](../CONTRIBUTING.md).
3. Abre una Discusión antes de iniciar grandes funcionalidades.

[Volver al Índice de Documentación](INDEX.md)
