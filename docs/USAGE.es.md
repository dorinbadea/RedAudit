# Guía de Uso de RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](USAGE.en.md)

**Audiencia:** Pentesters, Operadores de Seguridad, Blue Teamers
**Alcance:** Opciones CLI, ejemplos de uso, configuración, opciones de ejecución
**Qué NO cubre este documento:** Teoría de redes, desarrollo de exploits
**Fuente de verdad:** `redaudit --help`

---

## 1. Inicio Rápido

Ejecuta estos comandos para comenzar de inmediato.

### Asistente Interactivo (Recomendado para primera vez)

Navegación paso a paso con opción "< Volver" (v4.0.1+). La configuración de webhooks y opciones de descubrimiento está disponible en el asistente; las exportaciones SIEM se generan automáticamente cuando el cifrado está desactivado. La Fase 0 de bajo impacto puede activarse desde el asistente (por defecto desactivada) o con `--low-impact-enrichment`.

```bash
sudo redaudit
```

### Inventario rápido (LAN)

```bash
sudo redaudit -t 192.168.1.0/24 -m fast --yes
```

### Auditoría Estándar (Host Único)

```bash
sudo redaudit -t 10.10.10.5 -m normal --html-report
```

### Descubrimiento de Gateways VPN

Escanea una red para identificar interfaces VPN y endpoints virtuales:

```bash
sudo redaudit -t 10.0.0.0/24 --mode full --yes
# Ver resultados de assets VPN
cat redaudit_*.json | jq '.hosts[] | select(.asset_type == "vpn")'
```

---

## 2. Ejemplos por Escenario

### Lab / CTF (Agresivo)

Enfoque en velocidad y máxima recolección de información.

```bash
sudo redaudit -t 192.168.56.101 \
  --mode full \
  --udp-mode full \
  --threads 16 \
  --no-prevent-sleep
```

**Artefactos:** JSON/TXT, HTML opcional, PCAP (deep scan + tcpdump), playbooks (si hay categorías compatibles y sin cifrado).

### Escaneo Sigiloso (Modo Red Team)

Enfoque en bajo ruido, artefactos fiables y cifrado para cadena de custodia.

```bash
sudo redaudit -t 10.20.0.0/24 \
  --stealth \
  --encrypt \
  --encrypt-password "ProyectoCliente2025!"
```

**Notas:** `stealth` fuerza timing T1 y retardo de 5s. El cifrado deshabilita HTML/JSONL/playbooks/manifest.

### Blue Team / NetOps (Descubrimiento)

Enfoque en identificar dispositivos no autorizados y fugas de red.

```bash
sudo redaudit -t 172.16.0.0/16 \
  --mode fast \
  --net-discovery arp,mdns,upnp \
  --topology \
  --allow-non-root
```

**Notas:** `allow-non-root` ejecuta en modo limitado; la detección de SO, los escaneos UDP y la captura con tcpdump pueden fallar.

### Red Team (Reconocimiento Interno)

Enfoque en Active Directory, enumeración Kerberos y SNMP desde punto de pivote.

```bash
sudo redaudit -t 10.0.0.0/8 \
  --proxy socks5://127.0.0.1:1080 \
  --redteam \
  --redteam-active-l2 \
  --kerberos-realm CORP.LOCAL
```

**Riesgos:** `redteam-active-l2` usa sondeo activo (bettercap/scapy) que puede disparar IDS.

### Pipeline CI/CD (Verificación de Cambios)

Análisis diferencial entre dos escaneos previos.

```bash
redaudit --diff reports/report_v1.json reports/report_v2.json
```

**Salida:** Análisis delta mostrando puertos Nuevos/Abiertos/Cerrados/Cambiados. No se realiza escaneo.

---

## 3. Referencia de Flags CLI

Agrupadas por función operativa. Verificadas contra el estado actual del código.

### Alcance e Intensidad

| Flag | Descripción |
| :--- | :--- |
| `-t, --target CIDR` | IP, rango o CIDR (soporta lista separada por comas) |
| `-m, --mode` | `fast` (descubrimiento de hosts), `normal` (top 100), `full` (todos los puertos + scripts/detección de SO) |
| `-j, --threads N` | Hosts paralelos 1-16 (autodetectado) |
| `--rate-limit S` | Retardo entre hosts en segundos (aplica jitter) |
| `--deep-scan-budget N` | Máximo de hosts elegibles para deep scan agresivo (0 = sin límite) |
| `--identity-threshold N` | Umbral mínimo de identidad para omitir deep scan |
| `--stealth` | Fuerza timing T1, 1 hilo, 5s retardo |
| `--dry-run` | Muestra comandos sin ejecutarlos |

### Conectividad y Proxy

| Flag | Descripción |
| :--- | :--- |
| `--proxy URL` | Proxy SOCKS5 (socks5://host:port) |
| `--ipv6` | Activa modo escaneo solo IPv6 |
| `--no-prevent-sleep` | No inhibir suspensión del sistema |

### Descubrimiento Avanzado

| Flag | Descripción |
| :--- | :--- |
| `--net-discovery` | Protocolos broadcast (dhcp,netbios,mdns,upnp,arp,fping) |
| `--topology` | Mapeo de topología L2/L3 (rutas/gateways) |
| `--udp-mode` | `quick` (puertos prioritarios) o `full` (top ports) |
| `--redteam` | Añade técnicas de recon AD/Kerberos/SNMP |
| `--redteam-active-l2` | Habilita sondeo activo L2 más ruidoso |
| `--agentless-verify` | Verificación sin agente (SMB/RDP/LDAP/SSH/HTTP) |
| `--no-agentless-verify` | Desactivar verificación sin agente (sobrescribe defaults) |
| `--agentless-verify-max-targets N` | Límite de objetivos para verificación (1-200, defecto: 20) |

### Reportes e Integración

| Flag | Descripción |
| :--- | :--- |
| `-o, --output DIR` | Directorio de salida personalizado |
| `--html-report` | Generar dashboard interactivo (HTML) |
| `--webhook URL` | Enviar alertas webhook (JSON) para hallazgos high/critical |
| `--nuclei` | Habilitar escaneo de plantillas con Nuclei (requiere `nuclei`; solo en modo full) |
| `--no-nuclei` | Deshabilitar Nuclei (sobrescribe defaults persistentes) |
| `--no-vuln-scan` | Omitir escaneo de vulnerabilidades Web/Nikto |
| `--cve-lookup` | Correlar servicios con datos CVE NVD |

### Seguridad y Privacidad

| Flag | Descripción |
| :--- | :--- |
| `-e, --encrypt` | Cifrar todos los artefactos sensibles (AES-128) |
| `--allow-non-root` | Ejecutar sin sudo (capacidad limitada) |
| `--yes` | Auto-confirmar todos los prompts |

### Configuración

| Flag | Descripción |
| :--- | :--- |
| `--save-defaults` | Guardar argumentos CLI actuales en `~/.redaudit/config.json` |
| `--defaults {ask,use,ignore}` | Controlar cómo se aplican los defaults persistentes |
| `--use-defaults` | Cargar argumentos desde config.json automáticamente |
| `--ignore-defaults` | Forzar valores de fábrica |
| `--no-color` | Deshabilitar salida a color |
| `--skip-update-check` | Saltar comprobación de actualizaciones al inicio |
| `--lang` | Idioma de interfaz/informe (en/es) |

---

## 4. Salida y Rutas

**Ruta por Defecto:**
`<Documentos>/RedAuditReports/RedAudit_<TIMESTAMP>/` (usa la carpeta Documentos del usuario invocante)

Para cambiar la ruta por defecto permanentemente:

```bash
sudo redaudit --output /opt/redaudit/reports --save-defaults --yes
```

**Manifiesto de Artefactos:**

- **.json**: Modelo de datos completo (siempre creado).
- **.txt**: Resumen legible por humanos.
- **.html**: Dashboard (requiere `--html-report`, deshabilitado por `--encrypt`).
- **.jsonl**: Eventos streaming para SIEM (deshabilitado por `--encrypt`).
- **playbooks/*.md**: Guías de remediación (deshabilitado por `--encrypt`).
- **run_manifest.json**: Manifiesto de salida (deshabilitado por `--encrypt`).
- **.pcap**: Capturas de paquetes (solo si Deep Scan + tcpdump + Root).
- **session_*.log**: Salida de terminal raw con códigos de color (en `session_logs/`).
- **session_*.txt**: Salida de terminal en texto plano limpio (en `session_logs/`).

**Notas de Progreso/ETA:**

- `ETA≤` muestra el límite superior basado en timeouts para el lote actual.
- `ETA≈` es una estimación dinámica basada en hosts completados.

---

## 5. Errores Comunes

**`Permission denied` (socket error)**
RedAudit necesita root para:

- Detección de SO y algunos tipos de escaneo Nmap
- Escaneo UDP y sondas con raw sockets
- Generación de PCAP con `tcpdump`
**Solución:** Ejecutar con `sudo` o usar `--allow-non-root` (modo limitado).

**`nmap: command not found`**
Dependencias faltantes en el PATH.
**Solución:** Ejecutar `sudo bash redaudit_install.sh` o revisar `/usr/local/lib/redaudit`.

**`testssl.sh not found`**
Los checks TLS profundos se omiten en modo full.
**Solución:** Ejecutar `sudo bash redaudit_install.sh` para instalar el toolchain principal.

**`Decryption failed`**
Falta el archivo `.salt` o contraseña incorrecta.
**Solución:** Asegurar que el archivo `.salt` está en el mismo directorio que el `.enc`.

---

[Volver al README](../ES/README_ES.md) | [Índice de Documentación](INDEX.md)
