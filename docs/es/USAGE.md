# Guía de Uso RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](../en/USAGE.md)

## Referencia CLI

RedAudit está diseñado para ejecución sin estado (stateless) vía argumentos de línea de comandos.

### Sintaxis

```bash
sudo redaudit [OPTIONS]
# O vía módulo Python (v2.6+)
sudo python -m redaudit [OPTIONS]
```

Nota: para modo limitado sin sudo/root, añade `--allow-non-root` (algunas funciones de escaneo pueden fallar u omitirse).

### Argumentos Principales

| Flag | Descripción |
| :--- | :--- |
| `-t`, `--target` | IP objetivo, subred (CIDR), o lista separada por comas. |
| `-m`, `--mode` | Intensidad: `fast` (descubrimiento), `normal` (puertos top), `full` (todos + scripts). |
| `-o`, `--output` | Especificar directorio de salida. Por defecto: `~/Documents/RedAuditReports`. |
| `--lang` | Idioma de interfaz: `en` (defecto), `es`. |
| `-y`, `--yes` | Saltar confirmación de advertencia legal (usar con precaución). |

### Rendimiento y Evasión

| Flag | Descripción |
| :--- | :--- |
| `-j`, `--threads <N>` | Tamaño del pool de hilos para escaneo concurrente (1-16, defecto: 6). |
| `--rate-limit` | Segundos de espera entre escaneos de host (float). Incluye jitter ±30%. |
| `--prescan` | Habilita pre-scan asyncio rápido antes de nmap. |
| `--prescan-ports` | Rango de puertos pre-scan (defecto: 1-1024). |
| `--prescan-timeout` | Timeout pre-scan segundos (defecto: 0.5). |
| `--udp-mode` | Modo de escaneo UDP: `quick` (defecto) o `full`. |
| `--udp-ports` | Número de top puertos UDP a escanear en `--udp-mode full` (50-500, defecto: 100). |
| `--skip-update-check` | Omitir verificación de actualizaciones al iniciar. |
| `--no-deep-scan` | Desactiva el deep scan adaptativo. |
| `--no-vuln-scan` | Desactiva el escaneo de vulnerabilidades web. |
| `--no-txt-report` | Desactiva la generación de reporte TXT. |
| `--max-hosts` | Número máximo de hosts encontrados a escanear (defecto: todos). |

### Características v3.0

| Flag | Descripción |
| :--- | :--- |
| `--ipv6` | Activa modo solo IPv6. |
| `--proxy URL` | Proxy SOCKS5 para pivoting (ej: `socks5://pivot:1080`). |
| `--diff OLD NEW` | Compara dos reportes JSON y genera análisis diferencial. |
| `--cve-lookup` | Activa correlación CVE vía API NVD. |
| `--nvd-key KEY` | Clave API NVD para límites de velocidad más rápidos (opcional). |
| `--allow-non-root` | Ejecuta en modo limitado sin sudo (sin detección de SO/pcap; algunos scans pueden fallar). |

### Características v3.1+

| Flag | Descripción |
| :--- | :--- |
| `--topology` | Activa descubrimiento de topología (ARP/VLAN/LLDP + gateway/rutas). |
| `--no-topology` | Desactiva descubrimiento de topología (anula defaults persistentes). |
| `--topology-only` | Ejecuta solo topología (omite escaneo de hosts). |
| `--save-defaults` | Guarda ajustes CLI como defaults persistentes (`~/.redaudit/config.json`). |

### Características v3.2+

| Flag | Descripción |
| :--- | :--- |
| `--net-discovery [PROTO,...]` | Activa descubrimiento de red mejorado (all, o lista: dhcp,netbios,mdns,upnp,arp,fping). |
| `--redteam` | Incluye bloque opt-in de recon Red Team en net discovery (best-effort, más lento/más ruido). |
| `--net-discovery-interface IFACE` | Interfaz para net discovery y capturas L2 (ej: eth0). |
| `--redteam-max-targets N` | Máximo de IPs muestreadas para checks redteam (1-500, defecto: 50). |
| `--snmp-community COMMUNITY` | Comunidad SNMP para SNMP walking (defecto: public). |
| `--dns-zone ZONE` | Pista de zona DNS para intento AXFR (ej: corp.local). |
| `--kerberos-realm REALM` | Pista de realm Kerberos (ej: CORP.LOCAL). |
| `--kerberos-userlist PATH` | Lista opcional de usuarios para userenum Kerberos (requiere kerbrute; solo con autorización). |
| `--redteam-active-l2` | Activa checks L2 adicionales potencialmente más ruidosos (bettercap/scapy sniff; requiere root). |

### Características v3.2.3

| Flag | Descripción |
| :--- | :--- |
| `--stealth` | Modo sigiloso: timing paranoid nmap (T1), mono-hilo, retardo 5s+. Para redes empresariales con IDS/rate limiters. |

### Características v3.3.0

| Flag | Descripción |
| :--- | :--- |
| `--html-report` | Genera dashboard HTML interactivo con gráficos y tablas ordenables (funciona offline). |
| `--webhook URL` | Envía alertas en tiempo real para hallazgos de alta severidad a una URL (Slack/Teams/Discord). |

### Características v3.4.0

**Playbooks de Remediación** se generan automáticamente tras cada escaneo. Proveen guías accionables para remediar hallazgos.

| Categoría | Contenido |
| :--- | :--- |
| Hardening TLS | Suites de cifrado, versiones de protocolo, problemas de certificado |
| Cabeceras HTTP | HSTS, CSP, X-Frame-Options faltantes, etc. |
| Remediación CVE | Guías de parches con enlaces NVD |
| Hardening Web | Directory listing, banners, páginas por defecto |
| Hardening Puertos | Telnet, FTP, SMBv1, SNMP community public |

**Salida**: directorio `<output_dir>/playbooks/` con un archivo Markdown por categoría por host.

**Notas**: Los playbooks se deduplican (uno por host + categoría) y se omiten cuando el cifrado de reportes está activado (`--encrypt`).

### Seguridad

| Flag | Descripción |
| :--- | :--- |
| `-e`, `--encrypt` | Cifra artefactos de salida con AES-128. Pide contraseña si no se provee. |
| `--encrypt-password` | Contraseña para cifrado (modo no interactivo). |
| `-V`, `--version` | Muestra información de versión y sale. |

## Ejemplos

**1. Auditoría de Subred Estándar**
Enumera servicios en una subred Clase C con concurrencia por defecto.

```bash
sudo redaudit -t 192.168.1.0/24 --mode normal --yes
```

**2. Escaneo Dirigido de Alto Sigilo**
Escanea un único host con rate limiting habilitado para reducir ruido.

```bash
sudo redaudit -t 10.0.0.50 --rate-limit 1.5 --mode normal --yes
```

**3. Auditoría Completa con Cifrado**
Escaneo profundo con reporte cifrado para cadena de custodia.

```bash
sudo redaudit -t 192.168.1.100 --mode full --encrypt --yes
```

**4. Pre-scan Rápido en Rango Grande**
Usa pre-scan asyncio para descubrimiento rápido de puertos antes de nmap.

```bash
sudo redaudit -t 192.168.1.0/24 --prescan --prescan-ports 1-1024 --yes
```

**5. Escaneo de Red IPv6 (v3.0)**
Escanea un segmento de red IPv6.

```bash
sudo redaudit -t "2001:db8::/64" --ipv6 --mode normal --yes
```

**6. Comparar Dos Reportes (v3.0)**
Genera un análisis diferencial mostrando cambios de red.

```bash
redaudit --diff ~/reports/lunes.json ~/reports/viernes.json
```

**7. Escaneo a Través de Proxy (v3.0)**
Pivota a través de un proxy SOCKS5 para acceso a red interna.

```bash
sudo redaudit -t 10.0.0.0/24 --proxy socks5://pivot-host:1080 --yes
```

**8. Escaneo con Correlación CVE (v3.0)**
Enriquece resultados con datos de vulnerabilidad de NIST NVD.

```bash
sudo redaudit -t 192.168.1.0/24 --cve-lookup --nvd-key TU_CLAVE --yes
```

**9. Descubrimiento de Red Mejorado (v3.2)**
Descubrimiento basado en broadcast para revelar DHCP adicionales, hostnames y señales L2.

```bash
sudo redaudit -t 192.168.1.0/24 --net-discovery --redteam --net-discovery-interface eth0 --yes
```

**10. Dashboard HTML y Alertas Webhook (v3.3)**
Genera un reporte visual y alerta sobre hallazgos críticos.

```bash
sudo redaudit -t 192.168.1.0/24 --html-report --webhook https://hooks.slack.com/services/XXX --yes
```

### Reportes y Cifrado

Los reportes se guardan en subcarpetas con fecha (v2.8+): `RedAudit_YYYY-MM-DD_HH-MM-SS/`

Cada sesión de escaneo crea su propia carpeta con:

- **Texto Plano**: `.json` y `.txt`.
- **Cifrados**: `.json.enc`, `.txt.enc` y `.salt`.
- **Exportaciones SIEM/IA (v3.1)**: `findings.jsonl`, `assets.jsonl`, `summary.json` (solo cuando el cifrado está desactivado).
- **PCAP**: Archivos de captura de tráfico (cuando se ejecuta deep scan y las herramientas están disponibles).

**Nuevos campos en v3.1.4**:

- `severity_note`: Explicación cuando la severidad fue ajustada (ej: "Divulgación RFC-1918 en red privada")
- `potential_false_positives`: Array de contradicciones detectadas en cross-validación
- `pcap_file`: Nombre de archivo relativo portable para capturas PCAP

**Nuevos campos en v3.2.0**:

- `net_discovery`: Bloque opcional de descubrimiento de red mejorado (solo si se activa `--net-discovery`)
- `net_discovery.dhcp_servers[].domain` / `net_discovery.dhcp_servers[].domain_search`: Pistas de dominio best-effort desde respuestas DHCP
- `net_discovery.redteam`: Salida de recon extendida cuando se activa `--redteam` (SNMP/SMB/RPC/LDAP/Kerberos/DNS + señales L2 pasivas)

Para descifrar resultados:

```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```

Esto generará archivos `.decrypted` (o restaurará la extensión original) tras verificar la contraseña.

### Logging

Los logs de depuración se guardan en `~/.redaudit/logs/`. Revisa estos archivos si el escaneo falla o se comporta de forma inesperada.

## Configuración de Correlación CVE

RedAudit puede enriquecer los resultados del escaneo con datos CVE de la National Vulnerability Database (NVD) del NIST.
Este enriquecimiento depende de versiones detectadas (o CPEs con versión); si la versión es desconocida, RedAudit omite ese puerto para evitar resultados demasiado amplios.

### Configuración de API Key

La API de NVD tiene límites de velocidad:

- **Sin key**: 5 peticiones por 30 segundos
- **Con key**: 50 peticiones por 30 segundos (10x más rápido)

### Obtener una API Key

1. Visita: <https://nvd.nist.gov/developers/request-an-api-key>
2. Regístrate con tu email (GRATIS)
3. Recibe tu API key en formato UUID

### Métodos de Configuración

**Opción 1: Durante la Instalación**

El instalador pregunta por la API key:

```bash
sudo ./redaudit_install.sh
```

**Opción 2: Variable de Entorno**

Añade a tu `~/.bashrc` o `~/.zshrc`:

```bash
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Opción 3: Archivo de Configuración**

Crea `~/.redaudit/config.json`:

**Nota**: El campo `version` en `~/.redaudit/config.json` es la **versión del esquema de configuración** (actualmente `3.2.3`) y no tiene por qué coincidir con la versión de la aplicación RedAudit (v3.4.0).

```json
{
  "version": "3.2.3",
  "nvd_api_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "defaults": {
    "threads": 6,
    "rate_limit": 1.5,
    "udp_mode": "full",
    "udp_top_ports": 200,
    "topology_enabled": true,
    "lang": "es",
    "output_dir": "~/Documents/RedAuditReports"
  }
}
```

**Opción 4: Línea de Comandos**

Pasa la key directamente (no se guarda):

```bash
sudo redaudit -t 192.168.1.0/24 --cve-lookup --nvd-key TU_CLAVE
```

### Uso

```bash
# Con key configurada
sudo redaudit -t 192.168.1.0/24 --cve-lookup

# Sin key (límite más lento)
sudo redaudit -t 192.168.1.0/24 --cve-lookup
```

## Rendimiento y Sigilo

### Limitación de Velocidad (Rate Limiting)

RedAudit permite configurar un retardo (en segundos) entre el escaneo de cada host. **v2.7 añade jitter aleatorio ±30%** a este retardo para evasión de IDS.

- **0s (Por defecto)**: Velocidad máxima. Ideal para auditorías internas donde el ruido no importa.
- **1-5s**: Sigilo moderado. Reduce la probabilidad de activar firewalls de rate-limit simples.
- **>10s**: Sigilo alto. Ralentiza significativamente la auditoría pero minimiza el riesgo de detección y congestión.

### Pre-scan

Habilita `--prescan` para usar TCP connect asyncio para descubrimiento rápido de puertos antes de invocar nmap:

```bash
sudo redaudit -t 192.168.1.0/24 --prescan --prescan-ports 1-1024 --yes
```

**Nota sobre el Heartbeat**: Si usas un retardo alto (ej. 60s) con muchos hilos, el escaneo puede parecer "congelado". Revisa el log o el estado del heartbeat.

### Marcadores de Ejecución CLI

RedAudit v2.8.0 te informa estrictamente sobre los comandos que se están ejecutando:

- **`[nmap] 192.168.x.x → nmap ...`**: Escaneo de puertos estándar.
- **`[deep] 192.168.x.x → combined ...`**: Ejecución de Escaneo de Identidad Profundo (espera una duración de 90-140s).

### Deep Scan Adaptativo y Captura de Tráfico

RedAudit intenta automáticamente un "Deep Scan Adaptativo" en hosts que:

1. **Tienen más de 8 puertos abiertos**
2. **Tienen servicios sospechosos** (socks, proxy, vpn, tor, nagios, etc.)
3. **Tienen muy pocos puertos (<=3)**
4. **Tienen puertos abiertos pero no se detectó información de versión**

- **Estrategia Adaptativa**: Ejecuta un escaneo de 2 fases (primero TCP agresivo, luego UDP/SO solo si la Fase 1 no encontró identidad MAC/SO) para identificar hosts complejos.
- **Captura de Tráfico**: Como parte del Deep Scan, si `tcpdump` está disponible, captura un **snippet de 50 paquetes** (máx 15s) del tráfico del host.
  - Guarda archivos `.pcap` en tu directorio de reportes.
  - Si `tshark` está instalado, incluye un resumen de protocolos en el reporte JSON.
  - *Defensa*: La duración de captura está estrictamente limitada para prevenir bloqueos.

---

RedAudit se distribuye bajo **GPLv3**. Consulta [LICENSE](../../LICENSE) para más detalles.
