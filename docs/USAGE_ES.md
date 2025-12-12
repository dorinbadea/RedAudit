# Guía de Uso RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](USAGE.md)

## Referencia CLI

RedAudit está diseñado para ejecución sin estado (stateless) vía argumentos de línea de comandos.

### Sintaxis

```bash
sudo redaudit [OPTIONS]
# O vía módulo Python (v2.6+)
sudo python -m redaudit [OPTIONS]
```

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
| `--skip-update-check` | Omitir verificación de actualizaciones al iniciar. |
| `--no-deep-scan` | Desactiva el deep scan adaptativo. |
| `--no-vuln-scan` | Desactiva el escaneo de vulnerabilidades web. |
| `--no-txt-report` | Desactiva la generación de reporte TXT. |
| `--max-hosts` | Número máximo de hosts a escanear (defecto: todos). |

### Características v3.0

| Flag | Descripción |
| :--- | :--- |
| `--ipv6` | Activa modo solo IPv6. |
| `--proxy URL` | Proxy SOCKS5 para pivoting (ej: `socks5://pivot:1080`). |
| `--diff OLD NEW` | Compara dos reportes JSON y genera análisis diferencial. |
| `--cve-lookup` | Activa correlación CVE vía API NVD. |
| `--nvd-key KEY` | Clave API NVD para límites de velocidad más rápidos (opcional). |

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
sudo redaudit --diff ~/reports/lunes.json ~/reports/viernes.json
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

### Reportes y Cifrado

Los reportes se guardan en subcarpetas con fecha (v2.8+): `RedAudit_YYYY-MM-DD_HH-MM-SS/`

Cada sesión de escaneo crea su propia carpeta con:

- **Texto Plano**: `.json` y `.txt`.
- **Cifrados**: `.json.enc`, `.txt.enc` y `.salt`.
- **PCAP**: Archivos de captura de tráfico.

Para descifrar resultados:

```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```

Esto generará archivos `.decrypted` (o restaurará la extensión original) tras verificar la contraseña.

### Logging

Los logs de depuración se guardan en `~/.redaudit/logs/`. Revisa estos archivos si el escaneo falla o se comporta de forma inesperada.

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

RedAudit se distribuye bajo **GPLv3**. Consulta [LICENSE](../LICENSE) para más detalles.
