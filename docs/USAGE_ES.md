# Guía de Uso RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](USAGE.md)

## Referencia CLI

RedAudit está diseñado para ejecución sin estado (stateless) vía argumentos de línea de comandos.

### Sintaxis

```bash
sudo redaudit [TARGET] [OPTIONS]
# O vía módulo Python (v2.6+)
sudo python -m redaudit [TARGET] [OPTIONS]
```

### Argumentos Principales

| Flag | Descripción |
| :--- | :--- |
| `-t`, `--target` | IP objetivo, subred (CIDR), o lista separada por comas. |
| `-m`, `--mode` | Intensidad: `fast` (ICMP), `normal` (Puertos top), `full` (Todos + scripts). |
| `--deep` | Habilita escaneo de vulnerabilidades agresivo (Web/NSE). Equivale a `-m full`. |
| `-o`, `--output` | Especificar directorio de salida. Por defecto: `~/RedAuditReports`. |
| `-l`, `--lang` | Idioma de interfaz: `en` (defecto), `es`. |

### Rendimiento y Evasión

| Flag | Descripción |
| :--- | :--- |
| `--threads <N>` | Tamaño del pool de hilos para escaneo concurrente. |
| `-r`, `--rate-limit` | Segundos de espera entre operaciones de hilo (float). Incluye jitter ±30% (v2.7). |
| `--pcap` | Habilita captura de paquetes raw (`tcpdump`) durante el escaneo. |
| `--prescan` | Habilita pre-scan asyncio rápido antes de nmap (v2.7). |
| `--prescan-ports` | Rango de puertos para pre-scan (defecto: 1-1024). |
| `--prescan-timeout` | Timeout de conexión del pre-scan en segundos (defecto: 0.5). |

### Seguridad

| Flag | Descripción |
| :--- | :--- |
| `--encrypt` | Cifra artefactos de salida con AES-128. Pide contraseña si no se provee. |
| `--version` | Muestra información de versión y sale. |

## Ejemplos

**1. Auditoría de Subred Estándar**
Enumera servicios en una subred Clase C con concurrencia por defecto.

```bash
sudo redaudit -t 192.168.1.0/24
```

**2. Escaneo Dirigido de Alto Sigilo**
Escanea un único host con rate limiting habilitado para reducir ruido.

```bash
sudo redaudit -t 10.0.0.50 --rate-limit 1.5 --mode normal
```

**3. Modo Forense**
Escaneo profundo con captura de tráfico completa y reporte cifrado para cadena de custodia.

```bash
sudo redaudit -t 192.168.1.100 --deep --pcap --encrypt
```

### 3. Reportes y Cifrado

Los reportes se guardan con fecha `redaudit_YYYYMMDD_HHMMSS`.

- **Texto Plano**: `.json` y `.txt`.
- **Cifrados**: `.json.enc`, `.txt.enc` y `.salt`.

Para descifrar resultados:

```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```

Esto generará archivos `.decrypted` (o restaurará la extensión original) tras verificar la contraseña.

### 4. Logging

Los logs de depuración se guardan en `~/.redaudit/logs/`. Revisa estos archivos si el escaneo falla o se comporta de forma inesperada.

## Rendimiento y Sigilo

### Limitación de Velocidad (Rate Limiting)

RedAudit permite configurar un retardo (en segundos) entre el escaneo de cada host. **v2.7 añade jitter aleatorio ±30%** a este retardo para evasión de IDS.

- **0s (Por defecto)**: Velocidad máxima. Ideal para auditorías internas donde el ruido no importa.
- **1-5s**: Sigilo moderado. Reduce la probabilidad de activar firewalls de rate-limit simples.
- **>10s**: Sigilo alto. Ralentiza significativamente la auditoría pero minimiza el riesgo de detección y congestión.

### Pre-scan (v2.7)

Habilita `--prescan` para usar TCP connect asyncio para descubrimiento rápido de puertos antes de invocar nmap:

```bash
sudo redaudit -t 192.168.1.0/24 --prescan --prescan-ports 1-1024
```

**Nota sobre el Heartbeat**: Si usas un retardo alto (ej. 60s) con muchos hilos, el escaneo puede parecer "congelado". Revisa el log o el estado del heartbeat.

### Marcadores de Ejecución CLI

RedAudit v2.7.0 te informa estrictamente sobre los comandos que se están ejecutando:

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
