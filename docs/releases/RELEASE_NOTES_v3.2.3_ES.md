# RedAudit v3.2.3 - Notas de Lanzamiento

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.2.3.md)

**Fecha de Lanzamiento**: 16 de Diciembre, 2025
**Tipo**: Versión con nuevas funcionalidades (HyperScan + Modo Sigiloso)
**Versión Anterior**: v3.2.2

---

## Resumen

La versión 3.2.3 introduce dos capacidades principales: **HyperScan** para descubrimiento de red paralelo ultrarrápido, y **Modo Sigiloso** para redes empresariales con IDS/rate limiters. Además, los spinners de progreso ahora proporcionan feedback visual durante las fases de descubrimiento largas.

---

## Novedades en v3.2.3

### 1. Módulo HyperScan

Nuevo `redaudit/core/hyperscan.py` (~1000 líneas) proporciona descubrimiento paralelo ultrarrápido usando Python asyncio:

| Componente | Descripción |
|-----------|-------------|
| TCP Batch | 3000 conexiones concurrentes con control de semáforo |
| Barrido UDP | 45+ puertos con payloads específicos por protocolo |
| Broadcast IoT | Bombillas WiZ, SSDP, Chromecast, Yeelight, LIFX |
| ARP Agresivo | Barrido con 3 reintentos usando arp-scan + arping fallback |
| Detección de Backdoors | Marca puertos sospechosos (31337, 4444, 6666, etc.) |
| Deep Scan | Escaneo completo de 65535 puertos en hosts sospechosos |

### 2. Modo Sigiloso

Nuevo flag CLI `--stealth` para redes empresariales con políticas de seguridad estrictas:

```bash
sudo python3 -m redaudit --target 10.0.0.0/24 --stealth --yes
```

| Parámetro | Normal | Sigiloso |
|-----------|--------|----------|
| Timing | `-T4` | `-T1` (paranoid) |
| Hilos | 6-14 | 1 (secuencial) |
| Retardo | 0s | 5s+ mínimo |

### 3. Spinners de Progreso

Spinners animados ahora muestran tiempo transcurrido durante:

- Fase de descubrimiento de topología
- Fase de net discovery (DHCP/NetBIOS/mDNS/UPNP)

Esto reemplaza los anteriores avisos de "sin salida" durante operaciones largas.

### 4. Correcciones

- **Deduplicación de Redes**: "Escanear TODAS" ahora elimina correctamente CIDRs duplicados cuando la misma red se detecta en múltiples interfaces
- **Visualización de Defaults**: La revisión de configuración interactiva muestra 10 campos (antes 6)
- **Persistencia de Config**: `DEFAULT_CONFIG` expandido a 12 campos

---

## Ejemplos de Uso

```bash
# Scan estándar con HyperScan (auto-habilitado en modo completo)
sudo python3 -m redaudit --mode full --yes

# Scan sigiloso empresarial
sudo python3 -m redaudit --target 10.0.0.0/24 --stealth --mode full --yes

# Verificar versión
python3 -m redaudit --version
```

---

## Instrucciones de Actualización

```bash
# Actualizar desde cualquier versión anterior
cd ~/RedAudit
git pull origin main

# O reinstalar
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/v3.2.3/redaudit_install.sh | sudo bash
```

---

## Enlaces Útiles

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
- **Guía de Uso**: [docs/en/USAGE.es.md](../USAGE.es.md) / [docs/es/USAGE.es.md](../USAGE.es.md)
- **Manual**: [docs/en/MANUAL.es.md](../MANUAL.es.md) / [docs/es/MANUAL.es.md](../MANUAL.es.md)
