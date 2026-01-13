# RedAudit v3.1.1

[![English](https://img.shields.io/badge/EN-English-blue?style=flat-square)](#english) [![Español](https://img.shields.io/badge/ES-Espa%C3%B1ol-red?style=flat-square)](#espa%C3%B1ol)

## English

### Patch Release - Topology, Persistent Defaults & UDP Coverage

#### v3.1.1 Highlights

- **Topology Discovery (best-effort)**: Optional ARP/VLAN/LLDP + gateway/routes mapping (`--topology`, `--topology-only`).
- **Persistent Defaults**: Save common settings to `~/.redaudit/config.json` via `--save-defaults`.
- **Configurable UDP Coverage**: `--udp-ports N` (50-500) to tune full UDP identity scan coverage.

#### v3.1.0 Highlights (Included)

- **JSONL Exports**: Auto-generated `findings.jsonl`, `assets.jsonl`, and `summary.json` for SIEM/AI pipelines (when report encryption is disabled).
- **Finding IDs**: Deterministic hashes for finding deduplication across scans.
- **Category Classification**: Findings categorized as surface/misconfig/crypto/auth/info-leak/vuln.
- **Normalized Severity**: CVSS-like 0-10 scale with preserved original tool severity.
- **Parsed Observations**: Structured extraction from Nikto/TestSSL raw output.
- **Scanner Versions**: Provenance tracking with detected tool versions.

#### v3.0 Major Features

- **IPv6 Support**: Full scanning capabilities for IPv6 networks with automatic `-6` flag.
- **CVE Correlation (NVD)**: Deep vulnerability intelligence via NIST NVD API with 7-day cache.
- **Differential Analysis**: Compare two JSON reports to track network changes over time.
- **Proxy Chains (SOCKS5)**: Network pivoting support via proxychains wrapper.
- **Magic Byte Validation**: Enhanced false positive detection with file signature verification.

#### Previous (v2.9) Features

- **Smart-Check**: Intelligent false positive filtering for Nikto (90% noise reduction).
- **UDP Taming**: Optimized 3-phase UDP scanning strategy (50-80% faster).
- **Entity Resolution**: Intelligent grouping of multi-interface devices into unified assets.
- **SIEM Professional**: Enhanced JSON schema compliant with ECS v8.11.

---

#### Installation

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

#### New in v3.1.1 - JSON Output

```json
{
  "schema_version": "3.1",
  "scanner_versions": {"redaudit": "3.1.3", "nmap": "7.95"},
  "topology": {"candidate_networks": ["10.0.0.0/8"]},
  "hosts": [{"ip": "192.168.1.50", "deep_scan": {"udp_top_ports": 200}}]
}
```

#### New Modules (v3.1)

```text
redaudit/core/
├── scanner_versions.py  # Tool version detection
├── evidence_parser.py   # Nikto/TestSSL parsing
├── jsonl_exporter.py    # JSONL/JSON export views
└── topology.py          # Topology discovery (ARP/VLAN/LLDP)
```

#### CLI Options

| Flag | Description |
|:---|:---|
| `--ipv6` | Enable IPv6-only scanning mode |
| `--proxy URL` | SOCKS5 proxy for pivoting |
| `--diff OLD NEW` | Compare two JSON reports |
| `--cve-lookup` | Enable CVE correlation via NVD API |
| `--nvd-key KEY` | NVD API key for faster rate limits |
| `--udp-ports N` | Top UDP ports count for full identity scan (50-500) |
| `--topology` | Enable topology discovery (ARP/VLAN/LLDP + gateway/routes) |
| `--no-topology` | Disable topology discovery (override persisted defaults) |
| `--topology-only` | Run topology discovery only (skip host scanning) |
| `--save-defaults` | Save CLI settings as persistent defaults (~/.redaudit/config.json) |
| `--allow-non-root` | Run in limited mode without sudo/root |

#### Testing & Quality

- **Tests**: ![Tests](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg)
- **Coverage**: Reported by CI (see Actions/Codecov)
- **Security**: CodeQL & Dependabot active
- **License**: GPLv3

#### Documentation

Complete bilingual documentation (English/Spanish):

- [README.md](../../README.md) / [README_ES.md](../../ES/README_ES.md)
- [MANUAL (EN)](../MANUAL.en.md) / [MANUAL (ES)](../MANUAL.es.md)
- [USAGE (EN)](../USAGE.en.md) / [USAGE (ES)](../USAGE.es.md)

#### Links

- **Full Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md)
- **Release Notes**: [RELEASE_NOTES_v3.1.1.md](RELEASE_NOTES_v3.1.1.md) / [RELEASE_NOTES_v3.1.1_ES.md](RELEASE_NOTES_v3.1.1_ES.md)
- **Security Specs**: [EN](../SECURITY.en.md) / [ES](../SECURITY.es.md)

---

## Español

### Patch release - Topología, defaults persistentes y cobertura UDP

#### Highlights v3.1.1

- **Descubrimiento de topología (best-effort)**: Mapping opcional ARP/VLAN/LLDP + gateway/rutas (`--topology`, `--topology-only`).
- **Defaults persistentes**: Guardar ajustes comunes en `~/.redaudit/config.json` mediante `--save-defaults`.
- **Cobertura UDP configurable**: `--udp-ports N` (50-500) para ajustar la cobertura del UDP full de identidad.

#### Highlights v3.1.0 (incluido)

- **Exportaciones JSONL**: `findings.jsonl`, `assets.jsonl` y `summary.json` auto-generados para pipelines SIEM/IA (cuando el cifrado de informes está desactivado).
- **IDs de hallazgo**: Hashes determinísticos para deduplicación/correlación entre escaneos.
- **Clasificación por categoría**: surface/misconfig/crypto/auth/info-leak/vuln.
- **Severidad normalizada**: Escala 0-10 estilo CVSS con severidad original preservada.
- **Observaciones estructuradas**: Extracción estructurada desde outputs de Nikto/TestSSL.
- **Versiones de herramientas**: Proveniencia con versiones detectadas.

#### Características principales v3.0

- **Soporte IPv6**: Escaneo completo de redes IPv6 con flag `-6` automático.
- **Correlación CVE (NVD)**: Inteligencia de vulnerabilidades via NIST NVD API con caché de 7 días.
- **Análisis diferencial**: Comparación de dos informes JSON para detectar cambios.
- **Proxy Chains (SOCKS5)**: Soporte de pivoting via wrapper proxychains.
- **Validación Magic Byte**: Detección mejorada de falsos positivos con verificación de firmas.

#### Features previas (v2.9)

- **Smart-Check**: Filtrado inteligente de falsos positivos de Nikto (90% menos ruido).
- **UDP Taming**: Estrategia optimizada de 3 fases (50-80% más rápido).
- **Entity Resolution**: Agrupación inteligente de dispositivos multi-interfaz (unified assets).
- **SIEM profesional**: Esquema JSON enriquecido y alineado con ECS v8.11.

---

#### Instalación

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

#### Nuevo en v3.1.1 - Salida JSON

```json
{
  "schema_version": "3.1",
  "scanner_versions": {"redaudit": "3.1.3", "nmap": "7.95"},
  "topology": {"candidate_networks": ["10.0.0.0/8"]},
  "hosts": [{"ip": "192.168.1.50", "deep_scan": {"udp_top_ports": 200}}]
}
```

#### Módulos nuevos (v3.1)

```text
redaudit/core/
├── scanner_versions.py  # Detección de versiones de herramientas
├── evidence_parser.py   # Parsing Nikto/TestSSL
├── jsonl_exporter.py    # Vistas de exportación JSONL/JSON
└── topology.py          # Descubrimiento de topología (ARP/VLAN/LLDP)
```

#### Opciones CLI

| Flag | Descripción |
|:---|:---|
| `--ipv6` | Activa modo solo IPv6 |
| `--proxy URL` | Proxy SOCKS5 para pivoting |
| `--diff OLD NEW` | Compara dos informes JSON |
| `--cve-lookup` | Activa correlación CVE vía NVD |
| `--nvd-key KEY` | API key NVD para rate limits más rápidos |
| `--udp-ports N` | Número de top puertos UDP para identidad (50-500) |
| `--topology` | Activa descubrimiento de topología (ARP/VLAN/LLDP + gateway/rutas) |
| `--no-topology` | Desactiva topología (anula defaults persistentes) |
| `--topology-only` | Ejecuta solo topología (omite escaneo de hosts) |
| `--save-defaults` | Guarda ajustes CLI como defaults persistentes (~/.redaudit/config.json) |
| `--allow-non-root` | Ejecuta sin sudo/root (modo limitado) |

#### Testing y calidad

- **Tests**: ![Tests](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg)
- **Coverage**: Reportado por CI (ver Actions/Codecov)
- **Seguridad**: CodeQL y Dependabot activos
- **Licencia**: GPLv3

#### Documentación

Documentación bilingüe (inglés/español):

- [README.md](../../README.md) / [README_ES.md](../../ES/README_ES.md)
- [MANUAL (EN)](../MANUAL.en.md) / [MANUAL (ES)](../MANUAL.es.md)
- [USAGE (EN)](../USAGE.en.md) / [USAGE (ES)](../USAGE.es.md)

#### Links

- **Changelog completo**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md)
- **Release Notes**: [RELEASE_NOTES_v3.1.1.md](RELEASE_NOTES_v3.1.1.md) / [RELEASE_NOTES_v3.1.1_ES.md](RELEASE_NOTES_v3.1.1_ES.md)
- **Especificaciones de seguridad**: [EN](../SECURITY.en.md) / [ES](../SECURITY.es.md)
