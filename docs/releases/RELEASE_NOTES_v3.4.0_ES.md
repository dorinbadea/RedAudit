# Notas de Versión v3.4.0 - Playbook Export

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.4.0.md)

**Fecha de lanzamiento**: 2025-12-17

## Resumen

RedAudit v3.4.0 introduce **Playbooks de Remediación** - guías Markdown generadas automáticamente con pasos accionables para remediar vulnerabilidades detectadas.

## Nuevas Características

### Generación de Playbooks de Remediación

Tras cada escaneo, RedAudit genera playbooks en el directorio `<output_dir>/playbooks/`. Cada playbook contiene:

- **Instrucciones paso a paso**
- **Comandos shell sugeridos** para correcciones comunes
- **Enlaces de referencia** a OWASP, Mozilla, NVD y CIS

#### Categorías de Playbooks

| Categoría | Disparadores |
| :--- | :--- |
| **Hardening TLS** | Cifrados débiles, versiones TLS obsoletas, problemas de certificado |
| **Cabeceras HTTP** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options faltantes |
| **Remediación CVE** | CVEs conocidos detectados vía correlación NVD |
| **Hardening Web** | Directory listing, banners de servidor, páginas por defecto (hallazgos Nikto) |
| **Hardening Puertos** | Servicios peligrosos: Telnet, FTP, SMBv1, SNMP con community public |

#### Ejemplo de Salida

```
~/Documents/RedAuditReports/2025-12-17/playbooks/
├── 192_168_1_1_tls_hardening.md
├── 192_168_1_1_http_headers.md
├── 192_168_1_5_cve_remediation.md
└── 192_168_1_10_port_hardening.md
```

## Detalles Técnicos

- **Nuevo módulo**: `redaudit/core/playbook_generator.py`
- **Integración**: Playbooks generados automáticamente vía `reporter.py` tras finalizar el escaneo
- **12 tests unitarios** añadidos para el generador de playbooks

## Instrucciones de Actualización

```bash
# Si instalaste desde GitHub
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh

# O instalación limpia
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/main/redaudit_install.sh | sudo bash
```

---

*RedAudit v3.4.0 - Haciendo la remediación de vulnerabilidades accionable.*
