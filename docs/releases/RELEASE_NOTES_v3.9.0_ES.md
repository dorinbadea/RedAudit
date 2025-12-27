# RedAudit v3.9.0 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/🇬🇧-English-blue)](./RELEASE_NOTES_v3.9.0.md)

**Fecha de Lanzamiento**: 2025-12-27

## Destacados

Esta versión se centra en **usabilidad del wizard**, **precisión del escaneo** y **detección de falsos positivos**.

---

## ✨ Nuevas Funcionalidades

### Navegación del Wizard

- Añadida opción **"< Volver"** al seleccionar modo de timing
- Los usuarios pueden regresar al selector de perfil sin reiniciar

### Diferencias Reales de Timing

Las plantillas de timing de Nmap ahora se aplican correctamente según el modo seleccionado:

| Modo | Plantilla | Hilos | Retardo |
|------|-----------|-------|---------|
| Sigiloso | `-T1` | 4 | 300ms |
| Normal | `-T4` | 16 | 0ms |
| Agresivo | `-T5` | 32 | 0ms |

### Aumento de Cobertura de Puertos UDP

- **Perfil Exhaustivo** ahora escanea top **500 puertos UDP** (antes 200)
- Mejora la cobertura del ~95% al ~98%

### Detección de Falsos Positivos de Nuclei

- Los hallazgos ahora incluyen el campo `suspected_false_positive`
- Detección basada en cabecera Server vs vendor esperado
- Ejemplo: CVE-2022-26143 (Mitel) marcado como FP en routers FRITZ!Box

### Filtrado de Logs de Sesión

- Mejora en la reducción de ruido filtrando actualizaciones de progreso
- Logs de sesión más limpios para revisión

---

## 🐛 Correcciones

### nmap_timing No Aplicado

- **Corregido**: `get_nmap_arguments()` ahora recibe el objeto config
- Los modos Sigiloso/Normal/Agresivo usan correctamente T1/T4/T5

### Playbooks No Aparecían en Reporte HTML

- **Corregido**: La generación de playbooks ahora ocurre antes del renderizado HTML
- Los datos de playbooks se inyectan correctamente en la plantilla del reporte

---

## ⚡ Cambios

### Tipo de Retorno de `save_playbooks()`

- Ahora devuelve `tuple[int, list]` en lugar de `int`
- Devuelve `(count, playbook_data)` para integración con reporte HTML

---

## 🗑️ Eliminado

### Módulo `prescan.py`

- Eliminado como código muerto
- Funcionalidad reemplazada por `hyperscan.py` que ofrece:
  - Barridos paralelos TCP/UDP
  - Escaneo ARP agresivo
  - Descubrimiento de dispositivos IoT (SSDP, mDNS, WiZ)

---

## 📦 Instalación

```bash
pip install --upgrade redaudit
# o
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.0
```

---

## 🔗 Enlaces

- [Changelog Completo](../../CHANGELOG_ES.md)
- [Documentación](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
