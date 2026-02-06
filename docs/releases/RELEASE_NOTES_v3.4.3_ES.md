# Notas de la versión v3.4.3 - Títulos Descriptivos de Hallazgos

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.4.3.md)

**Fecha de publicación**: 2025-12-17

## Resumen

RedAudit v3.4.3 es un hotfix pequeño que mejora la legibilidad generando títulos descriptivos para hallazgos web.

## Correcciones

- **Títulos de hallazgos**: Los hallazgos web ahora tienen un `descriptive_title` corto derivado de observaciones parseadas (mejora títulos en el informe HTML, webhooks y encabezados de playbooks).
- **Directorio de salida (wizard)**: Cuando el default iba a caer bajo `/root/...`, RedAudit ahora prefiere la carpeta `Documentos` del usuario (usuario invocador bajo `sudo`, y un único usuario detectado bajo `/home/<usuario>` cuando se ejecuta como root sin `sudo`).
- **Marcador de selección (wizard)**: Usa un marcador ASCII `>` para máxima compatibilidad con terminales/fuentes.

## Instrucciones de actualización

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

*RedAudit v3.4.3 - Salida más clara para triage.*
