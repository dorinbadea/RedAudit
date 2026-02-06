# Notas de la Version v4.5.5

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.5/docs/releases/RELEASE_NOTES_v4.5.5.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta version empaqueta el **Seeder de Credenciales de Lab** (`scripts/seed_keyring.py`) y mejora el auto-updater para ejecutarlo automaticamente. Esto asegura una transicion fluida a la nueva funcion de carga de credenciales.

## Anadido

- **Script de Credenciales de Lab (Modo Spray)**
  - Nuevo script: `scripts/seed_keyring.py`
  - Contiene **TODAS** las credenciales del laboratorio Phase 4 (11 sets)
  - Configurado para Modo Spray (multiples credenciales por protocolo)
  - Pre-puebla el keyring con:
    - SSH: auditor, msfadmin, openplc
    - SMB: Administrator, docker, msfadmin
    - SNMP: admin-snmp

- **Updater Auto-Seed**
  - La actualizacion del asistente (Opcion 2) ejecuta automaticamente `seed_keyring.py` si esta presente
  - Reduce los pasos manuales para usuarios que actualizan RedAudit

## Nota Importante para esta Actualizacion

Como estas actualizando *desde* una version anterior que carece de la logica auto-seed, la ejecucion automatica **no se activara** durante la actualizacion a v4.5.5.

**Paso Manual (Solo una vez):**
Despues de actualizar, ejecuta:

```bash
python3 scripts/seed_keyring.py
```

Las futuras actualizaciones manejaran esto automaticamente.
