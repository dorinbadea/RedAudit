# Notas de la Version v4.5.6

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.6/docs/releases/RELEASE_NOTES_v4.5.6.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta version anade **Automatizacion de Configuracion de Laboratorio** (`scripts/setup_lab.sh`) y documentacion detallada. Los usuarios ahora pueden iniciar facilmente el entorno Docker exacto al que corresponden las credenciales de prueba de RedAudit.

## Anadido

- **Script de Configuracion de Lab** (`scripts/setup_lab.sh`)
  - Automatiza instalacion, inicio, parada y chequeo de estado del laboratorio.
  - Provisiona 11 objetivos incluyendo SCADA, Active Directory y simuladores IoT.
  - **Uso**: `sudo bash scripts/setup_lab.sh [install|start|stop|status]`

- **Documentacion**
  - [Guia del Laboratorio](../../docs/LAB_SETUP_ES.md)
  - README actualizado con enlace Quick Start a la guia.

## Como usar

1. **Actualizar e Instalar**:

   ```bash
   cd ~/RedAudit && git pull && sudo bash redaudit_install.sh
   # (Esto tambien ejecutara el seeder de credenciales si no lo has hecho)
   ```

2. **Configurar Lab**:

   ```bash
   sudo bash scripts/setup_lab.sh install
   ```

3. **Verificar Estado**:

   ```bash
   sudo bash scripts/setup_lab.sh status
   ```

4. **Verificar Seeder**:

   ```bash
   # Si actualizaste desde <v4.5.5, ejecuta esto una vez:
   python3 scripts/seed_keyring.py
   ```
