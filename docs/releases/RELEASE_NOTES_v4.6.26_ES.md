# Notas de Lanzamiento RedAudit v4.6.26

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.26/docs/releases/RELEASE_NOTES_v4.6.26.md)

## Resumen

**RedAudit v4.6.26** corrige un problema especifico de Interfaz de Usuario introducido por el nuevo motor Nuclei paralelo. Asegura que la barra de progreso del escaneo permanezca suave y precisa cuando se ejecutan multiples lotes simultaneamente.

## Corregido

- **"Jitter" en Barra de Progreso**: En modo paralelo, los lotes individuales reportaban su progreso *local* a la barra principal, causando saltos erraticos (ej: 10% -> 5% -> 12%). El uso de una logica de agregacion centralizada y segura para hilos asegura ahora que la barra refleje con precision el progreso *total* combinado de todos los lotes.

## Actualizacion

```bash
git pull origin main
```
