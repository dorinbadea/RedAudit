[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v4.17.0.md)

# Notas de Version - v4.17.0

**Fecha de Lanzamiento:** 2026-01-20

## Resumen

Esta version anade control de usuario sobre la limitacion de targets Nuclei, permitiendo elegir entre eficiencia audit-focus (por defecto en modo Personalizado) o cobertura completa de puertos (por defecto en modo Exhaustivo).

## Anadido

### Opcion Cobertura Completa Nuclei

Nueva pregunta en wizard: "Escanear TODOS los puertos HTTP con Nuclei?"

| Modo | Default | Comportamiento |
|------|---------|----------------|
| Exhaustivo | Si | Escanea todos los puertos HTTP (tipo pentesting) |
| Personalizado | No | Limita a 2 puertos/host (eficiencia auditoria) |

**Clave config:** `nuclei_full_coverage`

Cuando esta habilitado, la limitacion audit-focus de v4.16 se omite, y todos los endpoints HTTP descubiertos se escanean.

## Testing

- Anadidos `TestNucleiFullCoverage` (4 tests)
- Anadidos `TestNucleiFullCoverageI18n` (2 tests)
- Los 6 tests pasando

## Actualizacion

```bash
git pull origin main
pip install -e .
```
