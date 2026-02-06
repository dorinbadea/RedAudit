# Notas de la Version v4.5.4

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.4/docs/releases/RELEASE_NOTES_v4.5.4.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta version implementa B5: Carga de Credenciales desde Keyring. El asistente ahora detecta credenciales guardadas y ofrece cargarlas al inicio del escaneo, eliminando la necesidad de reintroducir credenciales en escaneos posteriores.

## Anadido

- **B5: Carga de Credenciales desde Keyring**
  - El asistente detecta si hay credenciales guardadas de escaneos anteriores
  - Pregunta al usuario: "Credenciales guardadas encontradas. Cargarlas?"
  - Carga credenciales SSH, SMB y SNMP desde el keychain del SO
  - Omite la entrada manual de credenciales si el usuario acepta

### Detalles de Implementacion

- `KeyringCredentialProvider.has_saved_credentials()` - Verifica si algun protocolo tiene credenciales guardadas
- `KeyringCredentialProvider.get_saved_credential_summary()` - Devuelve lista de tuplas (protocolo, usuario)
- `Wizard._check_and_load_saved_credentials()` - Orquesta el flujo de deteccion y carga

## Tests

- 22 tests de credenciales pasando (4 nuevos para deteccion de credenciales)
- Validacion completa de pre-commit

## Actualizacion

```bash
cd ~/RedAudit && git pull && sudo bash redaudit_install.sh
```

## Flujo de Trabajo

1. Primer escaneo: Introducir credenciales, opcionalmente guardar en keyring
2. Segundo escaneo: El asistente detecta credenciales guardadas y ofrece cargarlas
3. Aceptar: Las credenciales se cargan automaticamente
4. Rechazar: Proceder con entrada manual de credenciales
