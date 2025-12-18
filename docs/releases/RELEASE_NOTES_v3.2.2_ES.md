# RedAudit v3.2.2 - Notas de versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.2.2.md)

**Fecha de release**: 16 de diciembre de 2025
**Tipo**: Production Hardening
**Versión anterior**: v3.2.1

---

## Visión general

La versión 3.2.2 se centra en el hardening de producción: actualizaciones más seguras con instalación atómica y rollback, salida CLI más limpia y documentación de seguridad honesta.

---

## Novedades en v3.2.2

### 1. Instalación Atómica Staged

El sistema de actualización usa ahora un enfoque staged:

1. Los nuevos archivos se copian a un directorio temporal `.new`
2. El directorio staged se valida verificando archivos clave
3. La instalación actual se renombra a `.old`
4. El directorio staged se renombra atómicamente a la ubicación final
5. Si algún paso falla, el rollback automático restaura la versión anterior

Esto previene el estado "medio instalado" que podía ocurrir si el sistema fallaba durante la actualización.

### 2. CLI Output Polish

Los tokens de estado internos (`OKGREEN`, `OKBLUE`, `WARNING`) ahora se mapean a labels user-friendly en todos los modos de salida:

| Token Interno | Label Visible |
|--------------|---------------|
| `OKGREEN` | `OK` |
| `OKBLUE` | `INFO` |
| `HEADER` | `INFO` |
| `WARNING` | `WARN` |
| `FAIL` | `FAIL` |

### 3. Documentación de Seguridad Honesta

- Renombrado "Secure Update Module" → "Reliable Update Module"
- SECURITY.es.md Sección 7 clarifica verificación de integridad (hashes git) vs. autenticidad (firmas criptográficas)
- Nota explícita: **no se realiza verificación de firmas GPG**

---

## ⚠️ Aviso de Actualización para Usuarios de v3.2.1

La auto-actualización de v3.2.1 → v3.2.2 puede fallar con "Clone verification failed" debido a un bug en cómo se resolvían los tags git anotados. El fix está incluido en v3.2.2, pero los usuarios en v3.2.1 necesitan reinstalar manualmente (solo una vez):

```bash
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/v3.2.2/redaudit_install.sh | sudo bash
```

**Después de esta actualización manual, todas las futuras auto-actualizaciones funcionarán correctamente.**

---

## Enlaces útiles

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
- **Documentación de seguridad**: [docs/en/SECURITY.es.md](../SECURITY.es.md) / [docs/es/SECURITY.es.md](../SECURITY.es.md)
