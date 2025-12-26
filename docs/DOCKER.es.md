# Guía de Uso con Docker

RedAudit está disponible como imagen Docker para usuarios en **Windows**, **macOS**, o cualquier sistema donde la instalación nativa en Linux no sea práctica.

## Inicio Rápido

```bash
# Descargar la imagen
docker pull ghcr.io/dorinbadea/redaudit:latest

# Ejecutar un escaneo
docker run --rm -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

---

## Windows

### Configuración

1. Descarga e instala [Docker Desktop para Windows](https://www.docker.com/products/docker-desktop/)
2. Reinicia Windows y abre Docker Desktop
3. Espera a que el icono de la ballena en el systray esté verde

### Ejecutar un Escaneo

```powershell
# Crear carpeta de reportes
mkdir C:\RedAudit-Reports

# Ejecutar escaneo
docker run --rm ^
  -v C:\RedAudit-Reports:/reports ^
  ghcr.io/dorinbadea/redaudit:latest ^
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

### Wizard Interactivo

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

---

## macOS

### Configuración

1. Descarga [Docker Desktop para Mac](https://www.docker.com/products/docker-desktop/) (elige Apple Silicon o Intel)
2. Arrastra Docker.app a Aplicaciones y ábrelo
3. Espera a que el icono de la ballena en la barra de menú esté verde

### Ejecutar un Escaneo

```bash
# Crear carpeta de reportes
mkdir -p ~/RedAudit-Reports

# Ejecutar escaneo
docker run --rm \
  -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports

# Abrir el reporte
open ~/RedAudit-Reports/report.html
```

### Wizard Interactivo

```bash
docker run -it --rm -v ~/RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

---

## Linux (con host networking)

Los usuarios de Linux pueden usar host networking para mejor visibilidad de la red local:

```bash
docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

---

## Limitaciones

| Plataforma | `--network host` | Notas |
|:-----------|:-----------------|:------|
| Linux | ✅ Soportado | Visibilidad completa de la red local |
| macOS | ❌ No soportado | Docker corre en una VM; especifica targets manualmente |
| Windows | ❌ No soportado | Igual que macOS |

> **Tip**: En Windows/macOS, especifica siempre las IPs objetivo explícitamente. La auto-detección del wizard mostrará las interfaces del contenedor, no las del host.

---

## Comandos Comunes

| Acción | Comando |
|:-------|:--------|
| Mostrar ayuda | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --help` |
| Mostrar versión | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --version` |
| Escaneo rápido | `docker run --rm -v ./reports:/reports ghcr.io/dorinbadea/redaudit:latest --target 192.168.1.1 --mode quick --yes --output /reports` |
