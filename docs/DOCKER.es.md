# Guía de Uso con Docker

RedAudit está disponible como imagen Docker para usuarios en **Windows**, **macOS**, o cualquier sistema donde la instalación nativa en Linux no sea práctica.

---

## macOS

### Paso 1: Instalar Docker Desktop

1. Descarga [Docker Desktop para Mac](https://www.docker.com/products/docker-desktop/)
   - Elige **Apple Silicon** (M1/M2/M3) o **Intel** según tu Mac
2. Abre el archivo `.dmg` descargado
3. Arrastra `Docker.app` a tu carpeta de Aplicaciones
4. Abre Docker Desktop desde Aplicaciones
5. Acepta la licencia y concede los permisos cuando te lo pida
6. Espera a que el icono de la ballena en la barra de menú esté **verde** (esto significa que Docker está corriendo)

### Paso 2: Abrir Terminal

Presiona `Cmd + Espacio`, escribe "Terminal" y ábrela.

### Paso 3: Descargar la Imagen de RedAudit

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

Verás barras de progreso de descarga. Esto descarga ~300-500MB.

### Paso 4: Crear una Carpeta para Reportes

```bash
mkdir -p ~/RedAudit-Reports
```

### Paso 5: Ejecutar RedAudit

**Opción A - Wizard Interactivo (recomendado para primera vez):**

```bash
docker run -it --rm -v ~/RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

El wizard te guiará para seleccionar idioma, red objetivo, modo de escaneo, etc.

**Opción B - Escaneo Directo (reemplaza con tu red):**

```bash
docker run --rm -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode quick --yes --output /reports
```

> 💡 **Tip**: Para saber tu IP, ejecuta: `ipconfig getifaddr en0`

### Paso 6: Ver los Resultados

```bash
open ~/RedAudit-Reports/report.html
```

Esto abre el reporte HTML en tu navegador predeterminado.

---

## Windows

### Paso 1: Instalar Docker Desktop

1. Descarga [Docker Desktop para Windows](https://www.docker.com/products/docker-desktop/)
2. Ejecuta el instalador y sigue las instrucciones
3. **Reinicia Windows** cuando te lo pida
4. Abre Docker Desktop desde el menú Inicio
5. Espera a que el icono de la ballena en la bandeja del sistema esté **verde**

### Paso 2: Abrir PowerShell

Presiona `Win + X` y selecciona "Windows PowerShell" o "Terminal".

### Paso 3: Descargar la Imagen de RedAudit

```powershell
docker pull ghcr.io/dorinbadea/redaudit:latest
```

### Paso 4: Crear una Carpeta para Reportes

```powershell
mkdir C:\RedAudit-Reports
```

### Paso 5: Ejecutar RedAudit

**Opción A - Wizard Interactivo:**

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

**Opción B - Escaneo Directo:**

```powershell
docker run --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest --target 192.168.1.0/24 --mode quick --yes --output /reports
```

> 💡 **Tip**: Para saber tu IP, ejecuta: `ipconfig` y busca "Dirección IPv4"

### Paso 6: Ver los Resultados

Abre el Explorador de Archivos y navega a `C:\RedAudit-Reports`. Haz doble clic en `report.html`.

---

## Linux

Los usuarios de Linux pueden usar host networking para visibilidad completa de la red local:

```bash
# Descargar
docker pull ghcr.io/dorinbadea/redaudit:latest

# Ejecutar con host networking (recomendado)
docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

---

## Limitaciones por Plataforma

| Plataforma | `--network host` | Visibilidad de Red Local |
|------------|------------------|--------------------------|
| Linux      | ✅ Soportado      | Visibilidad completa     |
| macOS      | ❌ No soportado   | Especifica targets manualmente |
| Windows    | ❌ No soportado   | Especifica targets manualmente |

> **Nota**: En Windows y macOS, Docker corre dentro de una máquina virtual. La auto-detección del wizard mostrará las interfaces del contenedor, no la red de tu host. Siempre especifica las IPs objetivo explícitamente.

---

## Referencia Rápida

| Acción | Comando |
|--------|---------|
| Mostrar ayuda | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --help` |
| Mostrar versión | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --version` |
| Wizard interactivo | `docker run -it --rm -v ~/reports:/reports ghcr.io/dorinbadea/redaudit:latest` |
| Escaneo rápido | `docker run --rm -v ~/reports:/reports ghcr.io/dorinbadea/redaudit:latest --target IP --mode quick --yes --output /reports` |
