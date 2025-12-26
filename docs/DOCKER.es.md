# Docker: Ejecutar RedAudit en Windows o macOS

## ¿Qué es Docker y Por Qué Usarlo?

**Docker** es como una "caja virtual" que ejecuta aplicaciones de Linux en cualquier ordenador. Como RedAudit está diseñado para Linux, Docker te permite usarlo en **Windows** o **macOS** sin configuraciones complejas.

**Beneficios:**

- ✅ No necesitas instalar Linux
- ✅ No hay dependencias que configurar
- ✅ Funciona exactamente igual en todos lados
- ✅ Fácil de actualizar (solo descargas una nueva imagen)

---

# Guía para macOS

## Paso 1: Instalar Docker Desktop

1. **Ve a**: <https://www.docker.com/products/docker-desktop/>
2. **Haz clic** en el botón **Download**
   - Si tienes un Mac nuevo (M1, M2, M3, M4): elige **"Mac with Apple chip"**
   - Si tienes un Mac Intel antiguo: elige **"Mac with Intel chip"**
   - *¿No estás seguro? Haz clic en el menú Apple → "Acerca de este Mac" → mira si dice "Apple M1/M2/M3" o "Intel"*
3. **Abre** el archivo `.dmg` descargado
4. **Arrastra** el icono de Docker a tu carpeta de Aplicaciones
5. **Abre** Docker desde tu carpeta de Aplicaciones
6. **Haz clic en "Abrir"** cuando macOS pida permiso
7. **Acepta** el acuerdo de licencia
8. **Salta** o cierra los tutoriales/inicio de sesión (no necesitas cuenta)
9. **Espera** hasta ver un **indicador verde** en la barra de menú superior (el icono de la ballena)

> 💡 **Consejo**: Docker puede pedir tu contraseña para instalar componentes. Esto es normal.

## Paso 2: Abrir Terminal

1. Presiona **Cmd + Espacio** (abre Spotlight)
2. Escribe **Terminal**
3. Presiona **Enter**

Se abrirá una ventana negra/blanca. Aquí es donde escribirás los comandos.

## Paso 3: Descargar RedAudit

Copia y pega este comando en Terminal, luego presiona **Enter**:

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

Verás el progreso de descarga. Esto descarga unos 500MB y tarda 1-5 minutos dependiendo de tu internet.

## Paso 4: Crear una Carpeta para Reportes

```bash
mkdir -p ~/RedAudit-Reports
```

Esto crea una carpeta en tu directorio personal donde se guardarán los reportes de escaneo.

## Paso 5: Ejecutar RedAudit (Wizard Interactivo)

Esta es la **manera recomendada** para usuarios nuevos:

```bash
docker run -it --rm -v ~/RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

**Qué hace este comando:**

- `docker run` - inicia un contenedor
- `-it` - lo hace interactivo (puedes escribir)
- `--rm` - limpia todo cuando terminas
- `-v ~/RedAudit-Reports:/reports` - guarda reportes en tu carpeta
- La última parte es la imagen de RedAudit

**El wizard te guiará a través de:**

1. Seleccionar tu idioma (Inglés/Español)
2. Introducir la red objetivo (ej., `192.168.1.0/24`)
3. Elegir modo de escaneo (quick/normal/deep)
4. Opciones adicionales

> 💡 **Encontrar tu red**: Ejecuta `ipconfig getifaddr en0` para ver tu IP. Si es `192.168.1.50`, tu red probablemente es `192.168.1.0/24`.

## Paso 6: Ver Reportes

Cuando el escaneo termine, abre el reporte HTML:

```bash
open ~/RedAudit-Reports/report.html
```

Esto abre un reporte bonito e interactivo en tu navegador web.

---

# Guía para Windows

## Paso 1: Instalar Docker Desktop

1. **Ve a**: <https://www.docker.com/products/docker-desktop/>
2. **Haz clic** en "Download for Windows"
3. **Ejecuta** el instalador descargado (`Docker Desktop Installer.exe`)
4. **Sigue** las instrucciones de instalación (mantén la configuración por defecto)
5. **Reinicia** tu ordenador cuando te lo pida
6. **Abre** Docker Desktop desde el menú Inicio
7. **Salta** el tutorial y la creación de cuenta (no es necesario)
8. **Espera** hasta ver un **indicador verde** en la bandeja del sistema (abajo a la derecha, icono de ballena)

> ⚠️ **Usuarios de Windows 10/11 Home**: Docker puede pedirte que instales WSL2. Sigue las instrucciones para instalarlo - es necesario.

## Paso 2: Abrir PowerShell

1. Presiona **Win + X**
2. Haz clic en **"Windows PowerShell"** o **"Terminal"**

Se abrirá una ventana azul/negra.

## Paso 3: Descargar RedAudit

Copia y pega este comando, luego presiona **Enter**:

```powershell
docker pull ghcr.io/dorinbadea/redaudit:latest
```

Espera a que la descarga se complete (1-5 minutos).

## Paso 4: Crear una Carpeta para Reportes

```powershell
mkdir C:\RedAudit-Reports
```

## Paso 5: Ejecutar RedAudit (Wizard Interactivo)

Esta es la **manera recomendada** para usuarios nuevos:

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

**El wizard te guiará a través de todo:**

1. Seleccionar idioma
2. Introducir red objetivo
3. Elegir modo de escaneo
4. ¡Empezar a escanear!

> 💡 **Encontrar tu red**: Ejecuta `ipconfig` y busca "Dirección IPv4". Si es `192.168.1.50`, tu red es `192.168.1.0/24`.

## Paso 6: Ver Reportes

1. Abre el **Explorador de Archivos**
2. Navega a `C:\RedAudit-Reports`
3. Haz doble clic en `report.html`

---

# Referencia Rápida

## Comandos Más Comunes

| Qué quieres hacer | Comando |
|-------------------|---------|
| **Iniciar wizard** (recomendado) | `docker run -it --rm -v ~/RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest` |
| Actualizar a última versión | `docker pull ghcr.io/dorinbadea/redaudit:latest` |
| Mostrar ayuda | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --help` |
| Ver versión | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --version` |

## Solución de Problemas

### "Cannot connect to Docker daemon"

Docker Desktop no está corriendo. Abre Docker Desktop y espera al indicador verde.

### "No matching manifest for linux/arm64"

Tienes una imagen antigua. Ejecuta:

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

### Los escaneos no encuentran hosts

En Windows/macOS, Docker corre en un entorno virtual y puede no ver todos los dispositivos de la red local. Intenta escanear IPs específicas en lugar de rangos.

---

# Auditorías de Red Profesionales

## Por Qué Importa la Visibilidad de Red

Cuando realizas auditorías de seguridad autorizadas para tu empresa o clientes, necesitas que Docker vea la misma red que tu ordenador. Esta sección explica cómo lograrlo.

## Opción 1: Usar una VM Linux (Recomendado para Profesionales)

La manera más fiable de realizar auditorías de red desde Windows/macOS es ejecutar una máquina virtual Linux ligera:

1. **Instala una VM** como VirtualBox, VMware, o Parallels
2. **Crea una VM Ubuntu/Kali** con networking en modo puente (bridged)
3. **Instala Docker en la VM** y ejecuta RedAudit con `--network host`

```bash
# Dentro de la VM Linux
docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

Esto te da **visibilidad completa de red Capa 2/3** para escaneo ARP, descubrimiento de hosts, y escaneo profundo.

## Opción 2: Escanear Objetivos Específicos

Si una VM no es práctico, aún puedes realizar auditorías efectivas apuntando a direcciones IP específicas:

```bash
# Objetivo único
docker run -it --rm -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.100 --mode deep --yes --output /reports

# Múltiples objetivos específicos
docker run -it --rm -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.1,192.168.1.10,192.168.1.50 --mode normal --yes --output /reports
```

## Opción 3: Usar host.docker.internal (Limitado)

En Windows/macOS, puedes acceder a servicios en tu máquina host usando el hostname especial `host.docker.internal`:

```bash
docker run -it --rm -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target host.docker.internal --mode quick --yes --output /reports
```

> ⚠️ **Importante**: Esto solo escanea servicios en TU máquina, no otros dispositivos de la red.

## Comparación de Visibilidad de Red

| Método | Descubrimiento de Hosts | Escaneo Subred Completa | Capa 2 (ARP) |
|--------|------------------------|------------------------|--------------|
| Docker Windows/macOS | ❌ Limitado | ⚠️ Parcial | ❌ No |
| VM Linux + Docker | ✅ Completo | ✅ Completo | ✅ Sí |
| Linux Nativo | ✅ Completo | ✅ Completo | ✅ Sí |

## Para Despliegues Empresariales

Para auditorías de seguridad regulares en entornos corporativos, recomendamos:

1. **Máquina dedicada de auditoría Linux** (física o VM) con RedAudit instalado nativamente
2. **O**: Docker en un servidor Linux con `--network host`
3. **Programar escaneos regulares** usando cron o tu pipeline CI/CD
4. **Exportar reportes** a tu SIEM (RedAudit soporta JSONL para Splunk/ELK)

---

# Usuarios de Linux

Si estás en Linux, ¡no necesitas Docker! Instala RedAudit nativamente:

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh
```

Si aún así quieres Docker en Linux (para aislamiento):

```bash
docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

La opción `--network host` da visibilidad completa de la red (solo funciona en Linux).
