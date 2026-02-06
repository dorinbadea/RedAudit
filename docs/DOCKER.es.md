# Docker: Ejecutar RedAudit en Windows o macOS

RedAudit es una herramienta para Linux, pero puedes ejecutarla en **Windows** o **macOS** usando Docker.

> **Limitación Importante**: Docker en Windows/macOS **no permite descubrimiento L2 fiable** en tu red. Corre en una máquina virtual que no puede ver tu red real a nivel 2. Ver [Limitaciones](#limitaciones-en-windowsmacos) más abajo.

## Cuándo Usar Docker

| Caso de Uso | Docker en Win/Mac | Linux Nativo |
| :--- | :--- | :--- |
| **Escanear servidores conocidos** | Funciona | Funciona |
| **Demo/pruebas con IPs conocidas** | Funciona | Funciona |
| **Descubrir todos los dispositivos** | Incompleto | Funciona |
| **Auditoría profesional de red** | Limitado | Capacidad completa |
| **Escaneo ARP/Nivel 2** | No es posible | Funciona |
| **Detección VPN (MAC/GW)** | Limitada/Imprecisa | Funciona |

**Recomendación para auditorías profesionales**: Usa Linux nativo, o una VM Linux con networking en modo puente (bridged).

---

## Inicio Rápido (Recomendado)

Los scripts de ayuda manejan todo automáticamente: detectar tu red, descargar la última imagen y ejecutar el escaneo.

## macOS

### macOS: Primera vez (descargar script)

```bash
curl -O https://raw.githubusercontent.com/dorinbadea/RedAudit/main/scripts/redaudit-docker.sh
chmod +x redaudit-docker.sh
```

### macOS: Cada vez que quieras escanear

```bash
./redaudit-docker.sh
```

> Nota: El script **hace pull de la última imagen de RedAudit** antes de cada escaneo. No necesitas actualizar manualmente.

## Windows (PowerShell)

### Windows: Primera vez (descargar script)

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dorinbadea/RedAudit/main/scripts/redaudit-docker.ps1" -OutFile "redaudit-docker.ps1"
```

### Windows: Cada vez que quieras escanear

```powershell
.\redaudit-docker.ps1
```

> Nota: El script **descarga automáticamente la última imagen de RedAudit** antes de cada escaneo. No necesitas actualizar manualmente.

## Qué hacen los scripts

- Verificar que Docker esté corriendo
- Detectar tu red automáticamente
- Hacer pull de la última imagen
- Ejecutar el escaneo
- Ofrecer abrir el informe cuando termine

---

## macOS - Guía Completa

## macOS - 1. Instalar Docker Desktop

1. Ve a: **<https://www.docker.com/products/docker-desktop/>**

2. Haz clic en **Download for Mac**
   - **Apple Silicon** (M1/M2/M3/M4): Elige "Mac with Apple chip"
   - **Intel Mac**: Elige "Mac with Intel chip"
   - *¿No estás seguro? Menú Apple → Acerca de este Mac → Mira si dice "Apple M1/M2/M3" o "Intel"*

3. Abre el archivo `.dmg` descargado

4. Arrastra Docker a tu carpeta de **Aplicaciones**

5. Abre Docker desde Aplicaciones

6. Haz clic en **Abrir** cuando macOS pida permiso

7. Acepta el acuerdo de licencia

8. Salta el tutorial/inicio de sesión (no es necesario)

9. **Espera** hasta que el icono de la ballena en la barra de menú esté **verde**

## macOS - 2. Abrir Terminal

1. Presiona **Cmd + Espacio**
2. Escribe **Terminal**
3. Presiona **Enter**

## macOS - 3. Descargar RedAudit

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

Espera a que la descarga se complete (unos 500MB, 1-5 minutos).

Verifica que la imagen está descargada:

```bash
docker images | grep redaudit
```

## macOS - 4. Crear Carpeta de Informes

```bash
mkdir ~/RedAudit-Reports
```

## macOS - 5. Encontrar Tu Red

Docker en macOS no puede detectar automáticamente tu red real. Encuentra tu IP:

```bash
ipconfig getifaddr en0
```

Ejemplo de salida: `192.168.178.35`

Tu red sería: `192.168.178.0/24` (reemplaza el último número con `0/24`)

## macOS - 6. Ejecutar RedAudit

**Opción A - Con tu red (recomendado):**

```bash
docker run -it --rm \
  -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.178.0/24 \
  --lang es \
  --output /reports
```

**Opción B - Wizard interactivo:**

```bash
docker run -it --rm \
  -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --lang es
```

*Nota: El asistente mostrará la red interna de Docker (172.17.x.x). Debes introducir manualmente tu red real.*

## macOS - 7. Ver Informes

```bash
open ~/RedAudit-Reports/report.html
```

---

## Windows - Guía Completa

## Windows - 1. Instalar Docker Desktop

1. Ve a: **<https://www.docker.com/products/docker-desktop/>**

2. Haz clic en **Download for Windows**

3. Ejecuta **Docker Desktop Installer.exe**

4. Sigue el asistente de instalación (mantén la configuración por defecto)

5. **Reinicia Windows** cuando te lo pida

6. Abre **Docker Desktop** desde el menú Inicio

7. Salta el tutorial/inicio de sesión (no es necesario)

8. **Espera** hasta que el icono de la ballena en la bandeja del sistema esté **verde**

> **Windows 10/11 Home**: Docker puede pedirte que instales WSL2. Sigue las instrucciones - es necesario.

## Windows - 2. Abrir PowerShell

1. Presiona **Win + X**
2. Haz clic en **Windows PowerShell** o **Terminal**

## Windows - 3. Descargar RedAudit

```powershell
docker pull ghcr.io/dorinbadea/redaudit:latest
```

Espera a que la descarga se complete.

Verifica:

```powershell
docker images | Select-String redaudit
```

## 4. Crear Carpeta de Informes

```powershell
mkdir C:\RedAudit-Reports
```

## 5. Encontrar Tu Red

Docker en Windows no puede detectar automáticamente tu red real. Encuentra tu IP:

```powershell
ipconfig
```

Busca "Dirección IPv4" bajo tu adaptador de red (ej., `192.168.1.50`).

Tu red sería: `192.168.1.0/24` (reemplaza el último número con `0/24`)

## Windows - 6. Ejecutar RedAudit

**Opción A - Con tu red (recomendado):**

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest --target 192.168.1.0/24 --lang es --output /reports
```

**Opción B - Wizard interactivo:**

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest --lang es
```

## Windows - 7. Ver Informes

Abre el Explorador de Archivos → Navega a `C:\RedAudit-Reports` → Haz doble clic en `report.html`

---

## Linux - Guía Completa

En Linux, puedes instalar RedAudit **nativamente** (recomendado) o usar Docker.

## Opción A: Instalación Nativa (Recomendada)

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

Luego ejecuta:

```bash
sudo redaudit
```

## Opción B: Docker con Host Networking

Docker en Linux soporta `--network host`, que da visibilidad completa de la red:

### 1. Instalar Docker

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# Cierra sesión y vuelve a entrar

# Fedora/RHEL
sudo dnf install -y docker
sudo systemctl enable --now docker
```

### 2. Descargar RedAudit

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

### 3. Ejecutar con Host Networking

```bash
sudo docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 \
  --mode normal \
  --yes \
  --output /reports
```

**Ventajas de `--network host` en Linux:**

- Visibilidad completa de la red
- Escaneo ARP funciona
- Todos los protocolos de descubrimiento funcionan
- Mismo rendimiento que nativo

---

## Limitaciones en Windows/macOS

En Windows y macOS, Docker corre dentro de una **máquina virtual**:

```text
┌─────────────────────────────────────────┐
│  Tu Ordenador                           │
│  └─ Red real: 192.168.x.x              │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  VM de Docker                     │  │
│  │  └─ Red virtual: 172.17.x.x       │  │
│  │                                   │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  Contenedor RedAudit        │  │  │
│  │  │  ← Solo ve 172.17.x.x       │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Solución**: Siempre especifica `--target` con tu red real cuando ejecutes en Windows/macOS.

---

## Auditorías Profesionales

Para auditorías de seguridad autorizadas en entornos corporativos:

## Mejor Enfoque: VM Linux

1. Instala VirtualBox, VMware, o Parallels
2. Crea una VM Ubuntu o Kali Linux con **networking en puente (bridged)**
3. Instala Docker dentro de la VM
4. Ejecuta con `--network host`

Esto te da **visibilidad completa Capa 2/3** para:

- Escaneo ARP
- Descubrimiento de VLANs
- Enumeración NetBIOS
- Escaneo completo de subred

## Alternativa: Objetivos Específicos

Si no puedes usar una VM, especifica IPs exactas:

```bash
docker run -it --rm -v ~/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.1,192.168.1.10,192.168.1.50 \
  --mode deep \
  --output /reports
```

---

## Referencia Rápida

| Acción | Comando |
| :--- | :--- |
| Descargar/Actualizar | `docker pull ghcr.io/dorinbadea/redaudit:latest` |
| Ejecutar (Español) | `docker run -it --rm -v ~/reports:/reports ghcr.io/dorinbadea/redaudit:latest --target TU_RED --lang es --output /reports` |
| Ejecutar (Inglés) | `docker run -it --rm -v ~/reports:/reports ghcr.io/dorinbadea/redaudit:latest --target TU_RED --output /reports` |
| Mostrar ayuda | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --help` |
| Ver versión | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --version` |

---

## Solución de Problemas

## "Cannot connect to Docker daemon"

Docker Desktop no está corriendo. Abre Docker Desktop y espera al indicador verde.

## "No matching manifest for linux/arm64"

Tu imagen está desactualizada. Actualízala:

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

## Los escaneos no encuentran hosts

Probablemente estás escaneando la red interna de Docker (172.17.x.x) en lugar de tu red real. Usa `--target` con el CIDR de tu red real.

## Masscan y Redes Docker Bridge (v4.7.1+)

> **Nota**: Masscan usa su propia pila de red (sockets raw libpcap) que tiene problemas conocidos con las redes bridge de Docker (172.x.x.x). Al escanear contenedores Docker desde el host, masscan puede retornar 0 puertos aunque haya servicios corriendo.

**RedAudit maneja esto automaticamente**:

- Si masscan encuentra 0 puertos, RedAudit usa Scapy como fallback para deteccion precisa
- Las redes fisicas (192.168.x.x, 10.x.x.x) funcionan normalmente con masscan
- Las redes Docker se escanean via fallback Scapy (un poco mas lento pero fiable)

**Si estás probando RedAudit contra contenedores Docker**:

- Espera que el escaneo use Scapy en lugar de masscan para subredes Docker
- Los tiempos de escaneo seran ~1 min/host en lugar de segundos para redes Docker
- Los resultados son precisos; solo difiere la velocidad

## Permiso denegado

En Linux, ejecuta con `sudo` o añade tu usuario al grupo docker:

```bash
sudo usermod -aG docker $USER
```

Luego cierra sesión y vuelve a entrar.

## Texto ilegible / caracteres raros en Windows

Si ves texto como `[1m[95m` o `[0m[91m` en lugar de colores, tu terminal no soporta códigos de escape ANSI.

**Soluciones:**

1. **Usa el script de ayuda** - Detecta y corrige esto automáticamente:

   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dorinbadea/RedAudit/main/scripts/redaudit-docker.ps1" -OutFile "redaudit-docker.ps1"
   .\redaudit-docker.ps1
   ```

2. **Usa Windows Terminal** (recomendado) - Descárgalo gratis desde Microsoft Store

3. **Añade --no-color** a tu comando:

   ```powershell
   docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest --target TU_RED --no-color --output /reports
   ```

| Terminal | Colores ANSI |
| :--- | :--- |
| Windows Terminal | Sí |
| PowerShell 7+ | Sí |
| PowerShell 5 (negro) | Parcial |
| PowerShell ISE (azul) | No |
| CMD | Parcial |
