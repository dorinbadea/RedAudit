# Docker: Run RedAudit on Windows or macOS

RedAudit is a Linux tool, but you can run it on **Windows** or **macOS** using Docker.

> **Important Limitation**: Docker on Windows/macOS **cannot perform reliable L2 discovery** on your network. It runs inside a virtual machine that cannot see your real network at Layer 2. See [Limitations](#limitations-on-windowsmacos) below.

## When to Use Docker

| Use Case | Docker on Win/Mac | Linux Native |
| :--- | :--- | :--- |
| **Scan specific known servers** | Works | Works |
| **Demo/testing with known IPs** | Works | Works |
| **Discover all devices on network** | Incomplete | Works |
| **Professional network audit** | Limited | Full capability |
| **ARP/Layer 2 scanning** | Not possible | Works |
| **VPN Detection (MAC/GW)** | Limited/Inaccurate | Works |

**Recommendation for professional audits**: Use Linux natively, or a Linux VM with bridged networking.

---

## Quick Start (Recommended)

The helper scripts handle everything automatically: detecting your network, pulling the latest image, and running the scan.

## macOS

### macOS: First time (download script)

```bash
curl -O https://raw.githubusercontent.com/dorinbadea/RedAudit/main/scripts/redaudit-docker.sh
chmod +x redaudit-docker.sh
```

### macOS: Every time you scan

```bash
./redaudit-docker.sh
```

> Note: The script **automatically pulls the latest RedAudit image** before each scan. You don't need to update manually.

## Windows (PowerShell)

### Windows: First time (download script)

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dorinbadea/RedAudit/main/scripts/redaudit-docker.ps1" -OutFile "redaudit-docker.ps1"
```

### Windows: Every time you scan

```powershell
.\redaudit-docker.ps1
```

> Note: The script **automatically downloads the latest RedAudit image** before each scan. You don't need to update manually.

## What the scripts do

- Check that Docker is running
- Detect your network automatically
- Pull the latest RedAudit image (best-effort)
- Run the scan
- Offer to open the report when finished

---

## macOS - Complete Guide

## macOS - 1. Install Docker Desktop

1. Go to: **<https://www.docker.com/products/docker-desktop/>**

2. Click **Download for Mac**
   - **Apple Silicon** (M1/M2/M3/M4): Choose "Mac with Apple chip"
   - **Intel Mac**: Choose "Mac with Intel chip"
   - *Not sure? Apple menu → About This Mac → Check if it says "Apple M1/M2/M3" or "Intel"*

3. Open the downloaded `.dmg` file

4. Drag Docker to your **Applications** folder

5. Open Docker from Applications

6. Click **Open** when macOS asks for permission

7. Accept the license agreement

8. Skip the tutorial/sign-in (not required)

9. **Wait** until the whale icon in the menu bar turns **green**

## macOS - 2. Open Terminal

1. Press **Cmd + Space**
2. Type **Terminal**
3. Press **Enter**

## 3. Download RedAudit

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

Wait for the download to complete (about 500MB, 1-5 minutes).

Verify the image is downloaded:

```bash
docker images | grep redaudit
```

## macOS - 4. Create Reports Folder

```bash
mkdir -p ~/RedAudit-Reports
```

## macOS - 5. Find Your Network

Docker on macOS cannot auto-detect your real network. Find your IP:

```bash
ipconfig getifaddr en0
```

Example output: `192.168.178.35`

Your network would be: `192.168.178.0/24` (replace the last number with `0/24`)

## macOS - 6. Run RedAudit

**Option A - With your network (recommended):**

```bash
docker run -it --rm \
  -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.178.0/24 \
  --lang es \
  --output /reports
```

**Option B - Interactive wizard:**

```bash
docker run -it --rm \
  -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --lang es
```

*Note: The wizard will show Docker's internal network (172.17.x.x). You must manually enter your real network.*

## macOS - 7. View Reports

```bash
open ~/RedAudit-Reports/report.html
```

---

## Windows - Complete Guide

## Windows - 1. Install Docker Desktop

1. Go to: **<https://www.docker.com/products/docker-desktop/>**

2. Click **Download for Windows**

3. Run **Docker Desktop Installer.exe**

4. Follow the installation wizard (keep default settings)

5. **Restart Windows** when prompted

6. Open **Docker Desktop** from the Start menu

7. Skip the tutorial/sign-in (not required)

8. **Wait** until the whale icon in the system tray turns **green**

> **Windows 10/11 Home**: Docker may ask you to install WSL2. Follow the prompts - this is required.

## Windows - 2. Open PowerShell

1. Press **Win + X**
2. Click **Windows PowerShell** or **Terminal**

## Windows - 3. Download RedAudit

```powershell
docker pull ghcr.io/dorinbadea/redaudit:latest
```

Wait for the download to complete.

Verify:

```powershell
docker images | Select-String redaudit
```

## 4. Create Reports Folder

```powershell
mkdir C:\RedAudit-Reports
```

## 5. Find Your Network

Docker on Windows cannot auto-detect your real network. Find your IP:

```powershell
ipconfig
```

Look for "IPv4 Address" under your network adapter (e.g., `192.168.1.50`).

Your network would be: `192.168.1.0/24` (replace the last number with `0/24`)

## Windows - 6. Run RedAudit

**Option A - With your network (recommended):**

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest --target 192.168.1.0/24 --lang es --output /reports
```

**Option B - Interactive wizard:**

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest --lang es
```

## Windows - 7. View Reports

Open File Explorer → Navigate to `C:\RedAudit-Reports` → Double-click `report.html`

---

## Linux - Complete Guide

On Linux, you can install RedAudit **natively** (recommended) or use Docker.

## Option A: Native Installation (Recommended)

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

Then run:

```bash
sudo redaudit
```

## Option B: Docker with Host Networking

Linux Docker supports `--network host`, which gives full network visibility:

### 1. Install Docker

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# Log out and back in

# Fedora/RHEL
sudo dnf install -y docker
sudo systemctl enable --now docker
```

### 2. Download RedAudit

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

### 3. Run with Host Networking

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

**Advantages of `--network host` on Linux:**

- Full network visibility
- ARP scanning works
- All discovery protocols work
- Same performance as native

---

## Limitations on Windows/macOS

On Windows and macOS, Docker runs inside a **virtual machine**:

```text
┌─────────────────────────────────────────┐
│  Your Computer                          │
│  └─ Real network: 192.168.x.x          │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Docker VM                        │  │
│  │  └─ Virtual network: 172.17.x.x   │  │
│  │                                   │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  RedAudit Container         │  │  │
│  │  │  ← Only sees 172.17.x.x     │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Solution**: Always specify `--target` with your real network when running on Windows/macOS.

---

## Professional Audits

For authorized security audits in corporate environments:

## Best Approach: Linux VM

1. Install VirtualBox, VMware, or Parallels
2. Create an Ubuntu or Kali Linux VM with **bridged networking**
3. Install Docker inside the VM
4. Run with `--network host`

This gives you **full Layer 2/3 visibility** for:

- ARP scanning
- VLAN discovery
- NetBIOS enumeration
- Full subnet scanning

## Alternative: Specific Targets

If you can't use a VM, specify exact IPs:

```bash
docker run -it --rm -v ~/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.1,192.168.1.10,196.168.1.50 \
  --mode deep \
  --output /reports
```

---

## Quick Reference

| Action          | Command                                                                                                                      |
| :---            | :---                                                                                                                         |
| Download/Update | `docker pull ghcr.io/dorinbadea/redaudit:latest`                                                                             |
| Run (Spanish)   | `docker run -it --rm -v ~/reports:/reports ghcr.io/dorinbadea/redaudit:latest --target YOUR_NET --lang es --output /reports` |
| Run (English)   | `docker run -it --rm -v ~/reports:/reports ghcr.io/dorinbadea/redaudit:latest --target YOUR_NET --output /reports`           |
| Show help       | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --help`                                                                  |
| View version    | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --version`                                                               |

---

## Troubleshooting

## "Cannot connect to Docker daemon"

Docker Desktop isn't running. Open Docker Desktop and wait for the green indicator.

## "No matching manifest for linux/arm64"

Your image is outdated. Update it:

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

## Scans not finding hosts

You're probably scanning Docker's internal network (172.17.x.x) instead of your real network. Use `--target` with your actual network CIDR.

## Masscan and Docker Bridge Networks (v4.7.1+)

> **Note**: Masscan uses its own network stack (libpcap raw sockets) which has known issues with Docker bridge networks (172.x.x.x). When scanning Docker containers from a host, masscan may return 0 ports even when services are running.

**RedAudit handles this automatically**:

- If masscan finds 0 ports, RedAudit falls back to Scapy for accurate detection
- Physical networks (192.168.x.x, 10.x.x.x) work normally with masscan
- Docker networks are scanned via Scapy fallback (slightly slower but reliable)

**If you're testing RedAudit against Docker containers**:

- Expect the scan to use Scapy instead of masscan for Docker subnets
- Scan times will be ~1 min/host instead of seconds for Docker networks
- Results are accurate; only the speed differs

## Permission denied

On Linux, run with `sudo` or add your user to the docker group:

```bash
sudo usermod -aG docker $USER
```

Then log out and back in.

## Garbled text / weird characters on Windows

If you see text like `[1m[95m` or `[0m[91m` instead of colors, your terminal doesn't support ANSI escape codes.

**Solutions:**

1. **Use the helper script** - It auto-detects and fixes this:

   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dorinbadea/RedAudit/main/scripts/redaudit-docker.ps1" -OutFile "redaudit-docker.ps1"
   .\redaudit-docker.ps1
   ```

2. **Use Windows Terminal** (recommended) - Download free from Microsoft Store

3. **Add --no-color** to your command:

   ```powershell
   docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest --target YOUR_NETWORK --no-color --output /reports
   ```

| Terminal | ANSI Colors |
| :--- | :--- |
| Windows Terminal | Yes |
| PowerShell 7+ | Yes |
| PowerShell 5 (black) | Partial |
| PowerShell ISE (blue) | No |
| CMD | Partial |
