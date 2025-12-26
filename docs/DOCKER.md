# Docker Usage Guide

RedAudit is available as a Docker image for users on **Windows**, **macOS**, or any system where native Linux installation isn't practical.

---

## macOS

### Step 1: Install Docker Desktop

1. Download [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/)
   - Choose **Apple Silicon** (M1/M2/M3) or **Intel** based on your Mac
2. Open the downloaded `.dmg` file
3. Drag `Docker.app` to your Applications folder
4. Open Docker Desktop from Applications
5. Accept the license and grant permissions when prompted
6. Wait for the whale icon in the menu bar to turn **green** (this means Docker is running)

### Step 2: Open Terminal

Press `Cmd + Space`, type "Terminal", and open it.

### Step 3: Download the RedAudit Image

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest
```

You'll see download progress bars. This downloads ~300-500MB.

### Step 4: Create a Reports Folder

```bash
mkdir -p ~/RedAudit-Reports
```

### Step 5: Run RedAudit

**Option A - Interactive Wizard (recommended for first time):**

```bash
docker run -it --rm -v ~/RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

The wizard will guide you through selecting language, target network, scan mode, etc.

**Option B - Direct Scan (replace with your network):**

```bash
docker run --rm -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode quick --yes --output /reports
```

> 💡 **Tip**: To find your IP, run: `ipconfig getifaddr en0`

### Step 6: View the Results

```bash
open ~/RedAudit-Reports/report.html
```

This opens the HTML report in your default browser.

---

## Windows

### Step 1: Install Docker Desktop

1. Download [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Run the installer and follow the prompts
3. **Restart Windows** when prompted
4. Open Docker Desktop from the Start menu
5. Wait for the whale icon in the system tray to turn **green**

### Step 2: Open PowerShell

Press `Win + X` and select "Windows PowerShell" or "Terminal".

### Step 3: Download the RedAudit Image

```powershell
docker pull ghcr.io/dorinbadea/redaudit:latest
```

### Step 4: Create a Reports Folder

```powershell
mkdir C:\RedAudit-Reports
```

### Step 5: Run RedAudit

**Option A - Interactive Wizard:**

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

**Option B - Direct Scan:**

```powershell
docker run --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest --target 192.168.1.0/24 --mode quick --yes --output /reports
```

> 💡 **Tip**: To find your IP, run: `ipconfig` and look for "IPv4 Address"

### Step 6: View the Results

Open File Explorer and navigate to `C:\RedAudit-Reports`. Double-click `report.html`.

---

## Linux

Linux users can use host networking for full local network visibility:

```bash
# Download
docker pull ghcr.io/dorinbadea/redaudit:latest

# Run with host networking (recommended)
docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

---

## Platform Limitations

| Platform | `--network host` | Local Network Visibility |
|----------|------------------|--------------------------|
| Linux    | ✅ Supported      | Full visibility          |
| macOS    | ❌ Not supported  | Specify targets manually |
| Windows  | ❌ Not supported  | Specify targets manually |

> **Note**: On Windows and macOS, Docker runs inside a virtual machine. The wizard's auto-detection will show container interfaces, not your host's network. Always specify target IPs explicitly.

---

## Quick Reference

| Action | Command |
|--------|---------|
| Show help | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --help` |
| Show version | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --version` |
| Interactive wizard | `docker run -it --rm -v ~/reports:/reports ghcr.io/dorinbadea/redaudit:latest` |
| Quick scan | `docker run --rm -v ~/reports:/reports ghcr.io/dorinbadea/redaudit:latest --target IP --mode quick --yes --output /reports` |
