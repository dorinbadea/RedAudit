# Docker Usage Guide

RedAudit is available as a Docker image for users on **Windows**, **macOS**, or any system where native Linux installation isn't practical.

## Quick Start

```bash
# Pull the image
docker pull ghcr.io/dorinbadea/redaudit:latest

# Run a scan
docker run --rm -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

---

## Windows

### Setup

1. Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Restart Windows and open Docker Desktop
3. Wait for the whale icon in the systray to turn green

### Run a Scan

```powershell
# Create reports folder
mkdir C:\RedAudit-Reports

# Run scan
docker run --rm ^
  -v C:\RedAudit-Reports:/reports ^
  ghcr.io/dorinbadea/redaudit:latest ^
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

### Interactive Wizard

```powershell
docker run -it --rm -v C:\RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

---

## macOS

### Setup

1. Download [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/) (choose Apple Silicon or Intel)
2. Drag Docker.app to Applications and open it
3. Wait for the whale icon in the menu bar to turn green

### Run a Scan

```bash
# Create reports folder
mkdir -p ~/RedAudit-Reports

# Run scan
docker run --rm \
  -v ~/RedAudit-Reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports

# Open the report
open ~/RedAudit-Reports/report.html
```

### Interactive Wizard

```bash
docker run -it --rm -v ~/RedAudit-Reports:/reports ghcr.io/dorinbadea/redaudit:latest
```

---

## Linux (with host networking)

Linux users can leverage host networking for better local network visibility:

```bash
docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

---

## Limitations

| Platform | `--network host` | Notes |
|:---------|:-----------------|:------|
| Linux | ✅ Supported | Full local network visibility |
| macOS | ❌ Not supported | Docker runs in a VM; specify targets manually |
| Windows | ❌ Not supported | Same as macOS |

> **Tip**: On Windows/macOS, always specify target IPs explicitly. The wizard's network auto-detection will show container interfaces, not your host's.

---

## Common Commands

| Action | Command |
|:-------|:--------|
| Show help | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --help` |
| Show version | `docker run --rm ghcr.io/dorinbadea/redaudit:latest --version` |
| Quick scan | `docker run --rm -v ./reports:/reports ghcr.io/dorinbadea/redaudit:latest --target 192.168.1.1 --mode quick --yes --output /reports` |
