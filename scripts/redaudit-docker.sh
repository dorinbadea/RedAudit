#!/bin/bash
# RedAudit Docker Scanner - macOS/Linux Helper
# This script automatically detects your network and runs RedAudit
#
# Usage:
#   ./redaudit-docker.sh                    # Interactive mode (Spanish)
#   ./redaudit-docker.sh --lang en          # Interactive mode (English)
#   ./redaudit-docker.sh --mode quick --yes # Quick non-interactive scan
#
# Requirements: Docker Desktop must be running

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}          ${GREEN}RedAudit Docker Scanner${NC}                  ${BLUE}║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}✗ Error: Docker is not running${NC}"
    echo "  Please start Docker Desktop and try again."
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker is running"

# Detect network interface and IP
detect_network() {
    local ip=""

    # macOS
    if command -v ipconfig &> /dev/null; then
        # Try en0 (WiFi/Ethernet), then en1
        ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "")
    fi

    # Linux fallback
    if [ -z "$ip" ] && command -v hostname &> /dev/null; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    # Another Linux fallback
    if [ -z "$ip" ] && command -v ip &> /dev/null; then
        ip=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')
    fi

    echo "$ip"
}

MY_IP=$(detect_network)

if [ -z "$MY_IP" ]; then
    echo -e "${YELLOW}⚠ Could not auto-detect your network.${NC}"
    echo -e "  Please enter your target network manually."
    read -r -p "  Target (e.g., 192.168.1.0/24): " TARGET_NETWORK
else
    # Convert IP to network (e.g., 192.168.1.50 -> 192.168.1.0/24)
    MY_NETWORK="${MY_IP%.*}.0/24"
    echo -e "${GREEN}✓${NC} Detected your IP: ${BLUE}$MY_IP${NC}"
    echo -e "${GREEN}✓${NC} Target network: ${BLUE}$MY_NETWORK${NC}"
    echo ""

    read -r -p "Use this network? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn] ]]; then
        read -r -p "Enter target network: " TARGET_NETWORK
    else
        TARGET_NETWORK="$MY_NETWORK"
    fi
fi

# Create reports directory
REPORTS_DIR="$HOME/RedAudit-Reports"
mkdir -p "$REPORTS_DIR"
echo -e "${GREEN}✓${NC} Reports will be saved to: ${BLUE}$REPORTS_DIR${NC}"
echo ""

# Default language to Spanish, but allow override
LANG_ARGS=(--lang es)
for arg in "$@"; do
    if [[ "$arg" == "--lang" ]]; then
        LANG_ARGS=()
        break
    fi
done

# Pull latest image (silently check if update available)
echo -e "${BLUE}→${NC} Checking for updates..."
docker pull ghcr.io/dorinbadea/redaudit:latest -q > /dev/null 2>&1 || true

# Run RedAudit
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Starting RedAudit scan on $TARGET_NETWORK${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""

docker run -it --rm \
    -v "$REPORTS_DIR:/reports" \
    ghcr.io/dorinbadea/redaudit:latest \
    --target "$TARGET_NETWORK" \
    "${LANG_ARGS[@]}" \
    --output /reports \
    "$@"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Scan complete! Reports saved to:${NC}"
echo -e "${BLUE}$REPORTS_DIR${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"

# Try to open the report
if [ -f "$REPORTS_DIR/report.html" ]; then
    echo ""
    read -r -p "Open HTML report in browser? [Y/n]: " open_report
    if [[ ! "$open_report" =~ ^[Nn] ]]; then
        open "$REPORTS_DIR/report.html" 2>/dev/null || xdg-open "$REPORTS_DIR/report.html" 2>/dev/null || echo "Open $REPORTS_DIR/report.html manually"
    fi
fi
