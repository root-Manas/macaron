#!/bin/bash
# Macaron Installer
# Usage: curl -sL https://raw.githubusercontent.com/.../install.sh | bash

set -e

echo "
███╗   ███╗ █████╗  ██████╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██╔████╔██║███████║██║     ███████║██████╔╝██║   ██║██╔██╗ ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
               Macaron - INSTALLER
"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

# Check if running as root for tool installation
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &> /dev/null; then
        SUDO="sudo"
    else
        warn "Not running as root. Tool installation may fail."
    fi
fi

# Create directories
log "Creating directories..."
mkdir -p ~/.macaron/{config,data,state,logs,wordlists}

# Determine script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if macaron exists in current directory
if [ -f "$SCRIPT_DIR/macaron" ]; then
    log "Installing macaron CLI..."
    chmod +x "$SCRIPT_DIR/macaron"
    $SUDO cp "$SCRIPT_DIR/macaron" /usr/local/bin/macaron
    log "Installed to /usr/local/bin/macaron"
else
    warn "macaron file not found in current directory"
    warn "Make sure you're running this from the macaron directory"
fi

# Ask about tool installation
echo ""
read -p "Install reconnaissance tools? (requires sudo) [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Installing prerequisites..."
    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq golang-go python3-pip git curl wget unzip proxychains4 jq

    # Go environment
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    # Go tools
    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/sensepost/gowitness@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/hakluke/hakrawler@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/003random/getJS@latest"
    )

    for tool in "${GO_TOOLS[@]}"; do
        name=$(echo "$tool" | rev | cut -d'/' -f1 | rev | cut -d'@' -f1)
        log "Installing $name..."
        go install "$tool" 2>/dev/null || warn "Failed: $name"
    done

    # Copy Go binaries
    if [ -d "$GOPATH/bin" ]; then
        $SUDO cp -n "$GOPATH/bin"/* /usr/local/bin/ 2>/dev/null || true
    fi

    # Findomain
    if ! command -v findomain &> /dev/null; then
        log "Installing findomain..."
        curl -sLO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
        unzip -q -o findomain-linux.zip
        chmod +x findomain
        $SUDO mv findomain /usr/local/bin/
        rm -f findomain-linux.zip
    fi

    # Amass
    if ! command -v amass &> /dev/null; then
        log "Installing amass..."
        $SUDO apt-get install -y -qq amass 2>/dev/null || go install github.com/owasp-amass/amass/v4/...@master
    fi

    # Python tools
    log "Installing Python tools..."
    pip3 install -q waymore linkfinder 2>/dev/null || true

    # Nuclei templates
    log "Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null || true

    # Wordlists
    log "Downloading wordlists..."
    if [ ! -f ~/.macaron/wordlists/common.txt ]; then
        curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
            -o ~/.macaron/wordlists/common.txt
    fi
fi

# Setup auto-resume on boot
echo ""
read -p "Setup auto-resume on boot? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    (crontab -l 2>/dev/null | grep -v "macaron"; echo "@reboot /usr/local/bin/macaron scan --resume 2>/dev/null") | crontab -
    log "Added cron @reboot entry"
fi

echo ""
log "Installation complete!"
echo ""
echo "Usage:"
echo "  macaron scan -t example.com           # Wide infrastructure scan"
echo "  macaron scan -t app.com -m narrow     # Narrow application scan"
echo "  macaron config webhook --url URL      # Set Discord webhook"
echo "  macaron list tools                    # Show installed tools"
echo ""
