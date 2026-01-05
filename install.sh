#!/bin/bash
# Macaron - Recon Tool Installer
# Installs all required reconnaissance tools for Kali Linux / Debian

set -e

echo "========================================"
echo "Macaron - Tool Installer"
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

ok() { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }

# Update and install prerequisites
echo "[1/4] Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq golang-go python3-pip git curl wget unzip jq proxychains4 || true

# Setup Go
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

# Go tools
echo "[2/4] Installing Go tools..."
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/003random/getJS@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "$tool" | cut -d@ -f1)
    go install "$tool" 2>/dev/null && ok "$name" || fail "$name"
done

# Move Go binaries to /usr/local/bin
cp -n $GOPATH/bin/* /usr/local/bin/ 2>/dev/null || true

# Additional tools
echo "[3/4] Installing additional tools..."

# Amass
apt-get install -y -qq amass 2>/dev/null && ok "amass" || fail "amass"

# Findomain
if ! command -v findomain &> /dev/null; then
    curl -sLO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
    unzip -q -o findomain-linux.zip && chmod +x findomain && mv findomain /usr/local/bin/
    rm -f findomain-linux.zip
    ok "findomain"
fi

# Massdns
if ! command -v massdns &> /dev/null; then
    git clone --quiet https://github.com/blechschmidt/massdns.git /tmp/massdns
    cd /tmp/massdns && make -s && cp bin/massdns /usr/local/bin/
    cd - > /dev/null && rm -rf /tmp/massdns
    ok "massdns"
fi

# Feroxbuster
if ! command -v feroxbuster &> /dev/null; then
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin 2>/dev/null
    ok "feroxbuster"
fi

# Eyewitness
apt-get install -y -qq eyewitness 2>/dev/null && ok "eyewitness" || true

# Update nuclei templates
echo "[4/4] Updating nuclei templates..."
nuclei -update-templates 2>/dev/null && ok "nuclei templates" || fail "nuclei templates"

# Install Python dependencies
pip3 install -q rich pyyaml

# Install macaron globally
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/macaron" /usr/local/bin/macaron
chmod +x /usr/local/bin/macaron
ok "macaron installed to /usr/local/bin/macaron"

echo ""
echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "Usage:"
echo "  macaron -s target.com        # Wide scan"
echo "  macaron -s target.com -f     # Fast scan"
echo "  macaron -s target.com -n     # Narrow scan"
echo "  macaron -L                   # List tools"
echo "  macaron -S                   # Show status"
echo "  macaron --help               # Help"
echo ""
