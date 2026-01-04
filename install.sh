#!/bin/bash
# Quick install script

set -e

INSTALL_DIR="/opt/security-recon"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "Security Recon Platform Installer"
echo "========================================"

# Check if running as root for /opt installation
if [ "$EUID" -ne 0 ]; then
    echo "Note: Running without root. Some features may require sudo."
fi

# Create installation directory
echo "[1/5] Creating installation directory..."
sudo mkdir -p "$INSTALL_DIR"
sudo chown -R $USER:$USER "$INSTALL_DIR"

# Copy files
echo "[2/5] Copying files..."
cp -r "$REPO_DIR"/* "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/scripts/"*.sh
chmod +x "$INSTALL_DIR/recon.py"

# Create required directories
echo "[3/5] Creating directories..."
mkdir -p "$INSTALL_DIR"/{config,data,logs,state,wordlists}

# Setup Python environment
echo "[4/5] Setting up Python environment..."
cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Create symlink for easy access
echo "[5/5] Creating command alias..."
sudo ln -sf "$INSTALL_DIR/recon.py" /usr/local/bin/recon
sudo chmod +x /usr/local/bin/recon

echo ""
echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Install recon tools:  sudo $INSTALL_DIR/scripts/daemon.sh install"
echo "  2. Edit config:          nano $INSTALL_DIR/config/config.yaml"
echo "  3. Add Discord webhook:  recon config webhook --url YOUR_URL"
echo "  4. Add targets:          recon add target.com"
echo "  5. Start daemon:         recon daemon start"
echo ""
echo "Or run a quick scan:       recon scan -t target.com"
echo ""
