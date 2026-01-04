#!/bin/bash
# Security Recon Platform - Daemon Script
# Run this in WSL/Kali to start the background service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/venv"
LOG_DIR="/opt/security-recon/logs"
PID_FILE="/opt/security-recon/state/daemon.pid"

# Create directories
mkdir -p /opt/security-recon/{config,data,logs,state,wordlists}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if running as root for certain operations
check_root() {
    if [ "$EUID" -ne 0 ]; then
        warn "Not running as root. Some features may not work."
    fi
}

# Setup virtual environment
setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        log "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
    fi
    
    source "$VENV_DIR/bin/activate"
    
    log "Installing dependencies..."
    pip install -q --upgrade pip
    pip install -q pyyaml aiohttp croniter psutil requests
}

# Start the daemon
start_daemon() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            log "Daemon already running (PID: $PID)"
            return 0
        fi
    fi
    
    log "Starting Security Recon daemon..."
    
    source "$VENV_DIR/bin/activate"
    
    # Run in background with nohup
    nohup python3 "$PROJECT_DIR/backend/scheduler.py" daemon >> "$LOG_DIR/daemon.log" 2>&1 &
    
    PID=$!
    echo $PID > "$PID_FILE"
    
    log "Daemon started (PID: $PID)"
    log "Logs: $LOG_DIR/daemon.log"
}

# Stop the daemon
stop_daemon() {
    if [ ! -f "$PID_FILE" ]; then
        warn "PID file not found. Daemon may not be running."
        return 0
    fi
    
    PID=$(cat "$PID_FILE")
    
    if ps -p "$PID" > /dev/null 2>&1; then
        log "Stopping daemon (PID: $PID)..."
        kill -TERM "$PID"
        
        # Wait for graceful shutdown
        for i in {1..30}; do
            if ! ps -p "$PID" > /dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        
        # Force kill if still running
        if ps -p "$PID" > /dev/null 2>&1; then
            warn "Force killing daemon..."
            kill -9 "$PID"
        fi
    fi
    
    rm -f "$PID_FILE"
    log "Daemon stopped"
}

# Get status
status_daemon() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            log "Daemon is running (PID: $PID)"
            return 0
        else
            warn "PID file exists but daemon is not running"
            return 1
        fi
    else
        log "Daemon is not running"
        return 1
    fi
}

# View logs
view_logs() {
    if [ -f "$LOG_DIR/daemon.log" ]; then
        tail -f "$LOG_DIR/daemon.log"
    else
        error "Log file not found"
    fi
}

# Setup for auto-start on boot (WSL)
setup_autostart() {
    log "Setting up auto-start..."
    
    # For WSL, we use ~/.bashrc or a scheduled task
    BASHRC="$HOME/.bashrc"
    AUTOSTART_LINE="# Auto-start Security Recon"
    AUTOSTART_CMD="(pgrep -f 'scheduler.py daemon' > /dev/null || $SCRIPT_DIR/daemon.sh start &) 2>/dev/null"
    
    if ! grep -q "$AUTOSTART_LINE" "$BASHRC" 2>/dev/null; then
        echo "" >> "$BASHRC"
        echo "$AUTOSTART_LINE" >> "$BASHRC"
        echo "$AUTOSTART_CMD" >> "$BASHRC"
        log "Added auto-start to ~/.bashrc"
    else
        log "Auto-start already configured"
    fi
    
    # Also create a cron @reboot entry
    (crontab -l 2>/dev/null | grep -v "security-recon"; echo "@reboot $SCRIPT_DIR/daemon.sh start # security-recon-autostart") | crontab -
    log "Added cron @reboot entry"
}

# Install all required tools
install_tools() {
    log "Installing reconnaissance tools..."
    
    check_root
    
    # Update and install prerequisites
    apt-get update -qq
    apt-get install -y -qq golang-go python3-pip git curl wget unzip proxychains4
    
    # Go tools
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        "github.com/projectdiscovery/proxify/cmd/proxify@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/httprobe@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/sensepost/gowitness@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/hakluke/hakrawler@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/jaeles-project/gospider@latest"
        "github.com/003random/getJS@latest"
        "github.com/gwen001/github-subdomains@latest"
    )
    
    for tool in "${GO_TOOLS[@]}"; do
        log "Installing $tool..."
        go install "$tool" 2>/dev/null || warn "Failed to install $tool"
    done
    
    # Move Go binaries to /usr/local/bin
    if [ -d "$GOPATH/bin" ]; then
        cp -n "$GOPATH/bin"/* /usr/local/bin/ 2>/dev/null || true
    fi
    
    # Amass
    if ! command -v amass &> /dev/null; then
        log "Installing amass..."
        apt-get install -y -qq amass 2>/dev/null || \
            go install github.com/owasp-amass/amass/v3/...@master
    fi
    
    # Findomain
    if ! command -v findomain &> /dev/null; then
        log "Installing findomain..."
        curl -sLO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
        unzip -q -o findomain-linux.zip
        chmod +x findomain
        mv findomain /usr/local/bin/
        rm -f findomain-linux.zip
    fi
    
    # Massdns
    if ! command -v massdns &> /dev/null; then
        log "Installing massdns..."
        git clone --quiet https://github.com/blechschmidt/massdns.git /tmp/massdns
        cd /tmp/massdns && make -s && cp bin/massdns /usr/local/bin/
        cd - > /dev/null
        rm -rf /tmp/massdns
    fi
    
    # Python tools
    log "Installing Python tools..."
    pip3 install -q waymore linkfinder secretfinder dirsearch
    
    # xnLinkFinder
    if ! command -v xnLinkFinder &> /dev/null; then
        log "Installing xnLinkFinder..."
        pip3 install -q xnLinkFinder
    fi
    
    # Feroxbuster
    if ! command -v feroxbuster &> /dev/null; then
        log "Installing feroxbuster..."
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin
    fi
    
    # Eyewitness
    if ! command -v eyewitness &> /dev/null; then
        log "Installing eyewitness..."
        apt-get install -y -qq eyewitness 2>/dev/null || true
    fi
    
    # Update nuclei templates
    log "Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null || true
    
    # Download wordlists
    log "Downloading wordlists..."
    WORDLIST_DIR="/opt/security-recon/wordlists"
    mkdir -p "$WORDLIST_DIR"
    
    if [ ! -f "$WORDLIST_DIR/common.txt" ]; then
        curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
            -o "$WORDLIST_DIR/common.txt"
    fi
    
    if [ ! -f "$WORDLIST_DIR/raft-medium-directories.txt" ]; then
        curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt \
            -o "$WORDLIST_DIR/raft-medium-directories.txt"
    fi
    
    log "Tool installation complete!"
    
    # Show installed tools
    log "Checking installed tools..."
    for tool in subfinder amass assetfinder findomain httpx httprobe dnsx naabu nuclei ffuf gowitness katana gau hakrawler waymore feroxbuster; do
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
        fi
    done
}

# Copy config files
setup_config() {
    log "Setting up configuration..."
    
    CONFIG_DIR="/opt/security-recon/config"
    mkdir -p "$CONFIG_DIR"
    
    # Copy config if not exists
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        cp "$PROJECT_DIR/config/config.yaml" "$CONFIG_DIR/"
        log "Copied config.yaml"
    fi
    
    if [ ! -f "$CONFIG_DIR/resolvers.txt" ]; then
        cp "$PROJECT_DIR/config/resolvers.txt" "$CONFIG_DIR/"
        log "Copied resolvers.txt"
    fi
    
    # Create empty targets file
    touch "$CONFIG_DIR/targets.txt"
    
    log "Configuration setup complete"
    log "Edit /opt/security-recon/config/config.yaml to customize"
    log "Add targets to /opt/security-recon/config/targets.txt"
}

# Main
case "${1:-}" in
    start)
        setup_venv
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        stop_daemon
        sleep 2
        setup_venv
        start_daemon
        ;;
    status)
        status_daemon
        ;;
    logs)
        view_logs
        ;;
    install)
        install_tools
        ;;
    setup)
        setup_venv
        setup_config
        ;;
    autostart)
        setup_autostart
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|install|setup|autostart}"
        echo ""
        echo "Commands:"
        echo "  start     - Start the daemon"
        echo "  stop      - Stop the daemon"
        echo "  restart   - Restart the daemon"
        echo "  status    - Check daemon status"
        echo "  logs      - View daemon logs"
        echo "  install   - Install all reconnaissance tools"
        echo "  setup     - Setup virtual environment and config"
        echo "  autostart - Configure auto-start on boot"
        exit 1
        ;;
esac
