#!/bin/bash
# Security Recon Platform - Cron Runner Script
# Called by cron to run scheduled scans

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/venv"
LOG_FILE="/opt/security-recon/logs/cron.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "Cron runner started"

# Check if already running
if pgrep -f "scan_engine.py" > /dev/null; then
    log "Scan already in progress, skipping"
    exit 0
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate" 2>/dev/null

# Run scan
TARGETS_FILE="/opt/security-recon/config/targets.txt"

if [ -f "$TARGETS_FILE" ] && [ -s "$TARGETS_FILE" ]; then
    log "Starting scheduled scan"
    python3 "$PROJECT_DIR/backend/scan_engine.py" -f "$TARGETS_FILE" >> "$LOG_FILE" 2>&1
    log "Scheduled scan completed"
else
    log "No targets found in $TARGETS_FILE"
fi
