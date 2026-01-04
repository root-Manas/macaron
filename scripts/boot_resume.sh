#!/bin/bash
# Security Recon Platform - Boot Resume Script
# Called by cron @reboot to resume any interrupted scans

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/opt/security-recon/logs/boot_resume.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "Boot resume script started"

# Wait for network
sleep 30

# Check for interrupted scan
STATE_FILE="/opt/security-recon/state/scan_state.json"
if [ -f "$STATE_FILE" ]; then
    STATUS=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('status', ''))" 2>/dev/null)
    
    if [ "$STATUS" = "running" ] || [ "$STATUS" = "paused" ]; then
        log "Found interrupted scan (status: $STATUS), resuming..."
        
        # Start daemon which will auto-resume
        "$SCRIPT_DIR/daemon.sh" start
    else
        log "No interrupted scan to resume (status: $STATUS)"
    fi
else
    log "No state file found"
fi

log "Boot resume script completed"
