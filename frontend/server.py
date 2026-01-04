"""
Security Recon Platform - FastAPI Backend Server
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime
import json
import asyncio
import sys
import os

sys.path.insert(0, str(Path(__file__).parent.parent))
from shared.types import Config, ScanStatus, Severity
from shared.utils import get_timestamp, is_valid_domain, get_installed_tools
from backend.scan_engine import ScanEngine
from backend.notifier import DiscordNotifier

app = FastAPI(
    title="Security Recon Platform",
    description="Automated Security Reconnaissance API",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
active_scans: Dict[str, ScanEngine] = {}


# Pydantic models
class ScanRequest(BaseModel):
    targets: List[str]
    modules: Optional[List[str]] = None
    fast_mode: bool = False
    use_proxychains: bool = True


class TargetRequest(BaseModel):
    domain: str
    scope_patterns: Optional[List[str]] = None
    exclude_patterns: Optional[List[str]] = None
    notes: Optional[str] = None


class ConfigUpdate(BaseModel):
    key: str
    value: Any


class WebhookConfig(BaseModel):
    url: str
    enabled: bool = True
    notify_on: List[str] = ["scan_start", "scan_complete", "new_vulnerability"]


# API Routes

@app.get("/")
async def root():
    return {"name": "Security Recon Platform", "version": "1.0.0"}


@app.get("/api/status")
async def get_status():
    """Get overall platform status"""
    state_file = Path("/opt/security-recon/state/scan_state.json")
    scheduler_file = Path("/opt/security-recon/state/scheduler_state.json")
    pid_file = Path("/opt/security-recon/state/daemon.pid")
    
    status = {
        "daemon_running": False,
        "active_scans": len(active_scans),
        "last_scan": None,
        "next_scheduled": None,
        "current_scan": None
    }
    
    # Check daemon
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            status["daemon_running"] = True
        except:
            pass
    
    # Check scheduler
    if scheduler_file.exists():
        with open(scheduler_file) as f:
            sched = json.load(f)
            status["last_scan"] = sched.get("last_run")
            status["next_scheduled"] = sched.get("next_run")
    
    # Check current scan
    if state_file.exists():
        with open(state_file) as f:
            scan_state = json.load(f)
            if scan_state.get("status") in ("running", "paused"):
                status["current_scan"] = {
                    "id": scan_state.get("scan_id"),
                    "status": scan_state.get("status"),
                    "targets": scan_state.get("targets"),
                    "progress": f"{scan_state.get('current_target_index', 0) + 1}/{len(scan_state.get('targets', []))}",
                    "module": scan_state.get("current_module")
                }
    
    return status


@app.get("/api/tools")
async def get_tools():
    """Get installed tools status"""
    return get_installed_tools()


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan"""
    # Validate targets
    valid_targets = []
    for t in request.targets:
        t = t.strip().lower()
        if t.startswith("http"):
            from shared.utils import extract_domain
            t = extract_domain(t)
        if is_valid_domain(t):
            valid_targets.append(t)
    
    if not valid_targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")
    
    # Create config override
    config_override = {}
    if request.fast_mode:
        config_override = {
            "subdomain_enumeration.amass": {"enabled": False},
            "content_discovery.feroxbuster": {"enabled": False},
        }
    
    # Start scan in background
    from shared.utils import generate_scan_id
    scan_id = generate_scan_id(valid_targets)
    
    def run_scan():
        engine = ScanEngine(config_override)
        active_scans[scan_id] = engine
        try:
            engine.run_scan(valid_targets)
        finally:
            if scan_id in active_scans:
                del active_scans[scan_id]
    
    background_tasks.add_task(run_scan)
    
    return {
        "scan_id": scan_id,
        "targets": valid_targets,
        "status": "started"
    }


@app.post("/api/scan/stop/{scan_id}")
async def stop_scan(scan_id: str):
    """Stop an active scan"""
    if scan_id in active_scans:
        active_scans[scan_id].stop()
        return {"status": "stopping"}
    
    raise HTTPException(status_code=404, detail="Scan not found or not active")


@app.get("/api/scan/status")
async def get_scan_status():
    """Get current scan status"""
    state_file = Path("/opt/security-recon/state/scan_state.json")
    
    if state_file.exists():
        with open(state_file) as f:
            return json.load(f)
    
    return {"status": "no_active_scan"}


@app.post("/api/scan/resume")
async def resume_scan(background_tasks: BackgroundTasks):
    """Resume a paused scan"""
    state_file = Path("/opt/security-recon/state/scan_state.json")
    
    if not state_file.exists():
        raise HTTPException(status_code=404, detail="No scan to resume")
    
    with open(state_file) as f:
        state = json.load(f)
    
    if state.get("status") not in ("running", "paused"):
        raise HTTPException(status_code=400, detail="No scan to resume")
    
    scan_id = state.get("scan_id")
    
    def run_resume():
        engine = ScanEngine()
        active_scans[scan_id] = engine
        try:
            engine.run_scan(state.get("targets", []), resume=True)
        finally:
            if scan_id in active_scans:
                del active_scans[scan_id]
    
    background_tasks.add_task(run_resume)
    
    return {"status": "resuming", "scan_id": scan_id}


@app.get("/api/targets")
async def get_targets():
    """Get all targets"""
    targets_file = Path("/opt/security-recon/config/targets.txt")
    
    if targets_file.exists():
        with open(targets_file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return {"targets": targets}
    
    return {"targets": []}


@app.post("/api/targets")
async def add_target(request: TargetRequest):
    """Add a new target"""
    targets_file = Path("/opt/security-recon/config/targets.txt")
    targets_file.parent.mkdir(parents=True, exist_ok=True)
    
    domain = request.domain.strip().lower()
    if not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")
    
    # Check if exists
    existing = set()
    if targets_file.exists():
        with open(targets_file) as f:
            existing = set(line.strip().lower() for line in f if line.strip())
    
    if domain in existing:
        raise HTTPException(status_code=409, detail="Target already exists")
    
    with open(targets_file, 'a') as f:
        f.write(f"{domain}\n")
    
    return {"status": "added", "target": domain}


@app.delete("/api/targets/{domain}")
async def delete_target(domain: str):
    """Delete a target"""
    targets_file = Path("/opt/security-recon/config/targets.txt")
    
    if not targets_file.exists():
        raise HTTPException(status_code=404, detail="Target not found")
    
    with open(targets_file) as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if domain.lower() not in [t.lower() for t in targets]:
        raise HTTPException(status_code=404, detail="Target not found")
    
    targets = [t for t in targets if t.lower() != domain.lower()]
    
    with open(targets_file, 'w') as f:
        for t in targets:
            f.write(f"{t}\n")
    
    return {"status": "deleted"}


@app.get("/api/results")
async def get_results(domain: Optional[str] = None):
    """Get scan results"""
    data_dir = Path("/opt/security-recon/data")
    results = {}
    
    if not data_dir.exists():
        return {"results": {}}
    
    for domain_dir in data_dir.iterdir():
        if not domain_dir.is_dir():
            continue
        
        if domain and domain_dir.name != domain:
            continue
        
        domain_results = {"domain": domain_dir.name}
        
        # Subdomains
        subs_file = domain_dir / "subdomains.txt"
        if subs_file.exists():
            with open(subs_file) as f:
                domain_results["subdomains"] = [l.strip() for l in f if l.strip()]
        
        # Live hosts
        live_file = domain_dir / "live_hosts.txt"
        if live_file.exists():
            with open(live_file) as f:
                domain_results["live_hosts"] = [l.strip() for l in f if l.strip()]
        
        # Ports
        ports_file = domain_dir / "ports.txt"
        if ports_file.exists():
            with open(ports_file) as f:
                domain_results["ports"] = [l.strip() for l in f if l.strip()]
        
        # Vulnerabilities
        vulns_file = domain_dir / "vulnerabilities" / "nuclei.json"
        if vulns_file.exists():
            domain_results["vulnerabilities"] = []
            with open(vulns_file) as f:
                for line in f:
                    if line.strip():
                        try:
                            domain_results["vulnerabilities"].append(json.loads(line))
                        except:
                            pass
        
        results[domain_dir.name] = domain_results
    
    return {"results": results}


@app.get("/api/results/{domain}/subdomains")
async def get_subdomains(domain: str):
    """Get subdomains for a domain"""
    subs_file = Path(f"/opt/security-recon/data/{domain}/subdomains.txt")
    
    if subs_file.exists():
        with open(subs_file) as f:
            subdomains = [l.strip() for l in f if l.strip()]
        return {"domain": domain, "subdomains": subdomains, "count": len(subdomains)}
    
    return {"domain": domain, "subdomains": [], "count": 0}


@app.get("/api/results/{domain}/vulnerabilities")
async def get_vulnerabilities(domain: str, severity: Optional[str] = None):
    """Get vulnerabilities for a domain"""
    vulns_file = Path(f"/opt/security-recon/data/{domain}/vulnerabilities/nuclei.json")
    
    vulns = []
    if vulns_file.exists():
        with open(vulns_file) as f:
            for line in f:
                if line.strip():
                    try:
                        v = json.loads(line)
                        if severity and v.get("info", {}).get("severity") != severity:
                            continue
                        vulns.append(v)
                    except:
                        pass
    
    return {"domain": domain, "vulnerabilities": vulns, "count": len(vulns)}


@app.get("/api/stats")
async def get_stats():
    """Get overall statistics"""
    data_dir = Path("/opt/security-recon/data")
    
    stats = {
        "domains": 0,
        "subdomains": 0,
        "live_hosts": 0,
        "open_ports": 0,
        "vulnerabilities": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0
        }
    }
    
    if not data_dir.exists():
        return stats
    
    for domain_dir in data_dir.iterdir():
        if not domain_dir.is_dir():
            continue
        
        stats["domains"] += 1
        
        subs_file = domain_dir / "subdomains.txt"
        if subs_file.exists():
            with open(subs_file) as f:
                stats["subdomains"] += len(f.readlines())
        
        live_file = domain_dir / "live_hosts.txt"
        if live_file.exists():
            with open(live_file) as f:
                stats["live_hosts"] += len(f.readlines())
        
        ports_file = domain_dir / "ports.txt"
        if ports_file.exists():
            with open(ports_file) as f:
                stats["open_ports"] += len(f.readlines())
        
        vulns_file = domain_dir / "vulnerabilities" / "nuclei.json"
        if vulns_file.exists():
            with open(vulns_file) as f:
                for line in f:
                    if line.strip():
                        try:
                            v = json.loads(line)
                            sev = v.get("info", {}).get("severity", "info").lower()
                            if sev in stats["vulnerabilities"]:
                                stats["vulnerabilities"][sev] += 1
                            stats["vulnerabilities"]["total"] += 1
                        except:
                            pass
    
    return stats


@app.get("/api/dashboard")
async def get_dashboard():
    """Consolidated dashboard data - single API call for all dashboard needs"""
    status = await get_status()
    stats = await get_stats()
    targets = await get_targets()
    tools = await get_tools()
    results = await get_results()
    
    return {
        "status": status,
        "stats": stats,
        "targets": targets.get("targets", []),
        "tools": tools,
        "results": results.get("results", {})
    }


@app.get("/api/config")
async def get_config():
    """Get current configuration"""
    config_file = Path("/opt/security-recon/config/config.yaml")
    
    if config_file.exists():
        import yaml
        with open(config_file) as f:
            config = yaml.safe_load(f)
        # Remove sensitive data
        if "api_keys" in config:
            config["api_keys"] = {k: "***" if v else "" for k, v in config.get("api_keys", {}).items()}
        if "discord" in config and "webhook_url" in config["discord"]:
            url = config["discord"]["webhook_url"]
            if url:
                config["discord"]["webhook_url"] = url[:30] + "***"
        return config
    
    return {}


@app.post("/api/config")
async def update_config(update: ConfigUpdate):
    """Update configuration"""
    config_file = Path("/opt/security-recon/config/config.yaml")
    
    import yaml
    
    if config_file.exists():
        with open(config_file) as f:
            config = yaml.safe_load(f)
    else:
        config = {}
    
    # Navigate to nested key
    keys = update.key.split(".")
    current = config
    for k in keys[:-1]:
        if k not in current:
            current[k] = {}
        current = current[k]
    
    current[keys[-1]] = update.value
    
    with open(config_file, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    
    return {"status": "updated", "key": update.key}


@app.post("/api/webhook/configure")
async def configure_webhook(config: WebhookConfig):
    """Configure Discord webhook"""
    config_file = Path("/opt/security-recon/config/config.yaml")
    
    import yaml
    
    if config_file.exists():
        with open(config_file) as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}
    
    cfg["discord"] = {
        "webhook_url": config.url,
        "enabled": config.enabled,
        "notify_on": config.notify_on,
        "rate_limit_seconds": 5
    }
    
    config_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config_file, 'w') as f:
        yaml.dump(cfg, f, default_flow_style=False)
    
    return {"status": "configured"}


@app.post("/api/webhook/test")
async def test_webhook():
    """Test Discord webhook"""
    try:
        notifier = DiscordNotifier()
        await notifier.send_custom(
            "🔧 Test Notification",
            "Security Recon Platform webhook is working!",
            Severity.INFO
        )
        await notifier.close()
        return {"status": "sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/export")
async def export_data(domain: Optional[str] = None, format: str = "json"):
    """Export all data"""
    results = await get_results(domain)
    stats = await get_stats()
    
    export_data = {
        "exported_at": get_timestamp(),
        "stats": stats,
        **results
    }
    
    return export_data


# Serve frontend
frontend_dir = Path(__file__).parent / "static"

@app.get("/dashboard")
async def dashboard():
    html_file = frontend_dir / "index.html"
    if html_file.exists():
        return FileResponse(html_file)
    return JSONResponse({"error": "Dashboard not found"}, status_code=404)

if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
