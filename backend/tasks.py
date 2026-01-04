import asyncio
import subprocess
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import logging

from database import SessionLocal, Scan, ScanResult, ScanStatus, Asset, Target
from notifications import send_discord_notification
from config import settings
from tools import RECON_TOOLS

logger = logging.getLogger(__name__)

async def run_scan_task(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()
        
        target = scan.target
        profile = scan.profile
        tools_config = profile.tools_config
        
        await send_discord_notification(
            "🎯 Scan Started",
            f"Target: {target.value}\nProfile: {profile.name}\nScan ID: {scan.id}",
            "info"
        )
        
        total_tools = len([t for t, enabled in tools_config.items() if enabled])
        completed_tools = 0
        
        results_summary = {
            "subdomains": 0,
            "urls": 0,
            "ips": 0,
            "ports": 0,
            "vulnerabilities": 0
        }
        
        for tool_name, enabled in tools_config.items():
            if not enabled or tool_name not in RECON_TOOLS:
                continue
            
            scan.current_tool = tool_name
            scan.progress = int((completed_tools / total_tools) * 100)
            db.commit()
            
            tool = RECON_TOOLS[tool_name]
            result = await run_tool(scan_id, target.value, tool_name, tool, db, use_proxychains=True)
            
            if result and result.data:
                update_results_summary(results_summary, tool_name, result.data)
                await process_assets(target.id, tool_name, result.data, db)
            
            completed_tools += 1
        
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
        scan.results_summary = results_summary
        db.commit()
        
        await send_discord_notification(
            "✅ Scan Completed",
            f"Target: {target.value}\n"
            f"Subdomains: {results_summary['subdomains']}\n"
            f"URLs: {results_summary['urls']}\n"
            f"IPs: {results_summary['ips']}\n"
            f"Ports: {results_summary['ports']}",
            "success"
        )
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        
        await send_discord_notification(
            "❌ Scan Failed",
            f"Scan ID: {scan_id}\nError: {str(e)}",
            "error"
        )
    finally:
        db.close()

async def run_tool(scan_id: int, target: str, tool_name: str, tool_config: Dict, db, use_proxychains: bool = True) -> Optional[ScanResult]:
    result = ScanResult(
        scan_id=scan_id,
        tool_name=tool_name,
        started_at=datetime.utcnow(),
        status="running"
    )
    db.add(result)
    db.commit()
    db.refresh(result)
    
    try:
        output_file = f"{settings.DATA_DIR}/scan_{scan_id}_{tool_name}_{datetime.utcnow().timestamp()}.txt"
        
        command = tool_config["command"].format(target=target, output=output_file)
        
        # Add proxychains support to avoid rate limiting
        if use_proxychains:
            command = f"proxychains4 -q {command}"
        
        if tool_config.get("wsl", False):
            command = f"wsl -e bash -c '{command}'"
        
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=settings.TOOLS_DIR
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=tool_config.get("timeout", 3600)
            )
        except asyncio.TimeoutError:
            process.kill()
            raise Exception(f"Tool {tool_name} timed out")
        
        if os.path.exists(output_file):
            data = parse_tool_output(tool_name, output_file, tool_config)
            result.data = data
            result.output_file = output_file
        
        result.status = "completed" if process.returncode == 0 else "failed"
        result.completed_at = datetime.utcnow()
        
        if stderr:
            result.error = stderr.decode()
        
        db.commit()
        return result
        
    except Exception as e:
        logger.error(f"Tool {tool_name} execution failed: {e}")
        result.status = "failed"
        result.error = str(e)
        result.completed_at = datetime.utcnow()
        db.commit()
        return result

def parse_tool_output(tool_name: str, output_file: str, tool_config: Dict) -> Dict:
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        parser = tool_config.get("parser", "line")
        
        if parser == "line":
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            return {"items": lines, "count": len(lines)}
        elif parser == "json":
            data = json.loads(content)
            return data
        else:
            return {"raw": content}
            
    except Exception as e:
        logger.error(f"Failed to parse {tool_name} output: {e}")
        return {}

def update_results_summary(summary: Dict, tool_name: str, data: Dict):
    if "subdomain" in tool_name.lower():
        summary["subdomains"] += data.get("count", 0)
    elif "url" in tool_name.lower() or "wayback" in tool_name.lower():
        summary["urls"] += data.get("count", 0)
    elif "port" in tool_name.lower() or "nmap" in tool_name.lower():
        summary["ports"] += data.get("count", 0)
    elif "ip" in tool_name.lower():
        summary["ips"] += data.get("count", 0)

async def process_assets(target_id: int, tool_name: str, data: Dict, db):
    try:
        items = data.get("items", [])
        
        for item in items:
            if isinstance(item, str):
                value = item
                metadata = {}
            else:
                value = item.get("value", "")
                metadata = item
            
            if not value:
                continue
            
            asset_type = determine_asset_type(tool_name, value)
            
            existing = db.query(Asset).filter(
                Asset.target_id == target_id,
                Asset.value == value,
                Asset.asset_type == asset_type
            ).first()
            
            if not existing:
                asset = Asset(
                    target_id=target_id,
                    asset_type=asset_type,
                    value=value,
                    source_tool=tool_name,
                    metadata=metadata
                )
                db.add(asset)
        
        db.commit()
    except Exception as e:
        logger.error(f"Failed to process assets: {e}")

def determine_asset_type(tool_name: str, value: str) -> str:
    if "subdomain" in tool_name.lower():
        return "subdomain"
    elif "url" in tool_name.lower():
        return "url"
    elif "port" in tool_name.lower():
        return "port"
    elif "ip" in tool_name.lower():
        return "ip"
    else:
        return "unknown"
