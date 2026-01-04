"""Reports API Router"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import json
import os

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import get_db, Target, Scan, Asset, ScanResult
from config import settings

router = APIRouter()


@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Get overall statistics"""
    return {
        "targets": db.query(Target).count(),
        "scans": db.query(Scan).count(),
        "assets": {
            "total": db.query(Asset).count(),
            "subdomains": db.query(Asset).filter(Asset.asset_type == "subdomain").count(),
            "urls": db.query(Asset).filter(Asset.asset_type == "url").count(),
            "ips": db.query(Asset).filter(Asset.asset_type == "ip").count(),
            "ports": db.query(Asset).filter(Asset.asset_type == "port").count(),
            "alive": db.query(Asset).filter(Asset.is_alive == True).count()
        }
    }


@router.get("/export")
async def export_data(
    target_id: Optional[int] = None,
    format: str = "json",
    db: Session = Depends(get_db)
):
    """Export all data"""
    data = {
        "exported_at": datetime.utcnow().isoformat(),
        "targets": [],
        "assets": []
    }
    
    # Get targets
    query = db.query(Target)
    if target_id:
        query = query.filter(Target.id == target_id)
    
    targets = query.all()
    
    for target in targets:
        target_data = {
            "id": target.id,
            "value": target.value,
            "type": target.type.value,
            "program_name": target.program_name,
            "scope": target.scope,
            "metadata": target.metadata,
            "scans": []
        }
        
        # Get scans for this target
        for scan in target.scans:
            scan_data = {
                "id": scan.id,
                "status": scan.status.value,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "results_summary": scan.results_summary
            }
            target_data["scans"].append(scan_data)
        
        # Get assets
        assets = db.query(Asset).filter(Asset.target_id == target.id).all()
        for asset in assets:
            data["assets"].append({
                "target": target.value,
                "type": asset.asset_type,
                "value": asset.value,
                "is_alive": asset.is_alive,
                "http_status": asset.http_status,
                "technologies": asset.technologies,
                "source": asset.source_tool
            })
        
        data["targets"].append(target_data)
    
    if format == "json":
        return JSONResponse(content=data)
    else:
        # Save to file and return
        export_path = f"{settings.DATA_DIR}/export_{datetime.utcnow().timestamp()}.json"
        with open(export_path, 'w') as f:
            json.dump(data, f, indent=2)
        return FileResponse(export_path, filename="recon_export.json")


@router.get("/target/{target_id}/report")
async def get_target_report(target_id: int, db: Session = Depends(get_db)):
    """Get detailed report for a target"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Get all assets grouped by type
    assets = db.query(Asset).filter(Asset.target_id == target_id).all()
    
    assets_by_type = {}
    for asset in assets:
        if asset.asset_type not in assets_by_type:
            assets_by_type[asset.asset_type] = []
        assets_by_type[asset.asset_type].append({
            "value": asset.value,
            "is_alive": asset.is_alive,
            "http_status": asset.http_status,
            "technologies": asset.technologies,
            "source": asset.source_tool
        })
    
    # Get scan history
    scans = []
    for scan in target.scans:
        scans.append({
            "id": scan.id,
            "status": scan.status.value,
            "profile": scan.profile.name if scan.profile else None,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "progress": scan.progress,
            "results_summary": scan.results_summary
        })
    
    return {
        "target": {
            "id": target.id,
            "value": target.value,
            "type": target.type.value,
            "program_name": target.program_name,
            "scope": target.scope
        },
        "assets": assets_by_type,
        "asset_counts": {k: len(v) for k, v in assets_by_type.items()},
        "total_assets": len(assets),
        "scans": scans
    }


@router.get("/vulnerabilities")
async def get_vulnerabilities(
    target_id: Optional[int] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get vulnerability findings from nuclei scans"""
    vulnerabilities = []
    
    # Query scan results with nuclei data
    query = db.query(ScanResult).filter(ScanResult.tool_name == "nuclei")
    
    if target_id:
        query = query.join(Scan).filter(Scan.target_id == target_id)
    
    for result in query.all():
        if not result.data:
            continue
        
        items = result.data.get("items", [])
        for item in items:
            if severity and severity not in item.lower():
                continue
            vulnerabilities.append({
                "scan_id": result.scan_id,
                "finding": item,
                "discovered_at": result.completed_at
            })
    
    return {"vulnerabilities": vulnerabilities, "count": len(vulnerabilities)}
