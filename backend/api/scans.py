"""Scans API Router"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import get_db, Scan, ScanProfile, Target, ScanStatus
from tasks import run_scan_task

router = APIRouter()


class ScanCreate(BaseModel):
    target_id: int
    profile_id: int


class ScanResponse(BaseModel):
    id: int
    target_id: int
    profile_id: int
    status: str
    progress: int
    current_tool: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    results_summary: Optional[dict]
    error_message: Optional[str]

    class Config:
        from_attributes = True


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all scans"""
    query = db.query(Scan)
    if status:
        query = query.filter(Scan.status == status)
    return query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()


@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Create and start a new scan"""
    # Verify target exists
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Verify profile exists
    profile = db.query(ScanProfile).filter(ScanProfile.id == scan.profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Scan profile not found")
    
    # Create scan record
    db_scan = Scan(
        target_id=scan.target_id,
        profile_id=scan.profile_id,
        status=ScanStatus.PENDING
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # Start scan in background
    background_tasks.add_task(run_scan_task, db_scan.id)
    
    return db_scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan details"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: int, db: Session = Depends(get_db)):
    """Stop a running scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Scan is not running")
    
    scan.status = ScanStatus.PAUSED
    db.commit()
    
    return {"status": "stopping", "scan_id": scan_id}


@router.post("/{scan_id}/resume")
async def resume_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Resume a paused scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != ScanStatus.PAUSED:
        raise HTTPException(status_code=400, detail="Scan is not paused")
    
    background_tasks.add_task(run_scan_task, scan_id)
    
    return {"status": "resuming", "scan_id": scan_id}


@router.get("/{scan_id}/results")
async def get_scan_results(scan_id: int, db: Session = Depends(get_db)):
    """Get scan results"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan_id,
        "status": scan.status.value,
        "results_summary": scan.results_summary,
        "results": [
            {
                "tool": r.tool_name,
                "status": r.status,
                "data": r.data,
                "started_at": r.started_at,
                "completed_at": r.completed_at
            }
            for r in scan.results
        ]
    }
