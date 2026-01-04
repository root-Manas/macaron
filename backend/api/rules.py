"""Rules API Router - Scan Profiles"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import get_db, ScanProfile, CronJob
from tools import RECON_TOOLS, TOOL_CATEGORIES

router = APIRouter()


class ProfileCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tools_config: dict


class ProfileResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    tools_config: dict
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class CronJobCreate(BaseModel):
    name: str
    cron_expression: str
    target_id: Optional[int] = None
    profile_id: int
    is_active: bool = True


class CronJobResponse(BaseModel):
    id: int
    name: str
    cron_expression: str
    target_id: Optional[int]
    profile_id: int
    is_active: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/profiles", response_model=List[ProfileResponse])
async def list_profiles(db: Session = Depends(get_db)):
    """List all scan profiles"""
    return db.query(ScanProfile).all()


@router.post("/profiles", response_model=ProfileResponse)
async def create_profile(profile: ProfileCreate, db: Session = Depends(get_db)):
    """Create a new scan profile"""
    existing = db.query(ScanProfile).filter(ScanProfile.name == profile.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Profile name already exists")
    
    db_profile = ScanProfile(
        name=profile.name,
        description=profile.description,
        tools_config=profile.tools_config
    )
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)
    
    return db_profile


@router.get("/profiles/{profile_id}", response_model=ProfileResponse)
async def get_profile(profile_id: int, db: Session = Depends(get_db)):
    """Get profile details"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@router.put("/profiles/{profile_id}", response_model=ProfileResponse)
async def update_profile(
    profile_id: int,
    profile: ProfileCreate,
    db: Session = Depends(get_db)
):
    """Update a scan profile"""
    db_profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not db_profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    db_profile.name = profile.name
    db_profile.description = profile.description
    db_profile.tools_config = profile.tools_config
    db.commit()
    db.refresh(db_profile)
    
    return db_profile


@router.delete("/profiles/{profile_id}")
async def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    """Delete a scan profile"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    db.delete(profile)
    db.commit()
    return {"status": "deleted"}


@router.get("/tools")
async def list_available_tools():
    """List all available tools"""
    return {
        "tools": RECON_TOOLS,
        "categories": TOOL_CATEGORIES
    }


@router.get("/crons", response_model=List[CronJobResponse])
async def list_cron_jobs(db: Session = Depends(get_db)):
    """List all cron jobs"""
    return db.query(CronJob).all()


@router.post("/crons", response_model=CronJobResponse)
async def create_cron_job(cron: CronJobCreate, db: Session = Depends(get_db)):
    """Create a new cron job"""
    db_cron = CronJob(
        name=cron.name,
        cron_expression=cron.cron_expression,
        target_id=cron.target_id,
        profile_id=cron.profile_id,
        is_active=cron.is_active
    )
    db.add(db_cron)
    db.commit()
    db.refresh(db_cron)
    
    return db_cron


@router.delete("/crons/{cron_id}")
async def delete_cron_job(cron_id: int, db: Session = Depends(get_db)):
    """Delete a cron job"""
    cron = db.query(CronJob).filter(CronJob.id == cron_id).first()
    if not cron:
        raise HTTPException(status_code=404, detail="Cron job not found")
    
    db.delete(cron)
    db.commit()
    return {"status": "deleted"}


@router.post("/crons/{cron_id}/toggle")
async def toggle_cron_job(cron_id: int, db: Session = Depends(get_db)):
    """Toggle cron job active status"""
    cron = db.query(CronJob).filter(CronJob.id == cron_id).first()
    if not cron:
        raise HTTPException(status_code=404, detail="Cron job not found")
    
    cron.is_active = not cron.is_active
    db.commit()
    
    return {"status": "active" if cron.is_active else "inactive"}
