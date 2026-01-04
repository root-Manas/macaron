"""Targets API Router"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import get_db, Target, TargetType, Asset

router = APIRouter()


class TargetCreate(BaseModel):
    value: str
    type: str = "domain"
    program_name: Optional[str] = None
    scope: bool = True
    metadata: Optional[dict] = {}


class TargetResponse(BaseModel):
    id: int
    value: str
    type: str
    program_name: Optional[str]
    scope: bool
    created_at: datetime
    updated_at: datetime
    metadata: Optional[dict]

    class Config:
        from_attributes = True


class AssetResponse(BaseModel):
    id: int
    asset_type: str
    value: str
    source_tool: Optional[str]
    is_alive: bool
    http_status: Optional[int]
    technologies: Optional[list]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=List[TargetResponse])
async def list_targets(
    skip: int = 0,
    limit: int = 100,
    program: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all targets"""
    query = db.query(Target)
    if program:
        query = query.filter(Target.program_name == program)
    return query.order_by(Target.created_at.desc()).offset(skip).limit(limit).all()


@router.post("/", response_model=TargetResponse)
async def create_target(target: TargetCreate, db: Session = Depends(get_db)):
    """Create a new target"""
    # Check if exists
    existing = db.query(Target).filter(Target.value == target.value).first()
    if existing:
        raise HTTPException(status_code=409, detail="Target already exists")
    
    try:
        target_type = TargetType(target.type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid target type: {target.type}")
    
    db_target = Target(
        value=target.value,
        type=target_type,
        program_name=target.program_name,
        scope=target.scope,
        metadata=target.metadata or {}
    )
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    
    return db_target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: int, db: Session = Depends(get_db)):
    """Get target details"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/{target_id}")
async def delete_target(target_id: int, db: Session = Depends(get_db)):
    """Delete a target"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    db.delete(target)
    db.commit()
    return {"status": "deleted"}


@router.get("/{target_id}/assets", response_model=List[AssetResponse])
async def get_target_assets(
    target_id: int,
    asset_type: Optional[str] = None,
    alive_only: bool = False,
    db: Session = Depends(get_db)
):
    """Get all assets for a target"""
    query = db.query(Asset).filter(Asset.target_id == target_id)
    
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if alive_only:
        query = query.filter(Asset.is_alive == True)
    
    return query.order_by(Asset.created_at.desc()).all()


@router.post("/bulk")
async def bulk_create_targets(targets: List[TargetCreate], db: Session = Depends(get_db)):
    """Bulk create targets"""
    created = []
    skipped = []
    
    for target in targets:
        existing = db.query(Target).filter(Target.value == target.value).first()
        if existing:
            skipped.append(target.value)
            continue
        
        try:
            target_type = TargetType(target.type)
        except ValueError:
            skipped.append(target.value)
            continue
        
        db_target = Target(
            value=target.value,
            type=target_type,
            program_name=target.program_name,
            scope=target.scope,
            metadata=target.metadata or {}
        )
        db.add(db_target)
        created.append(target.value)
    
    db.commit()
    
    return {
        "created": len(created),
        "skipped": len(skipped),
        "targets": created
    }
