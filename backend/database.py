from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum

from config import settings

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

class TargetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    NETWORK = "network"

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, unique=True, index=True, nullable=False)
    type = Column(Enum(TargetType), nullable=False)
    program_name = Column(String, index=True)
    scope = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata = Column(JSON, default={})
    
    scans = relationship("Scan", back_populates="target")
    assets = relationship("Asset", back_populates="target")

class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text)
    tools_config = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scans = relationship("Scan", back_populates="profile")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    progress = Column(Integer, default=0)
    current_tool = Column(String)
    results_summary = Column(JSON, default={})
    error_message = Column(Text)
    
    target = relationship("Target", back_populates="scans")
    profile = relationship("ScanProfile", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan")

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    tool_name = Column(String, nullable=False)
    status = Column(String)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    output_file = Column(String)
    data = Column(JSON)
    error = Column(Text)
    
    scan = relationship("Scan", back_populates="results")

class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    asset_type = Column(String, index=True)
    value = Column(String, index=True)
    source_tool = Column(String)
    confidence = Column(Integer, default=100)
    is_alive = Column(Boolean, default=True)
    http_status = Column(Integer)
    technologies = Column(JSON, default=[])
    vulnerability_score = Column(Integer, default=0)
    metadata = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    target = relationship("Target", back_populates="assets")

class CronJob(Base):
    __tablename__ = "cron_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    cron_expression = Column(String, nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"))
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"))
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    level = Column(String, default="info")
    sent_at = Column(DateTime, default=datetime.utcnow)
    discord_sent = Column(Boolean, default=False)
    metadata = Column(JSON, default={})
