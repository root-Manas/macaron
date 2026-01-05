from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey, Enum, Index, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timezone
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

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, unique=True, index=True, nullable=False)
    type = Column(Enum(TargetType), nullable=False)
    program_name = Column(String, index=True)
    scope = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    metadata = Column(JSON, default=dict)  # Fixed: use callable, not mutable default
    
    # Relationships with CASCADE delete
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan", passive_deletes=True)
    assets = relationship("Asset", back_populates="target", cascade="all, delete-orphan", passive_deletes=True)
    
    # Composite index for common query patterns
    __table_args__ = (
        Index('idx_target_program_scope', 'program_name', 'scope'),
        Index('idx_target_type_created', 'type', 'created_at'),
    )

class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text)
    tools_config = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    scans = relationship("Scan", back_populates="profile", cascade="all, delete-orphan", passive_deletes=True)

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    started_at = Column(DateTime, index=True)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    progress = Column(Integer, default=0)
    current_tool = Column(String)
    results_summary = Column(JSON, default=dict)  # Fixed: use callable
    error_message = Column(Text)
    
    target = relationship("Target", back_populates="scans")
    profile = relationship("ScanProfile", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    
    # Composite indexes for common query patterns
    __table_args__ = (
        Index('idx_scan_target_status', 'target_id', 'status'),
        Index('idx_scan_created_status', 'created_at', 'status'),
    )

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_name = Column(String, nullable=False, index=True)  # Added index for tool filtering
    status = Column(String)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    output_file = Column(String)
    data = Column(JSON)
    error = Column(Text)
    
    scan = relationship("Scan", back_populates="results")
    
    __table_args__ = (
        Index('idx_scanresult_scan_tool', 'scan_id', 'tool_name'),
    )

class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(String, index=True)
    value = Column(String, index=True, nullable=False)  # Made nullable=False for data integrity
    source_tool = Column(String, index=True)  # Added index for tool filtering
    confidence = Column(Integer, default=100)
    is_alive = Column(Boolean, default=True, index=True)
    http_status = Column(Integer)
    technologies = Column(JSON, default=list)  # Fixed: use callable
    vulnerability_score = Column(Integer, default=0, index=True)
    metadata = Column(JSON, default=dict)  # Fixed: use callable
    
    # First/last seen tracking
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    target = relationship("Target", back_populates="assets")
    endpoints = relationship("Endpoint", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
    
    # Composite indexes for common query patterns
    __table_args__ = (
        Index('idx_asset_target_type', 'target_id', 'asset_type'),
        Index('idx_asset_alive_score', 'is_alive', 'vulnerability_score'),
        Index('idx_asset_type_lastseen', 'asset_type', 'last_seen'),  # For time-based queries
        Index('idx_asset_value_type', 'value', 'asset_type'),  # For unique lookups
    )

# NEW: Endpoint table for tracking discovered URLs/endpoints
class Endpoint(Base):
    __tablename__ = "endpoints"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String, nullable=False, index=True)
    path = Column(String, index=True)
    method = Column(String, default="GET")  # HTTP method
    status_code = Column(Integer)
    response_length = Column(Integer)
    parameters = Column(JSON, default=list)  # Fixed: use callable
    headers = Column(JSON, default=dict)  # Fixed: use callable
    screenshot_path = Column(String)
    
    # Tracking
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    asset = relationship("Asset", back_populates="endpoints")
    vulnerabilities = relationship("Vulnerability", back_populates="endpoint", cascade="all, delete-orphan", passive_deletes=True)
    
    __table_args__ = (
        Index('idx_endpoint_asset_path', 'asset_id', 'path'),
        Index('idx_endpoint_status', 'status_code'),
        Index('idx_endpoint_method_status', 'method', 'status_code'),
    )

# NEW: Vulnerability/Finding table (best practice from web research)
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), index=True)
    
    # Vulnerability details
    name = Column(String, nullable=False, index=True)
    vulnerability_type = Column(String, index=True)  # XSS, SQLi, IDOR, etc.
    severity = Column(Enum(Severity), nullable=False, index=True)
    template_id = Column(String, index=True)  # For nuclei templates
    description = Column(Text)
    remediation = Column(Text)
    proof_of_concept = Column(Text)
    
    # Status tracking
    status = Column(String, default="discovered", index=True)  # discovered, confirmed, reported, fixed
    verified = Column(Boolean, default=False, index=True)
    
    # References and evidence
    cvss_score = Column(Float)  # Added CVSS scoring
    cve_id = Column(String, index=True)
    references = Column(JSON, default=list)  # Fixed: use callable
    evidence_path = Column(String)
    tool_source = Column(String, index=True)
    
    # Metadata
    matcher_name = Column(String)
    extracted_results = Column(JSON, default=list)  # Fixed: use callable
    curl_command = Column(Text)
    metadata = Column(JSON, default=dict)  # Fixed: use callable
    
    # Timestamps
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    reported_at = Column(DateTime)
    fixed_at = Column(DateTime)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    asset = relationship("Asset", back_populates="vulnerabilities")
    endpoint = relationship("Endpoint", back_populates="vulnerabilities")
    
    # Composite indexes for common query patterns
    __table_args__ = (
        Index('idx_vuln_severity_status', 'severity', 'status'),
        Index('idx_vuln_scan_severity', 'scan_id', 'severity'),
        Index('idx_vuln_asset_severity', 'asset_id', 'severity'),
        Index('idx_vuln_discovered_severity', 'discovered_at', 'severity'),  # Time-based queries
        Index('idx_vuln_type_severity', 'vulnerability_type', 'severity'),
    )

class CronJob(Base):
    __tablename__ = "cron_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    cron_expression = Column(String, nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="SET NULL"))  # SET NULL instead of CASCADE
    profile_id = Column(Integer, ForeignKey("scan_profiles.id", ondelete="SET NULL"))  # SET NULL instead of CASCADE
    is_active = Column(Boolean, default=True, index=True)
    last_run = Column(DateTime, index=True)
    next_run = Column(DateTime, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        Index('idx_cronjob_active_nextrun', 'is_active', 'next_run'),
    )

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    level = Column(String, default="info", index=True)
    sent_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    discord_sent = Column(Boolean, default=False, index=True)
    metadata = Column(JSON, default=dict)  # Fixed: use callable
    
    __table_args__ = (
        Index('idx_notification_level_sent', 'level', 'sent_at'),
        # Partial index for unsent notifications (best practice from web research)
        Index('idx_notification_unsent', 'discord_sent', postgresql_where=(discord_sent == False)),
    )
