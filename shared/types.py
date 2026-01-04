"""
Shared configuration and types for Security Recon Platform
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from pathlib import Path
import yaml
import os


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class NotificationType(Enum):
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    NEW_SUBDOMAIN = "new_subdomain"
    NEW_VULNERABILITY = "new_vulnerability"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Target:
    domain: str
    scope_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    custom_config: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    created_at: str = ""
    last_scanned: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    module: str
    tool: str
    data: Any
    timestamp: str
    status: ScanStatus = ScanStatus.COMPLETED
    error: Optional[str] = None


@dataclass
class Subdomain:
    subdomain: str
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    is_alive: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    content_length: Optional[int] = None
    discovered_at: str = ""
    last_seen: str = ""
    source: str = ""


@dataclass
class Port:
    host: str
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    version: Optional[str] = None
    state: str = "open"
    discovered_at: str = ""


@dataclass
class HttpEndpoint:
    url: str
    status_code: int
    content_length: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    server: Optional[str] = None
    discovered_at: str = ""


@dataclass
class Vulnerability:
    target: str
    name: str
    severity: Severity
    template_id: Optional[str] = None
    description: Optional[str] = None
    matcher_name: Optional[str] = None
    extracted_results: List[str] = field(default_factory=list)
    curl_command: Optional[str] = None
    reference: List[str] = field(default_factory=list)
    discovered_at: str = ""
    verified: bool = False


@dataclass
class ScanState:
    scan_id: str
    targets: List[str]
    current_target_index: int = 0
    current_module: Optional[str] = None
    current_tool: Optional[str] = None
    completed_modules: Dict[str, List[str]] = field(default_factory=dict)
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[str] = None
    last_updated: Optional[str] = None
    error_count: int = 0
    resume_data: Dict[str, Any] = field(default_factory=dict)


class Config:
    """Configuration manager for the recon platform"""
    
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if Config._config is None:
            self.reload()
    
    def reload(self):
        """Reload configuration from file"""
        config_paths = [
            Path("/opt/security-recon/config/config.yaml"),
            Path.home() / ".config" / "security-recon" / "config.yaml",
            Path(__file__).parent.parent / "config" / "config.yaml"
        ]
        
        for path in config_paths:
            if path.exists():
                with open(path) as f:
                    Config._config = yaml.safe_load(f)
                    return
        
        raise FileNotFoundError("No configuration file found")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key"""
        keys = key.split(".")
        value = Config._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def is_module_enabled(self, module: str) -> bool:
        """Check if a scan module is enabled"""
        return self.get(f"modules.{module}.enabled", False)
    
    def is_tool_enabled(self, module: str, tool: str) -> bool:
        """Check if a specific tool is enabled"""
        return self.get(f"modules.{module}.tools.{tool}.enabled", False)
    
    def get_tool_config(self, module: str, tool: str) -> Dict[str, Any]:
        """Get configuration for a specific tool"""
        return self.get(f"modules.{module}.tools.{tool}", {})
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        key = self.get(f"api_keys.{service}", "")
        if not key:
            # Also check environment variables
            env_key = f"RECON_{service.upper()}_API_KEY"
            key = os.environ.get(env_key, "")
        return key if key else None
