from pydantic_settings import BaseSettings
from typing import Optional, List
import os
import secrets

class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    APP_NAME: str = "Security Recon Platform"
    DEBUG: bool = False  # Secure default
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database - NO DEFAULTS for security
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)  # Generate if not provided
    API_KEY_HEADER: str = "X-API-Key"
    
    # CORS - Secure default (no wildcard)
    ALLOWED_ORIGINS: str = "http://localhost:3000"
    
    @property
    def allowed_origins_list(self) -> List[str]:
        """Parse comma-separated origins"""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]
    
    # Discord Notifications
    DISCORD_WEBHOOK_URL: Optional[str] = None
    
    # Data Directories
    DATA_DIR: str = "./data"
    LOGS_DIR: str = "./logs"
    TOOLS_DIR: str = "./tools"
    
    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    
    # Scan Configuration
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 7200
    DEFAULT_THREADS: int = 10
    
    # API Keys for external services
    SHODAN_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    SECURITYTRAILS_API_KEY: Optional[str] = None
    CHAOS_API_KEY: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None
    HUNTER_API_KEY: Optional[str] = None
    ZOOMEYE_API_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        env_file_encoding = 'utf-8'

settings = Settings()

# Create directories on startup
os.makedirs(settings.DATA_DIR, exist_ok=True)
os.makedirs(settings.LOGS_DIR, exist_ok=True)
os.makedirs(settings.TOOLS_DIR, exist_ok=True)
