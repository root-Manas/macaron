from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    APP_NAME: str = "Security Recon Platform"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    DATABASE_URL: str = "postgresql://recon:recon123@localhost:5432/recon_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    DISCORD_WEBHOOK_URL: Optional[str] = None
    
    DATA_DIR: str = "./data"
    LOGS_DIR: str = "./logs"
    TOOLS_DIR: str = "./tools"
    
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 7200
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

os.makedirs(settings.DATA_DIR, exist_ok=True)
os.makedirs(settings.LOGS_DIR, exist_ok=True)
os.makedirs(settings.TOOLS_DIR, exist_ok=True)
