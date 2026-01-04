from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Optional
from datetime import datetime
import asyncio

from api import scans, targets, rules, notifications, reports
from database import engine, Base, get_db
from scheduler import ReconScheduler
from config import settings

scheduler = ReconScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    await scheduler.start()
    yield
    await scheduler.stop()

app = FastAPI(
    title="Security Asset Recon Platform",
    description="Automated security reconnaissance and asset discovery platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(rules.router, prefix="/api/rules", tags=["rules"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["notifications"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])

@app.get("/")
async def root():
    return {
        "name": "Security Asset Recon Platform",
        "version": "1.0.0",
        "status": "running",
        "scheduler": "active" if scheduler.running else "stopped"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )
