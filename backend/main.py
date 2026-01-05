from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import uvicorn
import time
from collections import defaultdict
import asyncio

from api import scans, targets, rules, notifications, reports
from database import engine, Base, get_db
from scheduler import ReconScheduler
from config import settings
from auth import get_current_user_api_key, is_public_endpoint

scheduler = ReconScheduler()

# Simple in-memory rate limiter
rate_limit_store = defaultdict(list)
RATE_LIMIT_REQUESTS = 100  # requests
RATE_LIMIT_WINDOW = 60  # seconds


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    Base.metadata.create_all(bind=engine)
    await scheduler.start()
    yield
    # Shutdown
    await scheduler.stop()


app = FastAPI(
    title="Security Asset Recon Platform",
    description="Automated security reconnaissance and asset discovery platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,  # Disable docs in production
    redoc_url="/redoc" if settings.DEBUG else None
)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Rate Limiting Middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate limiting by IP address"""
    client_ip = request.client.host
    current_time = time.time()
    
    # Clean old entries
    rate_limit_store[client_ip] = [
        req_time for req_time in rate_limit_store[client_ip]
        if current_time - req_time < RATE_LIMIT_WINDOW
    ]
    
    # Check rate limit
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please try again later."}
        )
    
    # Record request
    rate_limit_store[client_ip].append(current_time)
    
    response = await call_next(request)
    return response


# Authentication Middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Require authentication for non-public endpoints"""
    if is_public_endpoint(request.url.path):
        return await call_next(request)
    
    # Check for API key in header
    api_key = request.headers.get(settings.API_KEY_HEADER)
    if not api_key:
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
            headers={settings.API_KEY_HEADER: "Required"}
        )
    
    # Validation happens in route dependencies
    return await call_next(request)


# CORS - Restricted to configured origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
    max_age=3600
)

# Trusted Host Middleware (prevent host header attacks)
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", settings.HOST]
    )

# Include routers
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(rules.router, prefix="/api/rules", tags=["rules"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["notifications"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])


@app.get("/")
async def root():
    """Root endpoint - public"""
    return {
        "name": "Security Asset Recon Platform",
        "version": "1.0.0",
        "status": "running",
        "scheduler": "active" if scheduler.running else "stopped",
        "docs": "/docs" if settings.DEBUG else "disabled"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint - public"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info"
    )
