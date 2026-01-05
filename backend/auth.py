"""
Authentication and Authorization for Security Recon Platform API
"""
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from pydantic import BaseModel

from config import settings

# Security schemes
bearer_scheme = HTTPBearer()
api_key_scheme = APIKeyHeader(name=settings.API_KEY_HEADER, auto_error=False)


class TokenData(BaseModel):
    """JWT token payload"""
    sub: str
    exp: datetime
    scopes: list[str] = []


class User(BaseModel):
    """User model"""
    username: str
    scopes: list[str] = []
    disabled: bool = False


# In-memory API keys (replace with database in production)
VALID_API_KEYS = {
    # Add your API keys here or load from database
    # "your-api-key-here": User(username="admin", scopes=["read", "write"])
}


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
    
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm="HS256"
    )
    
    return encoded_jwt


def verify_token(token: str) -> TokenData:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"]
        )
        
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return TokenData(
            sub=username,
            exp=datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc),
            scopes=payload.get("scopes", [])
        )
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user_jwt(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)
) -> User:
    """Get current user from JWT token"""
    token = credentials.credentials
    token_data = verify_token(token)
    
    # In production, fetch user from database
    user = User(username=token_data.sub, scopes=token_data.scopes)
    
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return user


async def get_current_user_api_key(
    api_key: Optional[str] = Security(api_key_scheme)
) -> User:
    """Get current user from API key"""
    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="API key required",
            headers={settings.API_KEY_HEADER: "Required"}
        )
    
    user = VALID_API_KEYS.get(api_key)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return user


async def get_current_user(
    jwt_user: Optional[User] = Depends(get_current_user_jwt),
    api_key_user: Optional[User] = Depends(get_current_user_api_key)
) -> User:
    """
    Get current user from either JWT or API key
    Tries JWT first, falls back to API key
    """
    # This won't work as-is because both will raise exceptions
    # We need a custom implementation
    pass


def require_scopes(required_scopes: list[str]):
    """Dependency to check if user has required scopes"""
    async def check_scopes(user: User = Depends(get_current_user_api_key)):
        for scope in required_scopes:
            if scope not in user.scopes:
                raise HTTPException(
                    status_code=403,
                    detail=f"Missing required scope: {scope}"
                )
        return user
    return check_scopes


# Public endpoints (no auth required)
PUBLIC_ENDPOINTS = [
    "/",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json"
]


def is_public_endpoint(path: str) -> bool:
    """Check if endpoint is public"""
    return path in PUBLIC_ENDPOINTS
