"""Notifications API Router"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import get_db, Notification
from notifications import send_discord_notification
from config import settings

router = APIRouter()


class WebhookConfig(BaseModel):
    webhook_url: str


class NotificationResponse(BaseModel):
    id: int
    title: str
    message: str
    level: str
    sent_at: datetime
    discord_sent: bool
    metadata: Optional[dict]

    class Config:
        from_attributes = True


@router.get("/", response_model=List[NotificationResponse])
async def list_notifications(
    skip: int = 0,
    limit: int = 50,
    level: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List notifications"""
    query = db.query(Notification)
    if level:
        query = query.filter(Notification.level == level)
    return query.order_by(Notification.sent_at.desc()).offset(skip).limit(limit).all()


@router.post("/webhook")
async def configure_webhook(config: WebhookConfig):
    """Configure Discord webhook"""
    # In production, save to database or config file
    # For now, just validate and test
    import aiohttp
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.webhook_url,
                json={"content": "🔧 Webhook configured successfully!"}
            ) as response:
                if response.status in (200, 204):
                    return {"status": "configured", "message": "Test message sent"}
                else:
                    raise HTTPException(status_code=400, detail="Invalid webhook URL")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to configure webhook: {str(e)}")


@router.post("/test")
async def test_notification():
    """Send a test notification"""
    await send_discord_notification(
        "🔧 Test Notification",
        "Security Recon Platform is configured and working!",
        "info"
    )
    return {"status": "sent"}


@router.delete("/{notification_id}")
async def delete_notification(notification_id: int, db: Session = Depends(get_db)):
    """Delete a notification"""
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    db.delete(notification)
    db.commit()
    return {"status": "deleted"}


@router.delete("/")
async def clear_notifications(db: Session = Depends(get_db)):
    """Clear all notifications"""
    db.query(Notification).delete()
    db.commit()
    return {"status": "cleared"}
