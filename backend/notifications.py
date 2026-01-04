from discord_webhook import DiscordWebhook, DiscordEmbed
from datetime import datetime
import logging

from config import settings
from database import SessionLocal, Notification

logger = logging.getLogger(__name__)

async def send_discord_notification(title: str, message: str, level: str = "info"):
    db = SessionLocal()
    try:
        notification = Notification(
            title=title,
            message=message,
            level=level
        )
        db.add(notification)
        db.commit()
        
        if not settings.DISCORD_WEBHOOK_URL:
            return
        
        webhook = DiscordWebhook(url=settings.DISCORD_WEBHOOK_URL)
        
        color_map = {
            "info": 0x3498db,
            "success": 0x2ecc71,
            "warning": 0xf39c12,
            "error": 0xe74c3c
        }
        
        embed = DiscordEmbed(
            title=title,
            description=message,
            color=color_map.get(level, 0x3498db)
        )
        embed.set_timestamp()
        embed.set_footer(text="Security Recon Platform")
        
        webhook.add_embed(embed)
        response = webhook.execute()
        
        if response.status_code == 200:
            notification.discord_sent = True
            db.commit()
        
    except Exception as e:
        logger.error(f"Failed to send Discord notification: {e}")
    finally:
        db.close()
