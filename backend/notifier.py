"""
Discord Webhook Notifier for Security Recon Platform
"""
import asyncio
import aiohttp
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import logging

# Proper imports without sys.path manipulation
from shared.types import Config, NotificationType, Severity, Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class DiscordEmbed:
    title: str
    description: str = ""
    color: int = 0x7289DA
    fields: List[Dict[str, Any]] = None
    footer: str = ""
    timestamp: str = ""
    url: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        embed = {"title": self.title}
        
        if self.description:
            embed["description"] = self.description[:4096]
        if self.color:
            embed["color"] = self.color
        if self.fields:
            embed["fields"] = self.fields[:25]
        if self.footer:
            embed["footer"] = {"text": self.footer[:2048]}
        if self.timestamp:
            embed["timestamp"] = self.timestamp
        if self.url:
            embed["url"] = self.url
            
        return embed


class DiscordNotifier:
    """Send notifications to Discord via webhook"""
    
    COLORS = {
        Severity.CRITICAL: 0xFF0000,  # Red
        Severity.HIGH: 0xFF6600,      # Orange
        Severity.MEDIUM: 0xFFFF00,    # Yellow
        Severity.LOW: 0x00FF00,       # Green
        Severity.INFO: 0x7289DA,      # Discord Blue
    }
    
    NOTIFICATION_COLORS = {
        NotificationType.SCAN_START: 0x3498DB,    # Blue
        NotificationType.SCAN_COMPLETE: 0x2ECC71, # Green
        NotificationType.NEW_SUBDOMAIN: 0x9B59B6, # Purple
        NotificationType.NEW_VULNERABILITY: 0xE74C3C, # Red
        NotificationType.ERROR: 0xE74C3C,         # Red
        NotificationType.WARNING: 0xF39C12,       # Orange
        NotificationType.INFO: 0x7289DA,          # Discord Blue
    }
    
    def __init__(self, webhook_url: str = None):
        self.config = Config()
        self.webhook_url = webhook_url or self.config.get("discord.webhook_url", "")
        self.enabled = self.config.get("discord.enabled", False) and bool(self.webhook_url)
        self.rate_limit = self.config.get("discord.rate_limit_seconds", 5)
        self.notify_on = self.config.get("discord.notify_on", [])
        self.last_sent = 0
        self._queue = asyncio.Queue()
        self._session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
    
    def should_notify(self, notification_type: NotificationType) -> bool:
        """Check if this notification type should be sent"""
        if not self.enabled:
            return False
        return notification_type.value in self.notify_on
    
    async def _send_webhook(self, content: str = None, embeds: List[DiscordEmbed] = None):
        """Send message to Discord webhook"""
        if not self.webhook_url:
            logger.warning("Discord webhook URL not configured")
            return False
        
        # Rate limiting
        import time
        now = time.time()
        if now - self.last_sent < self.rate_limit:
            await asyncio.sleep(self.rate_limit - (now - self.last_sent))
        
        payload = {}
        if content:
            payload["content"] = content[:2000]
        if embeds:
            payload["embeds"] = [e.to_dict() for e in embeds[:10]]
        
        try:
            session = await self._get_session()
            async with session.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                self.last_sent = time.time()
                if response.status == 429:
                    retry_after = (await response.json()).get("retry_after", 5)
                    logger.warning(f"Rate limited, retrying after {retry_after}s")
                    await asyncio.sleep(retry_after)
                    return await self._send_webhook(content, embeds)
                return response.status in (200, 204)
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False
    
    async def notify_scan_start(self, targets: List[str], modules: List[str]):
        """Send notification when scan starts"""
        if not self.should_notify(NotificationType.SCAN_START):
            return
        
        embed = DiscordEmbed(
            title="🚀 Scan Started",
            description=f"Starting security reconnaissance scan",
            color=self.NOTIFICATION_COLORS[NotificationType.SCAN_START],
            fields=[
                {"name": "Targets", "value": "\n".join(targets[:10]) + (f"\n+{len(targets)-10} more" if len(targets) > 10 else ""), "inline": True},
                {"name": "Modules", "value": ", ".join(modules), "inline": True},
            ],
            timestamp=datetime.now(timezone.utc).isoformat(),
            footer="Security Recon Platform"
        )
        await self._send_webhook(embeds=[embed])
    
    async def notify_scan_complete(self, stats: Dict[str, Any]):
        """Send notification when scan completes"""
        if not self.should_notify(NotificationType.SCAN_COMPLETE):
            return
        
        embed = DiscordEmbed(
            title="✅ Scan Complete",
            description=f"Reconnaissance scan finished successfully",
            color=self.NOTIFICATION_COLORS[NotificationType.SCAN_COMPLETE],
            fields=[
                {"name": "Duration", "value": stats.get("duration", "N/A"), "inline": True},
                {"name": "Subdomains Found", "value": str(stats.get("subdomains", 0)), "inline": True},
                {"name": "Live Hosts", "value": str(stats.get("live_hosts", 0)), "inline": True},
                {"name": "Open Ports", "value": str(stats.get("ports", 0)), "inline": True},
                {"name": "Vulnerabilities", "value": str(stats.get("vulnerabilities", 0)), "inline": True},
            ],
            timestamp=datetime.now(timezone.utc).isoformat(),
            footer="Security Recon Platform"
        )
        await self._send_webhook(embeds=[embed])
    
    async def notify_new_subdomains(self, domain: str, subdomains: List[str]):
        """Send notification for new subdomains discovered"""
        if not self.should_notify(NotificationType.NEW_SUBDOMAIN):
            return
        
        # Batch subdomains to avoid hitting Discord limits
        batch_size = 20
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i+batch_size]
            embed = DiscordEmbed(
                title=f"🔍 New Subdomains Found - {domain}",
                description=f"```\n" + "\n".join(batch) + "\n```",
                color=self.NOTIFICATION_COLORS[NotificationType.NEW_SUBDOMAIN],
                fields=[
                    {"name": "Count", "value": f"{len(batch)} ({i+1}-{i+len(batch)} of {len(subdomains)})", "inline": True},
                ],
                timestamp=datetime.now(timezone.utc).isoformat(),
                footer="Security Recon Platform"
            )
            await self._send_webhook(embeds=[embed])
    
    async def notify_vulnerability(self, vuln: Vulnerability):
        """Send notification for new vulnerability found"""
        if not self.should_notify(NotificationType.NEW_VULNERABILITY):
            return
        
        color = self.COLORS.get(vuln.severity, 0x7289DA)
        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵",
        }.get(vuln.severity, "⚪")
        
        fields = [
            {"name": "Target", "value": f"`{vuln.target}`", "inline": True},
            {"name": "Severity", "value": f"{severity_emoji} {vuln.severity.value.upper()}", "inline": True},
        ]
        
        if vuln.template_id:
            fields.append({"name": "Template", "value": vuln.template_id, "inline": True})
        
        if vuln.matcher_name:
            fields.append({"name": "Matcher", "value": vuln.matcher_name, "inline": True})
        
        if vuln.extracted_results:
            extracted = "\n".join(vuln.extracted_results[:5])
            if len(vuln.extracted_results) > 5:
                extracted += f"\n+{len(vuln.extracted_results)-5} more"
            fields.append({"name": "Extracted", "value": f"```{extracted}```", "inline": False})
        
        embed = DiscordEmbed(
            title=f"⚠️ Vulnerability Found: {vuln.name}",
            description=vuln.description[:500] if vuln.description else "",
            color=color,
            fields=fields,
            timestamp=datetime.now(timezone.utc).isoformat(),
            footer="Security Recon Platform"
        )
        
        if vuln.reference:
            embed.url = vuln.reference[0] if vuln.reference else ""
        
        await self._send_webhook(embeds=[embed])
    
    async def notify_error(self, error: str, context: str = ""):
        """Send notification for errors"""
        if not self.should_notify(NotificationType.ERROR):
            return
        
        embed = DiscordEmbed(
            title="❌ Error Occurred",
            description=f"```\n{error[:1500]}\n```",
            color=self.NOTIFICATION_COLORS[NotificationType.ERROR],
            fields=[
                {"name": "Context", "value": context or "Unknown", "inline": True},
            ] if context else [],
            timestamp=datetime.now(timezone.utc).isoformat(),
            footer="Security Recon Platform"
        )
        await self._send_webhook(embeds=[embed])
    
    async def send_custom(self, title: str, message: str, severity: Severity = Severity.INFO):
        """Send custom notification"""
        embed = DiscordEmbed(
            title=title,
            description=message[:4096],
            color=self.COLORS.get(severity, 0x7289DA),
            timestamp=datetime.now(timezone.utc).isoformat(),
            footer="Security Recon Platform"
        )
        await self._send_webhook(embeds=[embed])


# Synchronous wrapper for non-async contexts
class SyncDiscordNotifier:
    """Synchronous wrapper for Discord notifications"""
    
    def __init__(self, webhook_url: str = None):
        self._notifier = DiscordNotifier(webhook_url)
    
    def _run_async(self, coro):
        """Run async coroutine safely"""
        try:
            # Use asyncio.run() - creates new event loop each time (safe)
            asyncio.run(coro)
        except RuntimeError as e:
            # If there's already a running loop, log warning
            logger.warning(f"Could not send notification: {e}")
        except Exception as e:
            logger.error(f"Notification failed: {e}")
    
    def notify_scan_start(self, targets: List[str], modules: List[str]):
        self._run_async(self._notifier.notify_scan_start(targets, modules))
    
    def notify_scan_complete(self, stats: Dict[str, Any]):
        self._run_async(self._notifier.notify_scan_complete(stats))
    
    def notify_new_subdomains(self, domain: str, subdomains: List[str]):
        self._run_async(self._notifier.notify_new_subdomains(domain, subdomains))
    
    def notify_vulnerability(self, vuln: Vulnerability):
        self._run_async(self._notifier.notify_vulnerability(vuln))
    
    def notify_error(self, error: str, context: str = ""):
        self._run_async(self._notifier.notify_error(error, context))
    
    def send_custom(self, title: str, message: str, severity: Severity = Severity.INFO):
        self._run_async(self._notifier.send_custom(title, message, severity))
    
    def close(self):
        self._run_async(self._notifier.close())
