import asyncio
from datetime import datetime
from croniter import croniter
from sqlalchemy.orm import Session
from typing import Dict, List
import logging

from database import SessionLocal, CronJob, Scan, ScanProfile, Target, ScanStatus
from tasks import run_scan_task
from notifications import send_discord_notification

logger = logging.getLogger(__name__)

class ReconScheduler:
    def __init__(self):
        self.running = False
        self.tasks: Dict[int, asyncio.Task] = {}
        
    async def start(self):
        self.running = True
        asyncio.create_task(self._schedule_loop())
        asyncio.create_task(self._resume_incomplete_scans())
        logger.info("Recon scheduler started")
        
    async def stop(self):
        self.running = False
        for task in self.tasks.values():
            task.cancel()
        logger.info("Recon scheduler stopped")
        
    async def _schedule_loop(self):
        while self.running:
            try:
                db = SessionLocal()
                cron_jobs = db.query(CronJob).filter(CronJob.is_active == True).all()
                
                for job in cron_jobs:
                    if self._should_run(job):
                        await self._execute_job(job, db)
                
                db.close()
                await asyncio.sleep(60)
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(60)
    
    def _should_run(self, job: CronJob) -> bool:
        if not job.next_run:
            cron = croniter(job.cron_expression, datetime.utcnow())
            job.next_run = cron.get_next(datetime)
            return True
        
        if datetime.utcnow() >= job.next_run:
            return True
        return False
    
    async def _execute_job(self, job: CronJob, db: Session):
        try:
            target = db.query(Target).filter(Target.id == job.target_id).first()
            profile = db.query(ScanProfile).filter(ScanProfile.id == job.profile_id).first()
            
            if not target or not profile:
                return
            
            scan = Scan(
                target_id=target.id,
                profile_id=profile.id,
                status=ScanStatus.PENDING
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            task_id = f"scan_{scan.id}"
            self.tasks[scan.id] = asyncio.create_task(
                run_scan_task(scan.id)
            )
            
            job.last_run = datetime.utcnow()
            cron = croniter(job.cron_expression, job.last_run)
            job.next_run = cron.get_next(datetime)
            db.commit()
            
            await send_discord_notification(
                f"🚀 Scheduled scan started",
                f"Job: {job.name}\nTarget: {target.value}\nProfile: {profile.name}",
                "info"
            )
            
        except Exception as e:
            logger.error(f"Job execution error: {e}")
    
    async def _resume_incomplete_scans(self):
        try:
            db = SessionLocal()
            incomplete_scans = db.query(Scan).filter(
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING])
            ).all()
            
            for scan in incomplete_scans:
                scan.status = ScanStatus.PENDING
                db.commit()
                
                self.tasks[scan.id] = asyncio.create_task(
                    run_scan_task(scan.id)
                )
                
            if incomplete_scans:
                await send_discord_notification(
                    "🔄 Resuming incomplete scans",
                    f"Resumed {len(incomplete_scans)} scan(s)",
                    "info"
                )
            
            db.close()
        except Exception as e:
            logger.error(f"Resume scans error: {e}")
