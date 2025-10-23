from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import asyncio
from loguru import logger
from app.database import get_db
from sqlalchemy import text
from app.services.scanners.scanner_orchestrator import scanner_orchestrator
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

class ScanScheduler:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.job_store = {}
        
    async def start(self):
        """Start the scheduler"""
        if not self.scheduler.running:
            self.scheduler.start()
            await self._load_scheduled_scans()
            
    async def stop(self):
        """Stop the scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            
    async def _load_scheduled_scans(self):
        """Load existing scheduled scans from database"""
        try:
            db = next(get_db())
            stmt = text("""
                SELECT * FROM scheduled_scans 
                WHERE is_active = true
            """)
            
            scheduled_scans = db.execute(stmt).fetchall()
            
            for scan in scheduled_scans:
                await self.schedule_scan(dict(scan))
                
        except Exception as e:
            logger.error(f"Error loading scheduled scans: {str(e)}")
            
    async def schedule_scan(self, scan_config: Dict[str, Any]) -> str:
        """Schedule a new scan"""
        try:
            schedule_id = scan_config.get('id') or str(uuid.uuid4())
            
            # Create trigger based on schedule type
            if scan_config.get('schedule_type') == 'cron':
                trigger = CronTrigger.from_crontab(scan_config['cron_expression'])
            else:  # interval
                interval = timedelta(**scan_config['interval'])
                trigger = IntervalTrigger(
                    seconds=int(interval.total_seconds()),
                    start_date=scan_config.get('start_date')
                )
            
            # Add job to scheduler
            self.scheduler.add_job(
                self._run_scheduled_scan,
                trigger=trigger,
                args=[scan_config],
                id=schedule_id,
                replace_existing=True
            )
            
            # Store in database if new schedule
            if not scan_config.get('id'):
                await self._store_schedule(schedule_id, scan_config)
            
            self.job_store[schedule_id] = scan_config
            return schedule_id
            
        except Exception as e:
            logger.error(f"Error scheduling scan: {str(e)}")
            raise
            
    async def _store_schedule(self, schedule_id: str, config: Dict[str, Any]):
        """Store schedule in database"""
        try:
            db = next(get_db())
            stmt = text("""
                INSERT INTO scheduled_scans (
                    id, user_id, target_url, scan_types, scan_config,
                    schedule_type, cron_expression, interval_config,
                    is_active, created_at
                ) VALUES (
                    :id, :user_id, :target_url, :scan_types, :scan_config,
                    :schedule_type, :cron_expression, :interval_config,
                    true, :created_at
                )
            """)
            
            db.execute(stmt.bindparams(
                id=schedule_id,
                user_id=config['user_id'],
                target_url=config['target_url'],
                scan_types=config['scan_types'],
                scan_config=config['scan_config'],
                schedule_type=config['schedule_type'],
                cron_expression=config.get('cron_expression'),
                interval_config=config.get('interval'),
                created_at=datetime.utcnow()
            ))
            db.commit()
            
        except Exception as e:
            logger.error(f"Error storing schedule: {str(e)}")
            raise
            
    async def _run_scheduled_scan(self, scan_config: Dict[str, Any]):
        """Execute a scheduled scan"""
        try:
            # Create scan record
            db = next(get_db())
            scan_id = str(uuid.uuid4())
            
            stmt = text("""
                INSERT INTO security_scans (
                    id, user_id, target_url, scan_types,
                    status, scan_config, started_at,
                    schedule_id
                ) VALUES (
                    :id, :user_id, :target_url, :scan_types,
                    'pending', :scan_config, :started_at,
                    :schedule_id
                )
            """)
            
            db.execute(stmt.bindparams(
                id=scan_id,
                user_id=scan_config['user_id'],
                target_url=scan_config['target_url'],
                scan_types=scan_config['scan_types'],
                scan_config=scan_config['scan_config'],
                started_at=datetime.utcnow(),
                schedule_id=scan_config.get('id')
            ))
            db.commit()
            
            # Run scan
            await scanner_orchestrator.run_scan(
                scan_id=scan_id,
                target=scan_config['target_url'],
                scan_types=scan_config['scan_types'],
                config=scan_config['scan_config']
            )
            
        except Exception as e:
            logger.error(f"Error running scheduled scan: {str(e)}")
            
    async def pause_schedule(self, schedule_id: str):
        """Pause a scheduled scan"""
        try:
            self.scheduler.pause_job(schedule_id)
            
            db = next(get_db())
            stmt = text("""
                UPDATE scheduled_scans 
                SET is_active = false 
                WHERE id = :schedule_id
            """)
            
            db.execute(stmt.bindparams(schedule_id=schedule_id))
            db.commit()
            
        except Exception as e:
            logger.error(f"Error pausing schedule: {str(e)}")
            raise
            
    async def resume_schedule(self, schedule_id: str):
        """Resume a paused schedule"""
        try:
            self.scheduler.resume_job(schedule_id)
            
            db = next(get_db())
            stmt = text("""
                UPDATE scheduled_scans 
                SET is_active = true 
                WHERE id = :schedule_id
            """)
            
            db.execute(stmt.bindparams(schedule_id=schedule_id))
            db.commit()
            
        except Exception as e:
            logger.error(f"Error resuming schedule: {str(e)}")
            raise
            
    async def delete_schedule(self, schedule_id: str):
        """Delete a schedule"""
        try:
            self.scheduler.remove_job(schedule_id)
            
            db = next(get_db())
            stmt = text("""
                DELETE FROM scheduled_scans 
                WHERE id = :schedule_id
            """)
            
            db.execute(stmt.bindparams(schedule_id=schedule_id))
            db.commit()
            
            if schedule_id in self.job_store:
                del self.job_store[schedule_id]
                
        except Exception as e:
            logger.error(f"Error deleting schedule: {str(e)}")
            raise
            
    async def get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """Get schedule details"""
        try:
            db = next(get_db())
            stmt = text("""
                SELECT * FROM scheduled_scans 
                WHERE id = :schedule_id
            """)
            
            result = db.execute(
                stmt.bindparams(schedule_id=schedule_id)
            ).fetchone()
            
            return dict(result) if result else None
            
        except Exception as e:
            logger.error(f"Error getting schedule: {str(e)}")
            return None
            
    async def list_schedules(
        self,
        user_id: str,
        active_only: bool = False
    ) -> List[Dict[str, Any]]:
        """List all schedules for a user"""
        try:
            db = next(get_db())
            query = """
                SELECT * FROM scheduled_scans 
                WHERE user_id = :user_id
            """
            
            if active_only:
                query += " AND is_active = true"
                
            stmt = text(query)
            
            results = db.execute(
                stmt.bindparams(user_id=user_id)
            ).fetchall()
            
            return [dict(row) for row in results]
            
        except Exception as e:
            logger.error(f"Error listing schedules: {str(e)}")
            return []

# Global scheduler instance
scheduler = ScanScheduler()