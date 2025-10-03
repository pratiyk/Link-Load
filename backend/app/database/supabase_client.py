import logging
import os
from supabase import create_client, Client
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SupabaseClient:
    def __init__(self):
        # Initialize Supabase clients
        self.client: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
        self.admin: Client  = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)
        
        # Initialize SQLAlchemy engine for raw SQL operations
        self.engine = create_engine(
            f"postgresql://{settings.SUPABASE_USER}:{settings.SUPABASE_PASSWORD}@"
            f"{settings.SUPABASE_HOST}:{settings.SUPABASE_PORT}/{settings.SUPABASE_DB}",
            pool_size=10, 
            max_overflow=20,
            pool_pre_ping=True
        )
        self.Session = sessionmaker(bind=self.engine)
        logger.info("Supabase client initialized")

    def health_check(self) -> bool:
        """Simple health check against database"""
        try:
            with self.Session() as session:
                session.execute("SELECT 1")
            logger.info("Supabase health check passed")
            return True
        except Exception as e:
            logger.error(f"Supabase health check failed: {e}")
            return False

    def create_scan(self, record: Dict) -> Dict:
        """Insert a new scan record"""
        try:
            # Convert datetime objects to ISO strings
            for k, v in record.items():
                if isinstance(v, datetime):
                    record[k] = v.isoformat()
                    
            res = self.admin.table("owasp_scans").insert(record).execute()
            if hasattr(res, 'error') and res.error:
                raise Exception(res.error.message)
            return res.data[0] if res.data else None
        except Exception as e:
            logger.error(f"Failed to create scan: {str(e)}", exc_info=True)
            raise

    def update_scan(self, scan_id: str, update: Dict) -> Optional[Dict]:
        """Update scan record identified by scan_id"""
        try:
            # Convert datetime to ISO strings
            for k, v in list(update.items()):
                if isinstance(v, datetime):
                    update[k] = v.isoformat()
                    
            res = self.admin.table("owasp_scans").update(update).eq("scan_id", scan_id).execute()
            if hasattr(res, 'error') and res.error:
                logger.error(f"Supabase error: {res.error}")
                return None
            return res.data[0] if res.data else None
        except Exception as e:
            logger.error(f"Failed to update scan {scan_id}: {str(e)}", exc_info=True)
            return None

    def fetch_scan(self, scan_id: str) -> Optional[Dict]:
        """Retrieve a single scan record"""
        try:
            res = self.client.table("owasp_scans").select("*").eq("scan_id", scan_id).single().execute()
            if hasattr(res, 'error') and res.error:
                return None
            return res.data
        except Exception as e:
            logger.error(f"Failed to fetch scan {scan_id}: {str(e)}", exc_info=True)
            return None

    def insert_vulnerabilities(self, scan_id: str, vulns: List[Dict]) -> int:
        """Bulk insert vulnerabilities; adds scan_id to each record"""
        try:
            for v in vulns:
                v["scan_id"] = scan_id
                # Convert discovered_at to ISO if present
                if isinstance(v.get("discovered_at"), datetime):
                    v["discovered_at"] = v["discovered_at"].isoformat()
                    
            res = self.admin.table("owasp_vulnerabilities").insert(vulns).execute()
            if hasattr(res, 'error') and res.error:
                return 0
            return len(res.data) if res.data else 0
        except Exception as e:
            logger.error(f"Failed to insert vulnerabilities for {scan_id}: {str(e)}", exc_info=True)
            return 0

    def fetch_vulnerabilities(self, scan_id: str) -> List[Dict]:
        """Retrieve all vulnerabilities for a given scan_id"""
        try:
            res = self.client.table("owasp_vulnerabilities").select("*").eq("scan_id", scan_id).execute()
            if hasattr(res, 'error') and res.error:
                return []
            return res.data
        except Exception as e:
            logger.error(f"Failed to fetch vulnerabilities for {scan_id}: {str(e)}", exc_info=True)
            return []

    def revoke_token(self, jti: str, expires: datetime):
        """Add token to revocation list"""
        try:
            with self.Session() as session:
                session.execute(
                    "INSERT INTO revoked_tokens (jti, expires) VALUES (:jti, :expires) "
                    "ON CONFLICT (jti) DO UPDATE SET expires = :expires",
                    {"jti": jti, "expires": expires}
                )
                session.commit()
        except Exception as e:
            logger.error(f"Token revocation failed: {str(e)}", exc_info=True)

    def is_token_revoked(self, jti: str) -> bool:
        """Check if token is revoked"""
        try:
            if not jti:
                return False
                
            with self.Session() as session:
                result = session.execute(
                    "SELECT 1 FROM revoked_tokens WHERE jti = :jti AND expires > NOW()",
                    {"jti": jti}
                ).scalar()
                return bool(result)
        except Exception as e:
            logger.error(f"Token revocation check failed: {str(e)}", exc_info=True)
            return False
            
    def get_user_scans(self, user_id: str, status: Optional[str] = None, limit: int = 10, offset: int = 0) -> List[dict]:
        """Get scans for a specific user"""
        try:
            query = self.client.table("owasp_scans").select("*").eq("user_id", user_id)
            
            if status:
                query = query.eq("status", status)
                
            query = query.order("started_at", desc=True)
            query = query.range(offset, offset + limit - 1)
            
            res = query.execute()
            return res.data
        except Exception as e:
            logger.error(f"Failed to fetch user scans: {str(e)}", exc_info=True)
            return []

# Global instance
supabase = SupabaseClient()