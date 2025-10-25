import logging
import os
import time
from enum import Enum
from supabase import create_client, Client
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from app.core.config import settings
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DatabaseError(Exception):
    """Base class for database errors"""
    pass

class ConnectionError(DatabaseError):
    """Database connection error"""
    pass

class QueryError(DatabaseError):
    """Database query error"""
    pass

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
                session.execute(text("SELECT 1"))
                session.commit()
            logger.info("Supabase health check passed")
            return True
        except OperationalError as e:
            logger.error(f"Supabase connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Supabase health check failed: {e}")
            return False
            
    def cleanup_expired_tokens(self) -> None:
        """Remove expired tokens from revocation list"""
        try:
            with self.Session() as session:
                session.execute(
                    text("DELETE FROM revoked_tokens WHERE expires < NOW()")
                )
                session.commit()
        except Exception as e:
            logger.error(f"Failed to cleanup expired tokens: {e}")

    @contextmanager
    def get_connection(self):
        """Context manager for database connections with retry logic"""
        retries = 3
        delay = 1  # Initial delay in seconds
        
        for attempt in range(retries):
            try:
                session = self.Session()
                try:
                    yield session
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
                finally:
                    session.close()
                return
            except OperationalError as e:
                if attempt == retries - 1:
                    raise ConnectionError(f"Failed to connect to database after {retries} attempts") from e
                logger.warning(f"Database connection attempt {attempt + 1} failed, retrying...")
                time.sleep(delay * (2 ** attempt))  # Exponential backoff

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {}
        for key, value in record.items():
            if isinstance(value, datetime):
                normalized[key] = value.isoformat()
            elif isinstance(value, Enum):
                normalized[key] = value.value
            else:
                normalized[key] = value
        return normalized

    def create_scan(self, record: Dict) -> Optional[Dict[str, Any]]:
        """Insert a new scan record"""
        try:
            res = self.admin.table("owasp_scans").insert(self._normalize_record(record)).execute()
            if not res.data:
                return None
            return res.data[0]
        except Exception as e:
            logger.error(f"Failed to create scan: {str(e)}", exc_info=True)
            raise

    def update_scan(self, scan_id: str, update: Dict) -> Optional[Dict[str, Any]]:
        """Update scan record identified by scan_id"""
        try:
            normalized = self._normalize_record(update)
            
            # Filter out columns that might not exist in schema yet (for Supabase cache issues)
            # Known safe columns
            safe_columns = {
                'scan_id', 'user_id', 'target_url', 'status', 'progress', 'current_stage',
                'started_at', 'completed_at', 'scan_types', 'options', 'risk_score', 
                'risk_level', 'ai_analysis', 'mitre_mapping', 'remediation_strategies',
                'created_at', 'updated_at'
            }
            
            # Filter update to only include safe columns initially
            filtered_update = {k: v for k, v in normalized.items() if k in safe_columns}
            
            # Try with filtered update
            res = self.admin.table("owasp_scans").update(filtered_update).eq("scan_id", scan_id).execute()
            if not res.data:
                return None
            if len(res.data) == 0:
                return None
            return res.data[0]
        except Exception as e:
            logger.error(f"Failed to update scan {scan_id}: {str(e)}", exc_info=True)
            return None

    def fetch_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single scan record"""
        try:
            res = self.client.table("owasp_scans").select("*").eq("scan_id", scan_id).single().execute()
            if not res.data:
                return None
            return res.data
        except Exception as e:
            logger.error(f"Failed to fetch scan {scan_id}: {str(e)}", exc_info=True)
            return None

    def insert_vulnerabilities(self, scan_id: str, vulns: List[Dict[str, Any]]) -> int:
        """Bulk insert vulnerabilities; adds scan_id to each record"""
        try:
            for v in vulns:
                v["scan_id"] = scan_id
                # Convert discovered_at to ISO if present
                if isinstance(v.get("discovered_at"), datetime):
                    v["discovered_at"] = v["discovered_at"].isoformat()
                    
            normalized = [self._normalize_record(v) for v in vulns]
            res = self.admin.table("owasp_vulnerabilities").insert(normalized).execute()
            return len(res.data) if res.data else 0
        except Exception as e:
            logger.error(f"Failed to insert vulnerabilities for {scan_id}: {str(e)}", exc_info=True)
            return 0

    def fetch_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve all vulnerabilities for a given scan_id"""
        try:
            res = self.client.table("owasp_vulnerabilities").select("*").eq("scan_id", scan_id).execute()
            return res.data if res.data else []
        except Exception as e:
            logger.error(f"Failed to fetch vulnerabilities for {scan_id}: {str(e)}", exc_info=True)
            return []

    def revoke_token(self, jti: str, expires: datetime):
        """Add token to revocation list"""
        try:
            with self.Session() as session:
                session.execute(
                    text("INSERT INTO revoked_tokens (jti, expires) VALUES (:jti, :expires) "
                         "ON CONFLICT (jti) DO UPDATE SET expires = :expires"),
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
                    text("SELECT 1 FROM revoked_tokens WHERE jti = :jti AND expires > NOW()"),
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

    def insert_batch_scan(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Insert a new batch scan record"""
        try:
            res = self.admin.table("batch_scans").insert(self._normalize_record(record)).execute()
            if not res.data:
                return None
            return res.data[0]
        except Exception as e:
            logger.error(f"Failed to create batch scan: {str(e)}", exc_info=True)
            raise

    def update_batch_scan(self, batch_id: str, update: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update batch scan record"""
        try:
            normalized = self._normalize_record(update)
            res = self.admin.table("batch_scans").update(normalized).eq("batch_id", batch_id).execute()
            if not res.data:
                return None
            if len(res.data) == 0:
                return None
            return res.data[0]
        except Exception as e:
            logger.error(f"Failed to update batch scan {batch_id}: {str(e)}", exc_info=True)
            return None

    def fetch_batch_scan(self, batch_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single batch scan record"""
        try:
            res = self.client.table("batch_scans").select("*").eq("batch_id", batch_id).single().execute()
            if not res.data:
                return None
            return res.data
        except Exception as e:
            logger.error(f"Failed to fetch batch scan {batch_id}: {str(e)}", exc_info=True)
            return None

    def fetch_batch_scan_results(self, batch_id: str) -> List[str]:
        """Retrieve all scan IDs associated with a batch"""
        try:
            res = self.client.table("owasp_scans").select("scan_id").like("scan_id", f"{batch_id}-%").execute()
            return [r["scan_id"] for r in res.data] if res.data else []
        except Exception as e:
            logger.error(f"Failed to fetch batch scan results for {batch_id}: {str(e)}", exc_info=True)
            return []

# Global instance
supabase = SupabaseClient()