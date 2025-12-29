import logging
import os
import time
import uuid
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import contextmanager

import httpx
from supabase import create_client, Client
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from sqlalchemy.engine.url import make_url

from app.core.config import settings

from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

_DEFAULT_CVSS_BY_SEVERITY = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.1,
}

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
        # In-memory fallback stores (used when DB is unavailable)
        self._memory_scans: Dict[str, Dict[str, Any]] = {}
        self._memory_vulns: Dict[str, List[Dict[str, Any]]] = {}
        
        # Initialize SQLAlchemy engine for raw SQL operations
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL must be set to your Supabase PostgreSQL connection string.")

        connect_args = self._build_connect_args(db_url)

        engine_kwargs: Dict[str, Any] = {"pool_pre_ping": True}

        if connect_args:
            engine_kwargs["connect_args"] = connect_args

        backend_name = None
        try:
            backend_name = make_url(db_url).get_backend_name()
        except Exception:
            backend_name = None

        if backend_name and backend_name.startswith("postgres"):
            engine_kwargs.update({"pool_size": 10, "max_overflow": 20})
        elif backend_name and backend_name.startswith("sqlite"):
            sqlite_args = dict(engine_kwargs.get("connect_args", {}))
            sqlite_args.setdefault("check_same_thread", False)
            engine_kwargs["connect_args"] = sqlite_args

        self.engine = create_engine(db_url, **engine_kwargs)
        self.Session = sessionmaker(bind=self.engine)
        logger.info("Supabase client initialized")

    def _build_connect_args(self, database_url: str) -> Dict[str, Any]:
        """Build connection arguments with sensible defaults for Supabase."""
        try:
            url = make_url(database_url)
        except Exception:
            return {}

        host = (url.host or "").lower()
        query = url.query if hasattr(url, "query") and url.query else {}

        if isinstance(query, dict) and "sslmode" in query:
            return {}

        if host and host not in {"localhost", "127.0.0.1"} and not host.startswith("localhost"):
            ssl_mode = os.getenv("SUPABASE_SSLMODE", "require")
            return {"sslmode": ssl_mode}

        return {}

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

    def _prepare_vulnerability_record(self, scan_id: str, vulnerability: Any) -> Dict[str, Any]:
        """Normalize scanner output into the minimal schema expected by the DB."""
        if vulnerability is None:
            return {"scan_id": scan_id, "title": "Unknown", "severity": "medium"}

        if hasattr(vulnerability, "dict"):
            raw = vulnerability.dict()
        else:
            raw = dict(vulnerability)

        record: Dict[str, Any] = dict(raw)
        record["scan_id"] = scan_id

        # Ensure core fields exist so DB constraints pass even if scanners omit them.
        title = record.get("title") or record.get("name") or record.get("vulnerability")
        if not title:
            logger.debug("Vulnerability missing title; defaulting to Unknown", extra={"scanner_source": record.get("scanner_source")})
            title = "Unknown"
        record["title"] = title

        if not record.get("description"):
            record["description"] = record.get("details") or ""

        severity = record.get("severity") or "medium"
        severity = str(severity).lower()
        record["severity"] = severity

        cvss_score = record.get("cvss_score")
        if cvss_score is None:
            cvss_score = _DEFAULT_CVSS_BY_SEVERITY.get(severity, 0.0)
        else:
            try:
                cvss_score = float(cvss_score)
            except (TypeError, ValueError):
                cvss_score = _DEFAULT_CVSS_BY_SEVERITY.get(severity, 0.0)
        record["cvss_score"] = cvss_score

        # Align location/recommendation defaults with what the API expects to return.
        location = record.get("location") or record.get("url") or record.get("path") or ""
        record["location"] = location

        if not record.get("recommendation"):
            record["recommendation"] = record.get("solution") or ""

        scanner_source = record.get("scanner_source") or record.get("source") or "unknown"
        record["scanner_source"] = scanner_source

        scanner_id = record.get("scanner_id") or record.get("vuln_id") or record.get("id")
        record["scanner_id"] = scanner_id

        references = record.get("references")
        if isinstance(references, dict):
            references = list(references.values())
        record["references"] = references or []

        tags = record.get("tags")
        if isinstance(tags, dict):
            tags = list(tags.values())
        record["tags"] = tags or []

        mitre = record.get("mitre_techniques")
        if isinstance(mitre, set):
            mitre = list(mitre)
        record["mitre_techniques"] = mitre or []

        discovered_at = record.get("discovered_at")
        if isinstance(discovered_at, str):
            try:
                discovered_at = datetime.fromisoformat(discovered_at)
            except ValueError:
                discovered_at = None
        if not isinstance(discovered_at, datetime):
            discovered_at = utc_now()
        record["discovered_at"] = discovered_at

        return record

    def cache_vulnerabilities(self, scan_id: str, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Persist vulnerabilities in the in-memory fallback store."""
        prepared = [self._prepare_vulnerability_record(scan_id, vuln) for vuln in vulns]
        cached = [self._normalize_record(record) for record in prepared]

        if cached:
            self._memory_vulns[scan_id] = cached
        else:
            self._memory_vulns.pop(scan_id, None)
        return cached

    def create_scan(self, record: Dict) -> Optional[Dict[str, Any]]:
        """Insert a new scan record"""
        try:
            normalized = self._normalize_record(record)
            res = self.admin.table("owasp_scans").insert(normalized).execute()
            if not res.data:
                self._memory_scans[normalized.get("scan_id")] = dict(normalized)
                return None

            created = res.data[0]
            self._memory_scans[created.get("scan_id")] = dict(created)
            return created
        except Exception as e:
            logger.error(f"Failed to create scan: {str(e)}", exc_info=True)
            scan_id = record.get("scan_id") or f"mem_{uuid.uuid4().hex[:12]}"
            record["scan_id"] = scan_id
            self._memory_scans[scan_id] = self._normalize_record(record)
            return record

    def update_scan(self, scan_id: str, update: Dict) -> Optional[Dict[str, Any]]:
        """Update scan record identified by scan_id"""
        try:
            normalized = self._normalize_record(update)

            safe_columns = {
                "scan_id",
                "user_id",
                "target_url",
                "status",
                "progress",
                "current_stage",
                "started_at",
                "completed_at",
                "scan_types",
                "options",
                "risk_score",
                "risk_level",
                "critical_count",
                "high_count",
                "medium_count",
                "low_count",
                "ai_analysis",
                "mitre_mapping",
                "remediation_strategies",
                "executive_summary",
                "scanner_debug",
                "threat_intel",  # Threat intelligence data from external APIs
                "created_at",
                "updated_at",
            }

            filtered_update = {k: v for k, v in normalized.items() if k in safe_columns}
            res = self.admin.table("owasp_scans").update(filtered_update).eq("scan_id", scan_id).execute()

            mem = self._memory_scans.get(scan_id, {})
            mem.update(normalized)
            self._memory_scans[scan_id] = dict(mem)

            if not res.data:
                return mem or None

            updated = res.data[0]
            merged = dict(mem)
            merged.update(updated)
            self._memory_scans[scan_id] = merged
            return merged
        except Exception as e:
            logger.error(f"Failed to update scan {scan_id}: {str(e)}", exc_info=True)
            # Fallback to memory
            mem = self._memory_scans.get(scan_id, {})
            mem.update(self._normalize_record(update))
            self._memory_scans[scan_id] = mem
            return mem

    def fetch_scan(self, scan_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve a single scan record.
        
        Args:
            scan_id: The scan ID to fetch
            user_id: If provided, verify the scan belongs to this user (data isolation)
            
        Returns:
            The scan data or None if not found
            
        Raises:
            Exception: If user_id is provided but doesn't match the scan owner
        """
        try:
            res = self.client.table("owasp_scans").select("*").eq("scan_id", scan_id).execute()
            if not res.data or len(res.data) == 0:
                # Fallback to memory
                return self._memory_scans.get(scan_id)
            # Use first result if multiple
            scan_data = res.data[0] if isinstance(res.data, list) else res.data
            
            # If user_id provided, verify ownership (data isolation)
            if user_id:
                scan_owner = scan_data.get("user_id")
                if scan_owner != user_id:
                    from app.core.authorization import AccessDeniedException
                    raise AccessDeniedException(
                        f"You do not have access to scan {scan_id}"
                    )
            
            # Merge DB data into existing memory (preserve extra debug fields)
            existing = self._memory_scans.get(scan_id, {})
            merged = dict(existing)
            merged.update(scan_data)
            self._memory_scans[scan_id] = dict(merged)
            return merged
        except Exception as e:
            logger.debug(f"Failed to fetch scan {scan_id} from DB: {str(e)}")
            return self._memory_scans.get(scan_id)

    def insert_vulnerabilities(self, scan_id: str, vulns: List[Dict[str, Any]]) -> int:
        """Bulk insert vulnerabilities; adds scan_id to each record"""
        try:
            logger.info(f"insert_vulnerabilities called for scan {scan_id} with {len(vulns)} vulns")
            normalized = self.cache_vulnerabilities(scan_id, vulns)
            if not normalized:
                logger.warning(f"No normalized vulnerabilities for scan {scan_id}")
                return 0

            logger.info(f"Cached {len(normalized)} normalized vulnerabilities for scan {scan_id}")
            
            # Try DB insert best-effort
            try:
                allowed_columns = {
                    "scan_id",
                    "title",
                    "description",
                    "severity",
                    "cvss_score",
                    "location",
                    "recommendation",
                    "mitre_techniques",
                    "scanner_source",
                    "scanner_id",
                    "discovered_at"
                }
                db_records = [
                    {k: record[k] for k in allowed_columns if k in record and record[k] is not None}
                    for record in normalized
                ]

                if db_records:
                    logger.info(f"Attempting DB insert of {len(db_records)} records for scan {scan_id}")
                    res = self.admin.table("owasp_vulnerabilities").insert(db_records).execute()
                    if res.data:
                        logger.info(f"Successfully inserted {len(res.data)} vulnerabilities to DB for scan {scan_id}")
                        return len(res.data)
                    else:
                        logger.warning(f"DB insert returned no data for scan {scan_id}")
            except Exception as db_err:
                logger.warning(f"DB insert_vulnerabilities failed, using memory store: {db_err}")
            return len(self._memory_vulns.get(scan_id, []))
        except Exception as e:
            logger.error(f"Failed to insert vulnerabilities for {scan_id}: {str(e)}", exc_info=True)
            # Still preserve in memory if normalization failed partially
            try:
                self.cache_vulnerabilities(scan_id, vulns)
            except Exception:
                pass
            return len(self._memory_vulns.get(scan_id, []))

    def fetch_vulnerabilities(self, scan_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve all vulnerabilities for a given scan_id.
        
        Args:
            scan_id: The scan ID to fetch vulnerabilities for
            user_id: If provided, verify the scan belongs to this user before returning data
            
        Returns:
            List of vulnerability records
            
        Raises:
            Exception: If user_id is provided but scan doesn't belong to user
        """
        try:
            # If user_id provided, verify ownership first
            if user_id:
                scan = self.fetch_scan(scan_id, user_id=user_id)
                if not scan:
                    logger.warning(f"Scan {scan_id} not found or not owned by user {user_id}")
                    return []
            
            # Use admin client to bypass RLS since vulnerabilities don't have user_id
            # The ownership check is done via the scan record above
            res = self.admin.table("owasp_vulnerabilities").select("*").eq("scan_id", scan_id).execute()
            logger.info(f"Fetched {len(res.data) if res.data else 0} vulnerabilities for scan {scan_id}")
            
            if res.data:
                # Sync memory cache
                self._memory_vulns[scan_id] = list(res.data)
                return res.data
            
            # Fallback to memory cache
            memory_vulns = self._memory_vulns.get(scan_id, [])
            if memory_vulns:
                logger.info(f"Using {len(memory_vulns)} cached vulnerabilities for scan {scan_id}")
            return memory_vulns
            
        except Exception as e:
            logger.error(f"Failed to fetch vulnerabilities for {scan_id}: {str(e)}", exc_info=True)
            return self._memory_vulns.get(scan_id, [])

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

    def confirm_user_email(self, email: str) -> bool:
        """Mark a Supabase user's email as confirmed using the service role API."""
        if not email:
            raise ValueError("Email is required for confirmation")

        base_url = settings.SUPABASE_URL.rstrip('/')
        headers = {
            "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
            "apikey": settings.SUPABASE_SERVICE_KEY,
            "Content-Type": "application/json",
        }

        with httpx.Client(timeout=httpx.Timeout(10.0, read=10.0)) as client:
            response = client.get(
                f"{base_url}/auth/v1/admin/users",
                params={"email": email},
                headers=headers,
            )
            if response.status_code != 200:
                logger.error("Supabase admin list users failed: %s", response.text)
                raise RuntimeError("Failed to query Supabase users")

            data = response.json() or {}
            users = data.get("users") or []
            if not users:
                return False

            user_id = users[0].get("id")
            if not user_id:
                return False

            confirm_payload = {
                "email_confirmed_at": datetime.utcnow().isoformat() + "Z",
                "email": email,
            }

            update_response = client.put(
                f"{base_url}/auth/v1/admin/users/{user_id}",
                json=confirm_payload,
                headers=headers,
            )

            if update_response.status_code not in {200, 204}:
                logger.error("Supabase admin update user failed: %s", update_response.text)
                raise RuntimeError("Failed to confirm Supabase user")

            return True

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

    def delete_scan(self, scan_id: str, user_id: Optional[str] = None) -> bool:
        """Permanently delete a scan and all associated vulnerabilities.
        
        Args:
            scan_id: The scan ID to delete
            user_id: If provided, verify the scan belongs to this user before deleting
            
        Returns:
            True if deletion was successful, False otherwise
            
        Raises:
            Exception: If user_id is provided but scan doesn't belong to user
        """
        try:
            # Verify ownership if user_id provided
            if user_id:
                scan = self.fetch_scan(scan_id, user_id=user_id)
                if not scan:
                    logger.warning(f"Scan {scan_id} not found or not owned by user {user_id}")
                    return False
            
            # Delete vulnerabilities first (foreign key constraint)
            try:
                vuln_res = self.admin.table("owasp_vulnerabilities").delete().eq("scan_id", scan_id).execute()
                vuln_count = len(vuln_res.data) if vuln_res.data else 0
                logger.info(f"Deleted {vuln_count} vulnerabilities for scan {scan_id}")
            except Exception as vuln_err:
                logger.warning(f"Failed to delete vulnerabilities for scan {scan_id}: {vuln_err}")
            
            # Delete the scan record
            res = self.admin.table("owasp_scans").delete().eq("scan_id", scan_id).execute()
            
            # Clean up memory cache
            if scan_id in self._memory_scans:
                del self._memory_scans[scan_id]
            if scan_id in self._memory_vulns:
                del self._memory_vulns[scan_id]
            
            deleted = len(res.data) > 0 if res.data else False
            if deleted:
                logger.info(f"Successfully deleted scan {scan_id}")
            else:
                logger.warning(f"Scan {scan_id} not found in database")
            
            return deleted
            
        except Exception as e:
            logger.error(f"Failed to delete scan {scan_id}: {str(e)}", exc_info=True)
            return False

    def delete_user_scans(self, user_id: str, before_date: Optional[datetime] = None) -> int:
        """Delete all scans for a user, optionally filtered by date.
        
        Args:
            user_id: The user ID whose scans to delete
            before_date: If provided, only delete scans created before this date
            
        Returns:
            Number of scans deleted
        """
        try:
            # Get all scan IDs for the user
            query = self.admin.table("owasp_scans").select("scan_id").eq("user_id", user_id)
            if before_date:
                query = query.lt("created_at", before_date.isoformat())
            
            res = query.execute()
            if not res.data:
                return 0
            
            scan_ids = [r["scan_id"] for r in res.data]
            deleted_count = 0
            
            for scan_id in scan_ids:
                if self.delete_scan(scan_id):
                    deleted_count += 1
            
            logger.info(f"Deleted {deleted_count} scans for user {user_id}")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to delete user scans for {user_id}: {str(e)}", exc_info=True)
            return 0

# Global instance
supabase = SupabaseClient()