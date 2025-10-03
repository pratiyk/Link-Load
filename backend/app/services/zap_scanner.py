import asyncio
import logging
import uuid
from datetime import datetime
from zapv2 import ZAPv2
from app.core.config import settings
from app.models.scan_models import Vulnerability, ScanRequest
from typing import List

logger = logging.getLogger(__name__)

class ScannerException(Exception):
    """Custom exception for scanner errors"""
    pass

class ZAPScanner:
    def __init__(self):
        self.api_key = settings.ZAP_API_KEY
        self.base_url = settings.ZAP_BASE_URL
        self.session_id = f"session-{uuid.uuid4()}"
        self.zap = None

    async def scan(self, target: str, req: ScanRequest) -> List[Vulnerability]:
        """Run active ZAP scan against the target URL with resource cleanup"""
        try:
            # Initialize ZAP client
            self.zap = ZAPv2(
                apikey=self.api_key,
                proxies={"http": self.base_url, "https": self.base_url}
            )
            
            # Create new session
            self.zap.core.new_session(name=self.session_id, overwrite=True)
            
            # Configure scan
            self.zap.ascan.set_option_attack_policy("OWASP Top 10")
            self.zap.ascan.set_option_thread_per_host(5)
            
            if req.custom_headers:
                for key, value in req.custom_headers.items():
                    self.zap.httpsessions.add_session_token(key, value)
            
            if req.authenticated and req.auth_username and req.auth_password:
                self._configure_authentication(target, req)
            
            # Start scan
            logger.info(f"Starting ZAP scan for {target}")
            scan_id = self.zap.ascan.scan(target)
            
            # Poll for status with progress updates
            progress = 0
            while progress < 100:
                await asyncio.sleep(10)
                progress = int(self.zap.ascan.status(scan_id))
                if progress == -1:  # Error state
                    raise ScannerException("ZAP scan encountered an error")
            
            # Retrieve results
            alerts = self.zap.core.alerts(baseurl=target)
            vulns = []
            for a in alerts:
                # Skip low risk if configured
                if not req.include_low_risk and a.get("risk") == "Low":
                    continue
                    
                vulns.append(Vulnerability(  # type: ignore[call-arg]
                    id=f"zap-{a.get('pluginId')}-{hash(a.get('url',''))}",
                    name=a.get("alert", "Unknown"),
                    description=a.get("description", ""),
                    severity=a.get("risk", "Low"),
                    confidence=a.get("confidence", ""),
                    solution=a.get("solution", ""),
                    references=[ref.strip() for ref in a.get("reference","").split("\n") if ref.strip()],
                    url=a.get("url"),
                    parameter=a.get("param"),
                    method=a.get("method"),
                    evidence=a.get("evidence"),
                    payload=a.get("attack"),
                    cve_id=a.get("cweid"),
                    cwe_id=a.get("cweid"),
                    owasp_category=a.get("wascid"),
                    scanner="ZAP",
                    discovered_at=datetime.utcnow()
                ))
            
            logger.info(f"ZAP scan completed with {len(vulns)} findings")
            return vulns
        except Exception as e:
            logger.error(f"ZAP scan error: {e}", exc_info=True)
            raise ScannerException(f"ZAP scan failed: {str(e)}")
        finally:
            # Cleanup session
            self._cleanup()

    def _configure_authentication(self, target: str, req: ScanRequest):
        """Configure authentication for ZAP scan"""
        try:
            # Setup authentication method
            auth_method = {
                "form": "formBasedAuthentication",
                "http": "httpAuthentication",
                "script": "scriptBasedAuthentication"
            }.get(req.auth_type or "form", "formBasedAuthentication")
            
            # Configure login URL
            self.zap.authentication.set_authentication_method(  # type: ignore
                contextid="1",
                authmethodname=auth_method,
                authmethodconfigparams=f"loginUrl={req.login_url}"
            )
            
            # Set credentials
            self.zap.authentication.set_authentication_credentials(  # type: ignore
                contextid="1",
                authcredentialsconfigparams=f"username={req.auth_username}&password={req.auth_password}"
            )
            
            # Set logged in indicator
            self.zap.authentication.set_logged_in_indicator(  # type: ignore
                contextid="1", 
                loggedinindicatorregex="logout"
            )
        except Exception as e:
            logger.error(f"ZAP auth configuration failed: {str(e)}")
            raise ScannerException("Authentication configuration failed")

    def _cleanup(self):
        """Cleanup ZAP resources"""
        try:
            if self.zap:
                self.zap.core.delete_session(self.session_id)  # type: ignore
        except Exception as e:
            logger.warning(f"ZAP session cleanup failed: {str(e)}")