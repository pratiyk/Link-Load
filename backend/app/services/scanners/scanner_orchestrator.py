from typing import List, Dict, Any, Optional, cast
import asyncio
import logging

from app.services.scanners.base_scanner import BaseScanner
from app.services.scanners.zap_scanner import ZAPScanner
from app.services.scanners.nuclei_scanner import NucleiScanner
from app.services.scanners.wapiti_scanner import WapitiScanner
from app.database import get_db_context
from app.api.ws_manager import progress_manager
from sqlalchemy import text
from app.utils.datetime_utils import utc_now_naive

logger = logging.getLogger(__name__)

class ScannerOrchestrator:
    """Orchestrates multiple security scanners and manages scan lifecycle"""
    
    def __init__(self):
        self.scanners: Dict[str, BaseScanner] = {
            "zap": ZAPScanner(),
            "nuclei": NucleiScanner(),
            "wapiti": WapitiScanner()
        }
        self.active_scans: Dict[str, Dict[str, Any]] = {}
    
    def _update_scan_status(self, db, scan_id: str, status: str, progress: Optional[Dict] = None):
        """Update scan status in database"""
        stmt = text(
            "UPDATE security_scans SET status = :status WHERE id = :scan_id"
        ).bindparams(status=status, scan_id=scan_id)
        
        if progress:
            stmt = text(
                """UPDATE security_scans 
                SET status = :status, progress = :progress 
                WHERE id = :scan_id"""
            ).bindparams(status=status, progress=progress, scan_id=scan_id)
        
        db.execute(stmt)
        db.commit()
    
    def _save_finding(self, db, finding: Dict):
        """Save vulnerability finding to database"""
        stmt = text(
            """INSERT INTO vulnerability_findings 
            (scan_id, scanner, name, description, severity, confidence,
            url, parameter, method, solution, references, evidence, payload,
            cwe_id, owasp_category, tags, attack_complexity, attack_vector,
            privileges_required, user_interaction, impact, risk_score,
            discovered_at, raw_finding)
            VALUES 
            (:scan_id, :scanner, :name, :description, :severity, :confidence,
            :url, :parameter, :method, :solution, :references, :evidence, :payload,
            :cwe_id, :owasp_category, :tags, :attack_complexity, :attack_vector,
            :privileges_required, :user_interaction, :impact, :risk_score,
            :discovered_at, :raw_finding)"""
        ).bindparams(**finding)
        
        db.execute(stmt)
        db.commit()
    
    async def run_scan(self, scan_id: str, target: str, scan_types: List[str], config: Dict):
        """Run security scan with specified scanners"""
        try:
            with get_db_context() as db:
                self._update_scan_status(db, scan_id, "running")
                self.active_scans[scan_id] = {"target": target, "scanners": scan_types}
                
                overall_progress = 0
                findings = []
                scanner_count = len(scan_types)
                
                for scanner_type in scan_types:
                    if scanner_type not in self.scanners:
                        logger.warning(f"Scanner {scanner_type} not found")
                        continue
                    
                    scanner = cast(Any, self.scanners[scanner_type])
                    
                    try:
                        # Initialize scanner
                        await scanner.setup(config.get(scanner_type, {}))
                        
                        # Start scanning
                        async for progress in scanner.scan(target):
                            # Update overall progress
                            scanner_progress = progress.get("progress", 0)
                            overall_progress = (scanner_progress + 100 * scan_types.index(scanner_type)) / scanner_count
                            
                            # Save progress
                            progress_data = {
                                "scanner": scanner_type,
                                "progress": overall_progress,
                                "current_step": progress.get("step", "scanning"),
                                "details": progress.get("details", {})
                            }
                            self._update_scan_status(db, scan_id, "running", progress_data)
                            
                            # Broadcast progress
                            await progress_manager.broadcast_progress(scan_id, progress_data)
                            
                            # Save findings
                            new_findings = progress.get("findings", [])
                            for finding in new_findings:
                                finding["scan_id"] = scan_id
                                finding["scanner"] = scanner_type
                                finding["discovered_at"] = utc_now_naive()
                                
                                self._save_finding(db, finding)
                                findings.extend(new_findings)
                                
                                # Broadcast finding
                                await progress_manager.broadcast_finding(scan_id, finding)
                    
                    except Exception as e:
                        logger.error(f"Error in scanner {scanner_type}: {e}")
                        continue
                    finally:
                        await scanner.cleanup()
                
                # Calculate summary
                summary = self._calculate_summary(findings)
                
                # Update scan completion
                stmt = text(
                    """UPDATE security_scans 
                    SET status = 'completed', 
                    completed_at = :completed_at,
                    summary = :summary
                    WHERE id = :scan_id"""
                ).bindparams(
                    completed_at=utc_now_naive(),
                    summary=summary,
                    scan_id=scan_id
                )
                
                db.execute(stmt)
                db.commit()
                
                # Broadcast completion
                await progress_manager.broadcast_completion(scan_id, summary)
                
        except Exception as e:
            logger.error(f"Error in scan {scan_id}: {e}")
            with get_db_context() as db:
                self._update_scan_status(db, scan_id, "error", {"error": str(e)})
        
        finally:
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
    
    def stop_scan(self, scan_id: str):
        """Stop an active scan"""
        if scan_id not in self.active_scans:
            return
        
        scan_info = self.active_scans[scan_id]
        for scanner_type in scan_info["scanners"]:
            if scanner_type in self.scanners:
                asyncio.create_task(self.scanners[scanner_type].stop())
    
    def _calculate_summary(self, findings: List[Dict]) -> Dict:
        """Calculate scan summary from findings"""
        summary = {
            "total_vulnerabilities": len(findings),
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "false_positive_count": 0,
            "risk_score": 0.0,
        }
        
        for finding in findings:
            severity = finding.get("severity", "").lower()
            if severity == "critical":
                summary["critical_count"] += 1
            elif severity == "high":
                summary["high_count"] += 1
            elif severity == "medium":
                summary["medium_count"] += 1
            elif severity == "low":
                summary["low_count"] += 1
            elif severity == "info":
                summary["info_count"] += 1
            
            if finding.get("false_positive"):
                summary["false_positive_count"] += 1
        
        # Calculate risk score (0-100)
        total_weighted = (
            summary["critical_count"] * 100 +
            summary["high_count"] * 70 +
            summary["medium_count"] * 40 +
            summary["low_count"] * 10
        )
        max_score = max(1, total_weighted)  # Avoid division by zero
        summary["risk_score"] = min(100.0, total_weighted / max_score * 100)
        
        return summary