import asyncio
import logging
import os
import json
import csv
import threading
import hashlib
import inspect
from contextlib import suppress
from datetime import datetime, timezone
from typing import List, Optional, Dict, Callable
from collections import defaultdict
from fpdf import FPDF  # fpdf2 package
import tempfile

# Import scanner implementations directly to avoid circular imports through app.services
from app.services.scanners import zap_scanner, nuclei_scanner, wapiti_scanner
from app.database.supabase_client import supabase
from app.models.scan_models import ScanRequest, ScanResult, Vulnerability, ScanProgress, ScanStatus, ScanSummary
from app.core.config import settings
from app.utils.datetime_utils import utc_now
logger = logging.getLogger(__name__)

class OWASPOrchestrator:
    def __init__(self):
        self.scans: Dict[str, Dict] = {}
        self.zap = zap_scanner.ZAPScanner()
        self.nuclei = nuclei_scanner.NucleiScanner()
        self.wapiti = wapiti_scanner.WapitiScanner()
        self.lock = threading.Lock()  # For synchronous access
        self.async_lock = asyncio.Lock()  # For async contexts
        self.subscribers = defaultdict(list)
        self._cache = {}
    
    def _get_from_cache(self, key: str):
        """Get value from in-memory cache"""
        return self._cache.get(key)
    
    def _set_in_cache(self, key: str, value: any, expire: int = 3600):
        """Set value in in-memory cache"""
        self._cache[key] = value
    
    async def get_cached_scan_result(self, scan_id: str, user_id: str) -> Optional[ScanResult]:
        """Get cached scan result or fetch from database"""
        cache_key = f"scan_result:{scan_id}:{user_id}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
        result = self.get_result(scan_id, user_id)
        if result:
            self._set_in_cache(cache_key, result)
        return result

    async def get_cached_vulnerability_list(self, scan_id: str) -> List[Vulnerability]:
        """Get cached vulnerability list or fetch from database"""
        cache_key = f"vulns:{scan_id}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
        raw_vulns = supabase.fetch_vulnerabilities(scan_id)
        vulns = [Vulnerability(**v) for v in raw_vulns]
        self._set_in_cache(cache_key, vulns)
        return vulns

    def _generate_cache_key(self, target_url: str, scan_types: List[str]) -> str:
        """Generate a unique cache key based on scan parameters"""
        key_str = f"{target_url}:{','.join(sorted(scan_types))}"
        return hashlib.sha256(key_str.encode()).hexdigest()

    async def get_cached_risk_score(self, cache_key: str, vulnerabilities: List[Vulnerability]) -> float:
        """Cache and return risk score calculation"""
        score_key = f"risk_score:{cache_key}"
        cached = self._get_from_cache(score_key)
        if cached:
            return cached
        score = self.calculate_risk_score(vulnerabilities)
        self._set_in_cache(score_key, score)
        return score

    async def run_scan(self, scan_id: str, req: ScanRequest, user_id: str):
        """Run the selected scanners with progress tracking, cancellation, and caching"""
        cache_key = self._generate_cache_key(str(req.target_url), req.scan_types)
        
        try:
            # Check cache for recent scan results
            cached_vulns = self._get_from_cache(f"scan_vulns:{cache_key}")
            
            if cached_vulns and not req.force_new_scan:
                # Use cached results if available and not forcing new scan
                vulns = cached_vulns
                
                # Calculate summary from cached vulnerabilities
                summary = ScanSummary(
                    total_vulnerabilities=len(vulns),
                    critical_count=len([v for v in vulns if v.severity == "Critical"]),
                    high_count=len([v for v in vulns if v.severity == "High"]),
                    medium_count=len([v for v in vulns if v.severity == "Medium"]),
                    low_count=len([v for v in vulns if v.severity == "Low"]),
                    info_count=len([v for v in vulns if v.severity == "Info"]),
                    risk_score=await self.get_cached_risk_score(cache_key, vulns)
                )
                
                # Update database with cached results
                supabase.insert_vulnerabilities(scan_id, [v.dict() for v in vulns])
                supabase.update_scan(scan_id, {
                    "status": ScanStatus.COMPLETED,
                    "completed_at": utc_now(),
                    "duration": 0,  # Cached result
                    "summary": summary.dict()
                })
                
                return
            
            # Initialize progress tracking
            progress = ScanProgress(
                scan_id=scan_id,
                current_step="Initializing",
                progress_percentage=0,
                estimated_time_remaining=req.max_scan_time,
                total_urls=0,
                scanned_urls=0,
                vulnerabilities_found=0
            )
            
            async with self.async_lock:
                self.scans[scan_id] = {
                    "status": ScanStatus.RUNNING,
                    "progress": progress,
                    "task": asyncio.current_task(),
                    "user_id": user_id
                }
            
            # Update database status
            supabase.update_scan(scan_id, {
                "status": ScanStatus.RUNNING,
                "progress": progress.dict()
            })
            
            logger.info(f"Starting scan {scan_id} for {req.target_url}")
            
            # Launch chosen scans in parallel
            tasks = []
            scanner_count = 0
            
            if "zap_active" in req.scan_types:
                scanner_count += 1
                tasks.append(self.run_scanner(
                    "ZAP", 
                    self.zap.scan, 
                    str(req.target_url), 
                    progress,
                    req
                ))
                
            if "nuclei" in req.scan_types:
                scanner_count += 1
                tasks.append(self.run_scanner(
                    "Nuclei", 
                    self.nuclei.scan, 
                    str(req.target_url), 
                    progress,
                    req
                ))
                
            if "wapiti" in req.scan_types:
                scanner_count += 1
                tasks.append(self.run_scanner(
                    "Wapiti", 
                    self.wapiti.scan, 
                    str(req.target_url), 
                    progress,
                    req
                ))
            
            # Calculate progress increment per scanner
            progress_increment = 100 / (scanner_count or 1)
            
            try:
                # Execute scanners with timeout
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=req.max_scan_time
                )
            except asyncio.TimeoutError:
                logger.warning(f"Scan {scan_id} timed out after {req.max_scan_time} seconds")
                supabase.update_scan(scan_id, {
                    "status": ScanStatus.TIMEOUT,
                    "errors": ["Scan timed out"]
                })
                return
            except asyncio.CancelledError:
                logger.info(f"Scan {scan_id} was cancelled")
                return
            
            # Collect vulnerabilities
            all_vulns: List[Vulnerability] = []
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"Scanner error: {str(r)}", exc_info=True)
                elif r:
                    all_vulns.extend(r)
            
            # Filter out low risk if needed
            if not req.include_low_risk:
                all_vulns = [v for v in all_vulns if v.severity in ("Critical", "High", "Medium")]
            
            # Cache vulnerabilities
            self._set_in_cache(
                f"scan_vulns:{cache_key}",
                all_vulns,
                settings.CACHE_EXPIRE_IN_SECONDS
            )
            
            # Insert vulnerabilities
            vuln_count = supabase.insert_vulnerabilities(
                scan_id, 
                [v.dict() for v in all_vulns]
            )
            
            # Calculate and cache summary
            summary = ScanSummary(
                total_vulnerabilities=vuln_count,
                critical_count=len([v for v in all_vulns if v.severity == "Critical"]),
                high_count=len([v for v in all_vulns if v.severity == "High"]),
                medium_count=len([v for v in all_vulns if v.severity == "Medium"]),
                low_count=len([v for v in all_vulns if v.severity == "Low"]),
                info_count=len([v for v in all_vulns if v.severity == "Info"]),
                risk_score=await self.get_cached_risk_score(cache_key, all_vulns)
            )
            
            # Update progress
            progress.progress_percentage = 100
            progress.vulnerabilities_found = vuln_count
            progress.current_step = "Generating report"
            self.update_progress(scan_id, progress)
            
            # Mark scan completed
            end_time = utc_now()
            scan_data = supabase.fetch_scan(scan_id)
            start_time = datetime.fromisoformat(scan_data["started_at"]) if scan_data else utc_now()
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=timezone.utc)
            
            update_data = {
                "status": ScanStatus.COMPLETED,
                "completed_at": end_time,
                "duration": (end_time - start_time).total_seconds(),
                "progress": 100,
                "current_stage": "Completed",
                "summary": summary.dict()
            }
            
            supabase.update_scan(scan_id, update_data)
            logger.info(f"Scan {scan_id} completed with {vuln_count} vulnerabilities")
            
        except asyncio.CancelledError:
            # Handle cancellation
            logger.info(f"Scan {scan_id} cancelled by user")
            supabase.update_scan(scan_id, {"status": ScanStatus.CANCELLED})
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {str(e)}", exc_info=True)
            supabase.update_scan(scan_id, {
                "status": ScanStatus.FAILED,
                "errors": [str(e)]
            })
        finally:
            # Cleanup resources
            async with self.async_lock:
                with suppress(KeyError):
                    del self.scans[scan_id]

    async def run_scanner(self, name: str, scanner, target: str, progress: ScanProgress, req: ScanRequest):
        """Wrapper for scanner execution with progress updates"""
        try:
            # Update progress
            progress.current_step = f"Running {name}"
            progress.progress_percentage += 100 / 3  # Distribute progress evenly
            self.update_progress(progress.scan_id, progress)
            
            logger.info(f"Starting {name} scan for {target}")
            result = await scanner(target, req)
            logger.info(f"{name} scan completed with {len(result)} findings")
            
            # Update progress
            progress.scanned_urls += 10  # Simplified for demo
            progress.total_urls += 10
            progress.vulnerabilities_found += len(result)
            self.update_progress(progress.scan_id, progress)
            
            return result
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"{name} scanner failed: {str(e)}", exc_info=True)
            return []

    def update_progress(self, scan_id: str, progress: ScanProgress):
        """Update scan progress in memory and database"""
        with self.lock:
            if scan_id in self.scans:
                self.scans[scan_id]["progress"] = progress
                
        # Update database asynchronously
        asyncio.create_task(self._async_update_progress(scan_id, progress))
        
        # Notify subscribers with properly formatted WebSocket message
        # Frontend expects: {type: "progress", status: {scan_id, status, progress, current_stage}}
        ws_message = {
            "type": "progress",
            "status": {
                "scan_id": scan_id,
                "status": "in_progress",
                "progress": int(progress.progress_percentage),
                "current_stage": progress.current_step
            }
        }
        self.notify_subscribers(scan_id, ws_message)

    async def _async_update_progress(self, scan_id: str, progress: ScanProgress):
        """Asynchronously update progress in database"""
        try:
            # Update both progress object and current_stage for WebSocket polling
            supabase.update_scan(scan_id, {
                "progress": int(progress.progress_percentage),
                "current_stage": progress.current_step
            })
        except Exception as e:
            logger.error(f"Progress update failed: {str(e)}", exc_info=True)

    def get_progress(self, scan_id: str, user_id: str) -> Optional[ScanProgress]:
        """Get current scan progress"""
        with self.lock:
            scan = self.scans.get(scan_id)
            if not scan or scan["user_id"] != user_id:
                return None
            return scan["progress"]

    def cancel_scan(self, scan_id: str, user_id: str) -> bool:
        """Request scan cancellation"""
        with self.lock:
            scan = self.scans.get(scan_id)
            if not scan or scan["user_id"] != user_id:
                return False
            if scan["task"] and not scan["task"].done():
                scan["task"].cancel()
                return True
            return False

    def get_result(self, scan_id: str, user_id: str) -> Optional[ScanResult]:
        """Retrieve scan record and vulnerabilities from Supabase"""
        try:
            scan = supabase.fetch_scan(scan_id)
            if not scan or scan.get("user_id") != user_id:
                return None

            raw_vulns = supabase.fetch_vulnerabilities(scan_id)
            vulns = [Vulnerability(**v) for v in raw_vulns]

            return ScanResult(
                scan_id=scan_id,
                user_id=scan["user_id"],
                status=scan.get("status", "unknown"),
                target_url=scan["target_url"],
                scan_types=scan["scan_types"],
                started_at=datetime.fromisoformat(scan["started_at"]),
                completed_at=datetime.fromisoformat(scan["completed_at"]) if scan.get("completed_at") else None,
                duration=scan.get("duration"),
                progress=ScanProgress(**scan["progress"]) if scan.get("progress") else None,
                vulnerabilities=vulns,
                summary=ScanSummary(**scan["summary"]) if scan.get("summary") else ScanSummary(),
                scan_config=scan.get("scan_config", {}),
                include_low_risk=scan.get("include_low_risk", False)
            )
        except Exception as e:
            logger.error(f"Result retrieval failed: {str(e)}", exc_info=True)
            return None
            
    def calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0.0
            
        severity_weights = {
            "Critical": 10,
            "High": 7,
            "Medium": 4,
            "Low": 1,
            "Info": 0.1
        }
        
        confidence_map = {
            "High": 90,
            "Medium": 60,
            "Low": 30,
            "Confirmed": 100
        }
        
        total_score = sum(
            severity_weights.get(vuln.severity, 0) * (
                confidence_map.get(vuln.confidence, 50) / 100
            )
            for vuln in vulnerabilities
        )
        
        # Normalize to 0-10 scale
        max_possible = len(vulnerabilities) * 10
        return min(10.0, total_score / (max_possible / 10) if max_possible > 0 else 0)
        
    def subscribe(self, scan_id: str, callback: Callable):
        """Subscribe to scan updates"""
        self.subscribers[scan_id].append(callback)
        
    def unsubscribe(self, scan_id: str, callback: Callable):
        """Unsubscribe from scan updates"""
        if scan_id in self.subscribers:
            self.subscribers[scan_id] = [cb for cb in self.subscribers[scan_id] if cb != callback]
            
    def notify_subscribers(self, scan_id: str, data: dict):
        """Notify all subscribers of an update"""
        for callback in self.subscribers.get(scan_id, []):
            try:
                result = callback(data)
                if inspect.isawaitable(result):
                    try:
                        asyncio.get_running_loop().create_task(result)
                    except RuntimeError:
                        # If we're outside the main loop (e.g., background thread), run synchronously
                        asyncio.run(result)
            except Exception as e:
                logger.error(f"Subscriber notification failed: {str(e)}")
                
    def generate_report(self, scan_id: str, format: str) -> str:
        """Generate a report file in the requested format"""
        try:
            # Fetch scan data
            scan = supabase.fetch_scan(scan_id)
            if not scan:
                raise ValueError("Scan not found")
            
            # Fetch vulnerabilities
            vulns = supabase.fetch_vulnerabilities(scan_id)
            
            # Create temp file
            fd, path = tempfile.mkstemp(suffix=f".{format}")
            os.close(fd)
            
            if format == "pdf":
                self._generate_pdf_report(path, scan, vulns)
            elif format == "csv":
                self._generate_csv_report(path, vulns)
            elif format == "json":
                self._generate_json_report(path, scan, vulns)
            else:
                raise ValueError("Unsupported format")
            
            return path
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}", exc_info=True)
            raise

    def _generate_pdf_report(self, path: str, scan: dict, vulns: List[dict]):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Add title
        pdf.cell(200, 10, txt="Security Scan Report", ln=True, align="C")
        pdf.ln(10)
        
        # Scan metadata
        pdf.cell(200, 10, txt=f"Scan ID: {scan['scan_id']}", ln=True)
        pdf.cell(200, 10, txt=f"Target URL: {scan['target_url']}", ln=True)
        pdf.cell(200, 10, txt=f"Status: {scan['status']}", ln=True)
        pdf.cell(200, 10, txt=f"Started: {scan['started_at']}", ln=True)
        
        if scan.get("completed_at"):
            pdf.cell(200, 10, txt=f"Completed: {scan['completed_at']}", ln=True)
        
        pdf.ln(15)
        
        # Vulnerability summary
        pdf.cell(200, 10, txt="Vulnerability Summary", ln=True)
        pdf.ln(5)
        
        summary = scan.get("summary", {})
        pdf.cell(200, 10, txt=f"Critical: {summary.get('critical_count', 0)}", ln=True)
        pdf.cell(200, 10, txt=f"High: {summary.get('high_count', 0)}", ln=True)
        pdf.cell(200, 10, txt=f"Medium: {summary.get('medium_count', 0)}", ln=True)
        pdf.cell(200, 10, txt=f"Low: {summary.get('low_count', 0)}", ln=True)
        pdf.cell(200, 10, txt=f"Info: {summary.get('info_count', 0)}", ln=True)
        pdf.cell(200, 10, txt=f"Risk Score: {summary.get('risk_score', 0)}/10", ln=True)
        
        pdf.ln(15)
        
        # Vulnerability details
        pdf.add_page()
        pdf.cell(200, 10, txt="Vulnerability Details", ln=True)
        pdf.ln(5)
        
        for i, vuln in enumerate(vulns):
            pdf.cell(200, 10, txt=f"{i+1}. {vuln['name']} ({vuln['severity']})", ln=True)
            pdf.multi_cell(0, 10, txt=vuln['description'])
            pdf.ln(5)
        
        pdf.output(path)

    def _generate_csv_report(self, path: str, vulns: List[dict]):
        with open(path, 'w', newline='') as csvfile:
            fieldnames = ['name', 'severity', 'description', 'url', 'parameter']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in vulns:
                writer.writerow({
                    'name': vuln['name'],
                    'severity': vuln['severity'],
                    'description': vuln['description'],
                    'url': vuln.get('url', ''),
                    'parameter': vuln.get('parameter', '')
                })

    def _generate_json_report(self, path: str, scan: dict, vulns: List[dict]):
        report = {
            "scan": scan,
            "vulnerabilities": vulns
        }
        with open(path, 'w') as jsonfile:
            json.dump(report, jsonfile, indent=2)

# Instantiate orchestrator
scanner_orchestrator = OWASPOrchestrator()