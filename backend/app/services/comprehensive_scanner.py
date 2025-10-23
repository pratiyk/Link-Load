"""Comprehensive security scanner orchestrator with AI analysis."""
import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from app.core.config import settings
from app.database.supabase_client import supabase

logger = logging.getLogger(__name__)


class ComprehensiveScanner:
    """Orchestrates multiple security scanners and AI analysis."""

    def __init__(self):
        """Initialize scanner components."""
        self.scanners = {}
        self._initialize_scanners()

    def _initialize_scanners(self):
        """Initialize all available scanners."""
        try:
            # Import scanner modules and configurations
            from app.services.scanners.zap_scanner import OWASPZAPScanner, ZAPScannerConfig
            from app.services.scanners.nuclei_scanner import NucleiScanner, NucleiScannerConfig
            from app.services.scanners.wapiti_scanner import WapitiScanner, WapitiScannerConfig
            
            # Create default configurations
            zap_config = ZAPScannerConfig()
            nuclei_config = NucleiScannerConfig()
            wapiti_config = WapitiScannerConfig()
            
            self.scanners = {
                "owasp": OWASPZAPScanner(zap_config),
                "nuclei": NucleiScanner(nuclei_config),
                "wapiti": WapitiScanner(wapiti_config)
            }
            logger.info("Scanners initialized successfully")
        except Exception as e:
            logger.warning(f"Some scanners failed to initialize: {e}")

    async def start_scan(
        self,
        scan_id: str,
        target_url: str,
        scan_types: List[str],
        options: Dict[str, Any]
    ) -> None:
        """
        Execute comprehensive scan with multiple scanner types.
        
        Args:
            scan_id: Unique scan identifier
            target_url: URL to scan
            scan_types: List of scanner types to use
            options: Additional scan options
        """
        try:
            # Update scan status to in_progress
            await self._update_scan_progress(
                scan_id,
                status="in_progress",
                progress=5,
                stage="Initializing scanners"
            )

            # Run selected scanners
            all_vulnerabilities = []
            
            tasks = []
            for scanner_type in scan_types:
                if scanner_type.lower() in self.scanners:
                    tasks.append(
                        self._run_scanner(
                            scan_id,
                            scanner_type.lower(),
                            target_url,
                            options
                        )
                    )

            # Execute scanners concurrently
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Scanner error: {result}")
                        continue
                    if isinstance(result, list):
                        all_vulnerabilities.extend(result)

            # Store vulnerabilities
            if all_vulnerabilities:
                count = supabase.insert_vulnerabilities(scan_id, all_vulnerabilities)
                logger.info(f"Inserted {count} vulnerabilities for scan {scan_id}")

            # Perform AI analysis
            await self._perform_ai_analysis(scan_id, all_vulnerabilities, options)

            # Perform MITRE mapping
            await self._perform_mitre_mapping(scan_id, all_vulnerabilities)

            # Calculate risk score
            await self._calculate_risk_assessment(scan_id, all_vulnerabilities)

            # Update scan to completed
            await self._update_scan_progress(
                scan_id,
                status="completed",
                progress=100,
                stage="Completed"
            )

            logger.info(f"Scan {scan_id} completed successfully")

        except Exception as e:
            logger.error(f"Comprehensive scan failed: {e}", exc_info=True)
            await self._update_scan_progress(
                scan_id,
                status="failed",
                stage=f"Error: {str(e)}"
            )

    async def _run_scanner(
        self,
        scan_id: str,
        scanner_type: str,
        target_url: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run a specific scanner and return vulnerabilities."""
        try:
            logger.info(f"Starting {scanner_type} scanner for {target_url}")
            
            await self._update_scan_progress(
                scan_id,
                progress=20 + (list(self.scanners.keys()).index(scanner_type) * 20),
                stage=f"Running {scanner_type.upper()} scan"
            )

            scanner = self.scanners[scanner_type]
            
            # Configure scanner
            if hasattr(scanner, 'configure'):
                scanner.configure({
                    "timeout": options.get("timeout_minutes", 30) * 60,
                    "deep_scan": options.get("deep_scan", False)
                })

            # Execute scan
            vulnerabilities = await scanner.scan(target_url)
            
            logger.info(f"{scanner_type} scanner found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            logger.error(f"Error running {scanner_type} scanner: {e}")
            return []

    async def _perform_ai_analysis(
        self,
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]],
        options: Dict[str, Any]
    ) -> None:
        """Perform AI-powered analysis on vulnerabilities using LLM service."""
        if not options.get("enable_ai_analysis", True):
            return

        try:
            logger.info(f"Performing AI analysis for scan {scan_id}")
            
            await self._update_scan_progress(
                scan_id,
                progress=75,
                stage="Performing AI analysis"
            )

            # Use LLM service for comprehensive analysis
            from app.services.llm_service import llm_service
            
            # Get business context from options if provided
            business_context = options.get("business_context")
            
            # Call LLM service
            llm_result = await llm_service.analyze_vulnerabilities(
                vulnerabilities=vulnerabilities,
                target_url=options.get("target_url", "unknown"),
                business_context=business_context
            )
            
            # Extract recommendations from LLM response
            ai_analysis = llm_result.get("vulnerabilities", [])
            
            # If no LLM result, fall back to basic analysis
            if not ai_analysis:
                ai_analysis = []
                for vuln in vulnerabilities[:5]:  # Top 5 vulnerabilities
                    analysis = {
                        "title": f"Analysis of {vuln.get('title', 'Unknown')}",
                        "description": f"This is a {vuln.get('severity', 'unknown')} severity vulnerability",
                        "recommendations": [
                            "Implement input validation",
                            "Use parameterized queries",
                            "Apply security patches"
                        ],
                        "remediation_priority": "high" if vuln.get("severity") in ["critical", "high"] else "medium"
                    }
                    ai_analysis.append(analysis)

            # Update scan with AI analysis
            supabase.update_scan(scan_id, {"ai_analysis": ai_analysis})
            logger.info(f"AI analysis completed for scan {scan_id} with {len(ai_analysis)} insights")

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")

    async def _perform_mitre_mapping(
        self,
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> None:
        """Map vulnerabilities to MITRE ATT&CK techniques."""
        try:
            logger.info(f"Performing MITRE mapping for scan {scan_id}")
            
            await self._update_scan_progress(
                scan_id,
                progress=80,
                stage="Mapping to MITRE ATT&CK"
            )

            # Simple MITRE mapping (in production, use ML model)
            mitre_mapping = []
            
            for vuln in vulnerabilities:
                # Map vulnerability types to MITRE techniques
                vuln_type = vuln.get("title", "").lower()
                
                if "sql injection" in vuln_type:
                    technique = {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
                elif "xss" in vuln_type or "cross-site scripting" in vuln_type:
                    technique = {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}
                elif "authentication" in vuln_type:
                    technique = {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
                else:
                    continue
                
                mitre_mapping.append(technique)

            # Remove duplicates
            seen = set()
            unique_mapping = []
            for t in mitre_mapping:
                if t["id"] not in seen:
                    seen.add(t["id"])
                    unique_mapping.append(t)

            supabase.update_scan(scan_id, {"mitre_mapping": unique_mapping})
            logger.info(f"MITRE mapping completed for scan {scan_id}")

        except Exception as e:
            logger.error(f"MITRE mapping failed: {e}")

    async def _calculate_risk_assessment(
        self,
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> None:
        """Calculate risk score and assessment."""
        try:
            logger.info(f"Calculating risk assessment for scan {scan_id}")
            
            await self._update_scan_progress(
                scan_id,
                progress=90,
                stage="Calculating risk score"
            )

            # Calculate vulnerability counts
            critical_count = len([v for v in vulnerabilities if v.get("severity") == "critical"])
            high_count = len([v for v in vulnerabilities if v.get("severity") == "high"])
            medium_count = len([v for v in vulnerabilities if v.get("severity") == "medium"])
            low_count = len([v for v in vulnerabilities if v.get("severity") == "low"])

            # Calculate risk score (0-10 scale)
            # This is a simplified model; use ML in production
            risk_score = min(
                10.0,
                (critical_count * 2.0) + (high_count * 1.5) + (medium_count * 0.8) + (low_count * 0.2)
            )

            # Determine risk level
            if risk_score >= 8:
                risk_level = "Critical"
            elif risk_score >= 6:
                risk_level = "High"
            elif risk_score >= 4:
                risk_level = "Medium"
            elif risk_score >= 2:
                risk_level = "Low"
            else:
                risk_level = "Minimal"

            # Update scan with risk assessment
            supabase.update_scan(
                scan_id,
                {
                    "risk_score": round(risk_score, 2),
                    "risk_level": risk_level,
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "medium_count": medium_count,
                    "low_count": low_count
                }
            )

            logger.info(f"Risk assessment calculated: Score={risk_score}, Level={risk_level}")

        except Exception as e:
            logger.error(f"Risk assessment calculation failed: {e}")

    async def _update_scan_progress(
        self,
        scan_id: str,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        stage: Optional[str] = None
    ) -> None:
        """Update scan progress in database."""
        try:
            update_data = {}
            if status:
                update_data["status"] = status
            if progress is not None:
                update_data["progress"] = progress
            if stage:
                update_data["current_stage"] = stage
            if status == "completed":
                update_data["completed_at"] = datetime.utcnow().isoformat()
            
            if update_data:
                supabase.update_scan(scan_id, update_data)
        except Exception as e:
            logger.error(f"Failed to update scan progress: {e}")
