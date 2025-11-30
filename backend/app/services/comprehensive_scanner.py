"""Comprehensive security scanner orchestrator with AI analysis."""
import asyncio
import logging
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from app.core.config import settings
from app.database.supabase_client import supabase

logger = logging.getLogger(__name__)

_DEFAULT_CVSS_BY_SEVERITY = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.1,
}


class ComprehensiveScanner:
    """Orchestrates multiple security scanners and AI analysis."""

    def __init__(self):
        """Initialize scanner components."""
        self.scanners = {}
        self._last_debug: Dict[str, Any] = {}
        self._initialize_scanners()

    def _initialize_scanners(self):
        """Initialize all available scanners."""
        available_scanners = {}
        
        # Try to initialize OWASP ZAP
        try:
            from app.services.scanners.zap_scanner import OWASPZAPScanner, ZAPScannerConfig
            
            zap_config = ZAPScannerConfig(
                api_key=settings.ZAP_API_KEY or "",
                host=settings.ZAP_BASE_URL.split("://")[1].split(":")[0] if settings.ZAP_BASE_URL else "127.0.0.1",
                port=int(settings.ZAP_BASE_URL.split(":")[-1]) if settings.ZAP_BASE_URL else 8080
            )
            
            zap_scanner = OWASPZAPScanner(zap_config)
            # ZAP initialization will be done lazily on first scan
            # For now, just check if ZAP library is available
            try:
                from zapv2 import ZAPv2
                if ZAPv2 is not None:
                    available_scanners["owasp"] = zap_scanner
                    logger.info("[OK] OWASP ZAP scanner configured (will connect on first scan)")
                else:
                    logger.warning("[WARN] OWASP ZAP library not available")
            except ImportError:
                logger.warning("[WARN] OWASP ZAP library not installed")
        except Exception as e:
            logger.warning(f"[WARN] OWASP ZAP scanner configuration failed: {e}")
        
        # Try to initialize Nuclei
        try:
            import os
            import sys
            
            def _repo_root() -> str:
                here = os.path.abspath(os.path.dirname(__file__))
                return os.path.abspath(os.path.join(here, "..", "..", ".."))

            def _resolve_binary(default_value: str, tool_folder: str, binary_name: str) -> str:
                # 1) Absolute path that exists
                if default_value and os.path.isabs(default_value) and os.path.exists(default_value):
                    return default_value
                # 2) Check repo tools folder
                repo = _repo_root()
                candidate = os.path.join(repo, tool_folder, binary_name)
                if sys.platform.startswith("win") and not os.path.exists(candidate):
                    candidate_exe = candidate + ".exe"
                    if os.path.exists(candidate_exe):
                        return candidate_exe
                if os.path.exists(candidate):
                    return candidate
                # 3) Fallback to value (PATH)
                return default_value
            
            from app.services.scanners.nuclei_scanner import NucleiScanner, NucleiScannerConfig
            
            templates_dir = getattr(settings, "NUCLEI_TEMPLATES_PATH", "") or ""
            if templates_dir and not os.path.exists(templates_dir):
                templates_dir = ""

            nuclei_binary = _resolve_binary(settings.NUCLEI_BINARY_PATH or "nuclei", os.path.join("tools", "nuclei"), "nuclei")
            nuclei_config = NucleiScannerConfig(
                binary_path=nuclei_binary,
                templates_dir=templates_dir
            )
            
            nuclei_scanner = NucleiScanner(nuclei_config)
            # Test if Nuclei binary is available
            import subprocess
            try:
                result = subprocess.run(
                    [nuclei_binary, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    available_scanners["nuclei"] = nuclei_scanner
                    logger.info("[OK] Nuclei scanner initialized")
                else:
                    logger.warning(f"[WARN] Nuclei binary found but not working: {result.stderr}")
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                logger.warning(f"[WARN] Nuclei binary not found or not executable: {e}")
        except Exception as e:
            logger.warning(f"[WARN] Nuclei scanner not available: {e}")
        
        # Try to initialize Wapiti
        try:
            import os
            import sys
            from app.services.scanners.wapiti_scanner import WapitiScanner, WapitiScannerConfig
            
            wapiti_binary = settings.WAPITI_BINARY_PATH
            if not wapiti_binary or not os.path.exists(wapiti_binary):
                # Try virtual environment Scripts folder
                venv_wapiti = os.path.join(sys.prefix, "Scripts", "wapiti.exe" if sys.platform.startswith("win") else "wapiti")
                if os.path.exists(venv_wapiti):
                    wapiti_binary = venv_wapiti
                else:
                    wapiti_binary = "wapiti"  # Try PATH
            
            wapiti_config = WapitiScannerConfig(
                binary_path=wapiti_binary
            )
            
            wapiti_scanner = WapitiScanner(wapiti_config)
            # Test if Wapiti is available
            try:
                # Check if wapitiCore module is importable (library-based)
                import wapitiCore
                available_scanners["wapiti"] = wapiti_scanner
                logger.info("[OK] Wapiti scanner initialized")
            except ImportError:
                # Try binary approach
                import subprocess
                try:
                    result = subprocess.run(
                        [wapiti_binary, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        available_scanners["wapiti"] = wapiti_scanner
                        logger.info("[OK] Wapiti scanner initialized (binary)")
                    else:
                        logger.warning(f"[WARN] Wapiti binary found but not working")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    logger.warning("[WARN] Wapiti not available (neither library nor binary)")
        except Exception as e:
            logger.warning(f"[WARN] Wapiti scanner not available: {e}")
        
        self.scanners = available_scanners
        
        if not self.scanners:
            logger.warning("[WARN] No scanners available! Install at least one: ZAP, Nuclei, or Wapiti")
        else:
            logger.info(f"[OK] Initialized {len(self.scanners)} scanner(s): {', '.join(self.scanners.keys())}")

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
            task_scanners: List[str] = []
            scanner_counts: Dict[str, int] = {}
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
                    task_scanners.append(scanner_type.lower())

            # Execute scanners concurrently
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)

                result_types: Dict[str, str] = {}
                for scanner_name, result in zip(task_scanners, results):
                    if isinstance(result, Exception):
                        logger.error(f"Scanner {scanner_name} raised error: {result}")
                        continue
                    if isinstance(result, list):
                        logger.info(
                            "Scanner %s produced %d findings before normalization",
                            scanner_name,
                            len(result)
                        )
                        all_vulnerabilities.extend(result)
                        scanner_counts[scanner_name] = len(result)
                    else:
                        logger.warning(
                            "Scanner %s returned unexpected payload type %s",
                            scanner_name,
                            type(result)
                        )
                        result_types[scanner_name] = type(result).__name__

            logger.info(
                "Scan %s aggregated %d raw findings across scanners: %s",
                scan_id,
                len(all_vulnerabilities),
                scanner_counts
            )

            # Normalize vulnerability data for consistent field names
            normalized_vulns: List[Dict[str, Any]] = []
            severity_tally: Dict[str, int] = {}
            for vuln in all_vulnerabilities:
                severity = (vuln.get("severity") or "medium").lower()
                severity_tally[severity] = severity_tally.get(severity, 0) + 1

                cvss_score = vuln.get("cvss_score")
                if cvss_score is None:
                    cvss_score = _DEFAULT_CVSS_BY_SEVERITY.get(severity, 0.0)
                else:
                    try:
                        cvss_score = float(cvss_score)
                    except (TypeError, ValueError):
                        cvss_score = _DEFAULT_CVSS_BY_SEVERITY.get(severity, 0.0)

                references = vuln.get("references") or []
                if isinstance(references, dict):
                    references = list(references.values())

                tags = vuln.get("tags") or []
                if isinstance(tags, dict):
                    tags = list(tags.values())

                discovered_at = vuln.get("discovered_at")
                if isinstance(discovered_at, str):
                    try:
                        discovered_at = datetime.fromisoformat(discovered_at)
                    except ValueError:
                        discovered_at = None

                normalized = {
                    "vuln_id": vuln.get("vuln_id") or vuln.get("id") or str(uuid.uuid4()),
                    "title": vuln.get("title") or vuln.get("name") or "Unknown",
                    "name": vuln.get("name") or vuln.get("title") or "Unknown",
                    "description": vuln.get("description") or "",
                    "severity": severity,
                    "confidence": vuln.get("confidence") or "medium",
                    "cvss_score": cvss_score,
                    "url": vuln.get("url") or "",
                    "path": vuln.get("path") or vuln.get("url") or "",
                    "location": vuln.get("location") or vuln.get("url") or vuln.get("path") or "",
                    "parameter": vuln.get("parameter") or "",
                    "evidence": vuln.get("evidence") or "",
                    "solution": vuln.get("solution") or vuln.get("recommendation") or "",
                    "recommendation": vuln.get("recommendation") or vuln.get("solution") or "",
                    "references": references,
                    "tags": tags,
                    "cwe_id": vuln.get("cwe_id"),
                    "mitre_techniques": vuln.get("mitre_techniques") or [],
                    "scanner_source": vuln.get("scanner_source") or vuln.get("source") or "unknown",
                    "scanner_id": vuln.get("scanner_id") or vuln.get("id") or vuln.get("vuln_id"),
                    "discovered_at": discovered_at or datetime.now(timezone.utc),
                    "raw_finding": vuln.get("raw_finding")
                }
                normalized_vulns.append(normalized)

            logger.info(
                "Normalization for scan %s produced %d findings (severity breakdown: %s)",
                scan_id,
                len(normalized_vulns),
                severity_tally
            )

            # Store vulnerabilities
            if normalized_vulns:
                cached_records = supabase.cache_vulnerabilities(scan_id, normalized_vulns)
                logger.info(
                    "Cached %d normalized findings for scan %s before DB insert",
                    len(cached_records),
                    scan_id
                )
                count = supabase.insert_vulnerabilities(scan_id, normalized_vulns)
                logger.info(f"Inserted {count} vulnerabilities for scan {scan_id}")
            # Capture last run diagnostics for in-process inspection
            self._last_debug = {
                "scanner_counts": dict(scanner_counts),
                "normalized_count": len(normalized_vulns),
                "result_types": result_types,
            }
            # Persist per-scan diagnostics with counts for troubleshooting
            try:
                scan_record = supabase.fetch_scan(scan_id) or {}
                debug_map = dict(scan_record.get("scanner_debug") or {})
                summary = debug_map.get("__summary", {})
                summary.update({
                    "normalized_count": len(normalized_vulns),
                    "scanner_counts": scanner_counts
                })
                debug_map["__summary"] = summary
                supabase.update_scan(scan_id, {"scanner_debug": debug_map})
            except Exception:
                logger.debug("Failed to persist scanner summary", exc_info=True)

            # Perform AI analysis
            await self._perform_ai_analysis(scan_id, normalized_vulns, options)

            # Perform MITRE mapping
            await self._perform_mitre_mapping(scan_id, normalized_vulns)

            # Calculate risk score
            await self._calculate_risk_assessment(scan_id, normalized_vulns)

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
            
            # Configure scanner options based on scan mode
            from app.services.scanners.base_scanner import ScannerConfig
            
            deep_scan = options.get("deep_scan", False)
            include_low_risk = options.get("include_low_risk", True)
            timeout_minutes = options.get("timeout_minutes", 30)
            
            scanner_config = ScannerConfig(
                target_url=target_url,
                scan_types=[scanner_type],
                include_passive=True,
                deep_scan=deep_scan,
                include_low_risk=include_low_risk,
                ajax_spider=deep_scan,  # Enable AJAX spider for deep scans
                max_scan_duration=timeout_minutes * 60
            )
            
            logger.info(
                f"Scanner config for {scanner_type}: deep_scan={deep_scan}, "
                f"include_low_risk={include_low_risk}, timeout={timeout_minutes}min"
            )

            # Execute scan
            scan_task_id = await scanner.start_scan(scanner_config)
            logger.info(f"{scanner_type} scan started with task ID: {scan_task_id}")
            
            # Wait for scan to complete (poll status)
            max_wait = timeout_minutes * 60
            wait_interval = 10 if deep_scan else 5  # Longer intervals for deep scans
            elapsed = 0
            timed_out = True
            
            while elapsed < max_wait:
                status = await scanner.get_scan_status(scan_task_id)
                scan_status = status.get('status')
                
                if scan_status == 'completed':
                    timed_out = False
                    break
                elif scan_status in ['failed', 'error', 'not_found']:
                    logger.error(f"{scanner_type} scan failed: {status}")
                    return []
                
                await asyncio.sleep(wait_interval)
                elapsed += wait_interval
            
            if timed_out:
                logger.error(
                    "%s scan exceeded max wait of %s seconds; stopping task",
                    scanner_type,
                    max_wait
                )
                try:
                    await scanner.stop_scan(scan_task_id)
                    await scanner.cleanup_scan(scan_task_id)
                except Exception:
                    logger.debug("Failed to stop timed out %s scan", scanner_type, exc_info=True)
                await self._update_scan_progress(
                    scan_id,
                    stage=f"{scanner_type.upper()} scan timed out",
                    progress=60
                )
                return []
            
            # Get scan results
            try:
                results_timeout = max(30, min(max_wait or 120, 300))
                result = await asyncio.wait_for(
                    scanner.get_scan_results(scan_task_id),
                    timeout=results_timeout
                )
            except asyncio.TimeoutError:
                logger.error("%s scan results retrieval timed out", scanner_type)
                try:
                    await scanner.stop_scan(scan_task_id)
                except Exception:
                    logger.debug("Failed to stop %s after results timeout", scanner_type, exc_info=True)
                return []
            vulnerabilities = result.vulnerabilities if result and hasattr(result, 'vulnerabilities') else []
            enriched_vulnerabilities: List[Dict[str, Any]] = []
            for vuln in vulnerabilities or []:
                if isinstance(vuln, dict):
                    enriched = dict(vuln)
                    enriched.setdefault("scanner_source", scanner_type)
                    enriched_vulnerabilities.append(enriched)
                else:
                    enriched_vulnerabilities.append(vuln)
            vulnerabilities = enriched_vulnerabilities

            # Persist scanner diagnostics for troubleshooting
            try:
                scan_record = supabase.fetch_scan(scan_id) or {}
                debug_map = dict(scan_record.get("scanner_debug") or {})
                debug_map[scanner_type] = getattr(result, 'raw_findings', {})
                supabase.update_scan(scan_id, {"scanner_debug": debug_map})
            except Exception as _:
                pass
            
            logger.info(f"{scanner_type} scanner found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            logger.error(f"Error running {scanner_type} scanner: {e}")
            # Persist error details for troubleshooting
            try:
                scan_record = supabase.fetch_scan(scan_id) or {}
                debug_map = dict(scan_record.get("scanner_debug") or {})
                debug_map[scanner_type] = {"error": str(e)}
                supabase.update_scan(scan_id, {"scanner_debug": debug_map})
            except Exception:
                pass
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
            try:
                from app.services.llm_service import llm_service
                
                # Get business context from options if provided
                business_context = options.get("business_context")
                
                try:
                    # Call LLM service with timeout to prevent hanging
                    llm_result = await asyncio.wait_for(
                        llm_service.analyze_vulnerabilities(
                            vulnerabilities=vulnerabilities,
                            target_url=options.get("target_url", "unknown"),
                            business_context=business_context
                        ),
                        timeout=30.0  # 30 second timeout
                    )
                    
                    # Extract recommendations from LLM response
                    ai_analysis = llm_result.get("vulnerabilities", [])
                except asyncio.TimeoutError:
                    logger.warning(f"LLM analysis timeout for scan {scan_id}, using fallback")
                    ai_analysis = []
                except Exception as llm_err:
                    logger.warning(f"LLM service error: {llm_err}, using fallback")
                    ai_analysis = []
            except ImportError:
                logger.debug("LLM service not available, using fallback")
                ai_analysis = []
            
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
            # Continue anyway - don't fail the entire scan

    async def _perform_mitre_mapping(
        self,
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> None:
        """Map vulnerabilities to MITRE ATT&CK techniques using advanced ML ensemble."""
        try:
            logger.info(f"Performing MITRE mapping for scan {scan_id}")
            
            await self._update_scan_progress(
                scan_id,
                progress=80,
                stage="Mapping to MITRE ATT&CK"
            )

            # Use advanced MITRE mapper if available
            try:
                from sqlalchemy.orm import Session
                from app.database import SessionLocal
                from app.services.intelligence_mapping.mitre_mapper import MITREMapper
                
                db: Session = SessionLocal()
                mitre_mapper = MITREMapper(db)
                
                all_techniques = []
                all_ttps = []
                all_capec = []
                
                try:
                    # Process vulnerabilities with timeout
                    for vuln in vulnerabilities[:20]:  # Process top 20 vulnerabilities
                        description = f"{vuln.get('title', '')} {vuln.get('description', '')}"
                        cve_id = vuln.get('cve_id')
                        
                        try:
                            # Add timeout to MITRE mapping call
                            mapping_result = await asyncio.wait_for(
                                mitre_mapper.map_vulnerability(description, cve_id),
                                timeout=5.0  # 5 second timeout per vulnerability
                            )
                            
                            # Extract techniques with confidence scores
                            for tech in mapping_result.get('techniques', [])[:3]:  # Top 3 per vuln
                                technique_data = {
                                    "id": tech['technique_id'],
                                    "name": tech.get('name', 'Unknown'),
                                    "confidence": tech.get('confidence', 0.0),
                                    "method": tech.get('method', 'unknown'),
                                    "vulnerability_id": vuln.get('vulnerability_id'),
                                    "tactic": tech.get('tactic', 'Unknown')
                                }
                                all_techniques.append(technique_data)
                            
                            # Collect TTPs
                            all_ttps.extend(mapping_result.get('ttps', []))
                            
                            # Collect CAPEC patterns
                            all_capec.extend(mapping_result.get('capec_patterns', []))
                            
                        except asyncio.TimeoutError:
                            logger.debug(f"MITRE mapping timeout for {vuln.get('title')}")
                            continue
                        except Exception as ve:
                            logger.debug(f"MITRE mapping failed for vulnerability {vuln.get('title')}: {ve}")
                            continue
                finally:
                    db.close()
                
                # Remove duplicates and sort by confidence
                seen_techniques = {}
                for tech in all_techniques:
                    tech_id = tech['id']
                    if tech_id not in seen_techniques or tech['confidence'] > seen_techniques[tech_id]['confidence']:
                        seen_techniques[tech_id] = tech
                
                unique_mapping = list(seen_techniques.values())
                unique_mapping.sort(key=lambda x: x.get('confidence', 0), reverse=True)
                
                # Prepare comprehensive MITRE data
                mitre_data = {
                    "techniques": unique_mapping[:15],  # Top 15 techniques
                    "ttps": all_ttps[:10],  # Top 10 TTPs
                    "capec_patterns": all_capec[:10],  # Top 10 CAPEC patterns
                    "mapping_confidence": sum(t.get('confidence', 0) for t in unique_mapping) / len(unique_mapping) if unique_mapping else 0,
                    "total_techniques_found": len(unique_mapping),
                    "tactics_coverage": list(set([t.get('tactic', 'Unknown') for t in unique_mapping]))
                }
                
                supabase.update_scan(scan_id, {"mitre_mapping": unique_mapping})
                logger.info(f"Advanced MITRE mapping completed: {len(unique_mapping)} techniques, avg confidence: {mitre_data['mapping_confidence']:.2f}")
                
            except ImportError as ie:
                logger.warning(f"Advanced MITRE mapper not available: {ie}, falling back to basic mapping")
                # Fallback to simple mapping
                mitre_mapping = []
                
                for vuln in vulnerabilities:
                    vuln_type = vuln.get("title", "").lower()
                    
                    if "sql injection" in vuln_type:
                        technique = {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": 0.8}
                    elif "xss" in vuln_type or "cross-site scripting" in vuln_type:
                        technique = {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "confidence": 0.7}
                    elif "authentication" in vuln_type:
                        technique = {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "confidence": 0.75}
                    elif "command injection" in vuln_type:
                        technique = {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "confidence": 0.85}
                    elif "file upload" in vuln_type:
                        technique = {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "confidence": 0.7}
                    elif "path traversal" in vuln_type or "directory traversal" in vuln_type:
                        technique = {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "confidence": 0.75}
                    elif "ssrf" in vuln_type:
                        technique = {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Collection", "confidence": 0.7}
                    elif "xxe" in vuln_type:
                        technique = {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution", "confidence": 0.75}
                    elif "deserialization" in vuln_type:
                        technique = {"id": "T1204", "name": "User Execution", "tactic": "Execution", "confidence": 0.8}
                    elif "csrf" in vuln_type:
                        technique = {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access", "confidence": 0.7}
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
                logger.info(f"Basic MITRE mapping completed for scan {scan_id}: {len(unique_mapping)} techniques")

        except Exception as e:
            logger.error(f"MITRE mapping failed: {e}")
            import traceback
            traceback.print_exc()

    async def _calculate_risk_assessment(
        self,
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> None:
        """Calculate comprehensive risk score and assessment with business context."""
        try:
            logger.info(f"Calculating risk assessment for scan {scan_id}")
            
            await self._update_scan_progress(
                scan_id,
                progress=90,
                stage="Calculating risk score"
            )

            # Calculate vulnerability counts (case-insensitive)
            critical_count = len([v for v in vulnerabilities if (v.get("severity") or "").lower() == "critical"])
            high_count = len([v for v in vulnerabilities if (v.get("severity") or "").lower() == "high"])
            medium_count = len([v for v in vulnerabilities if (v.get("severity") or "").lower() == "medium"])
            low_count = len([v for v in vulnerabilities if (v.get("severity") or "").lower() == "low"])
            info_count = len([v for v in vulnerabilities if (v.get("severity") or "").lower() == "info"])

            # Try to use enhanced risk analyzer
            try:
                from app.services.intelligence.enhanced_risk_analyzer import EnhancedRiskAnalyzer, IndustryType
                
                risk_analyzer = EnhancedRiskAnalyzer()
                
                # Get scan record for business context
                scan_record = supabase.client.table('owasp_scans').select('*').eq('scan_id', scan_id).execute()
                scan_data = scan_record.data[0] if scan_record.data else {}
                target_url = scan_data.get('target_url', '') if scan_data else ''
                
                # Build business context (can be enhanced with user input)
                business_context = {
                    'asset_criticality': 'high' if critical_count > 0 else 'medium',
                    'sensitive_data': any('data' in v.get('title', '').lower() or 'password' in v.get('title', '').lower() for v in vulnerabilities),
                    'customer_facing': 'api' in target_url or 'www' in target_url,
                    'revenue_impact': critical_count > 0 or high_count > 2,
                    'compliance_required': True,
                    'compliance_frameworks': ['owasp_top_10', 'pci_dss'] if any('payment' in v.get('title', '').lower() for v in vulnerabilities) else ['owasp_top_10'],
                    'industry': IndustryType.TECHNOLOGY.value,
                    'data_classification': 'confidential' if critical_count > 0 else 'internal',
                    'public_facing': True,
                    'estimated_breach_cost': 100000
                }
                
                # Get MITRE mapping for context
                mitre_techniques = scan_data.get('mitre_mapping', []) if scan_data else []
                
                # Analyze highest risk vulnerability
                if vulnerabilities:
                    highest_risk_vuln = max(vulnerabilities, key=lambda v: v.get('cvss_score', 0) or 0)
                    
                    comprehensive_risk = await risk_analyzer.analyze_comprehensive_risk(
                        vulnerability=highest_risk_vuln,
                        business_context=business_context,
                        mitre_techniques=mitre_techniques if isinstance(mitre_techniques, list) else [],
                        threat_intel=None  # Can be enhanced with real-time threat intel
                    )
                    
                    risk_score = comprehensive_risk['risk_score']
                    risk_level = comprehensive_risk['risk_level'].title()
                    
                    # Store comprehensive risk analysis
                    remediation_strategies = {
                        'priority_matrix': comprehensive_risk.get('remediation_priority'),
                        'cost_benefit': comprehensive_risk.get('cost_benefit_analysis'),
                        'recommendations': comprehensive_risk.get('recommendations'),
                        'resource_allocation': comprehensive_risk.get('resource_allocation'),
                        'timeline': comprehensive_risk.get('timeline')
                    }
                    
                    supabase.update_scan(scan_id, {
                        "remediation_strategies": remediation_strategies
                    })
                    
                    logger.info(f"Enhanced risk assessment: Score={risk_score}, Priority={comprehensive_risk['remediation_priority']['priority']}")
                
                else:
                    # No vulnerabilities found
                    risk_score = 0.0
                    risk_level = "Minimal"
                    
            except Exception as e:
                logger.warning(f"Enhanced risk analyzer failed: {e}, using basic calculation")
                # Fallback to basic calculation based on severity counts
                risk_score = min(
                    10.0,
                    (critical_count * 2.0) + (high_count * 1.5) + (medium_count * 0.8) + (low_count * 0.2)
                )
                
                # If we have vulnerabilities but score is still 0, calculate from CVSS
                if risk_score == 0 and vulnerabilities:
                    # Use average CVSS score of all vulnerabilities
                    cvss_scores = [v.get('cvss_score', 0) or 0 for v in vulnerabilities]
                    if cvss_scores:
                        avg_cvss = sum(cvss_scores) / len(cvss_scores)
                        # Also consider max CVSS for risk
                        max_cvss = max(cvss_scores)
                        # Weighted combination: 60% max, 40% average
                        risk_score = (0.6 * max_cvss) + (0.4 * avg_cvss)
                        logger.info(f"Calculated risk from CVSS: max={max_cvss}, avg={avg_cvss}, score={risk_score}")

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
            import traceback
            traceback.print_exc()

    async def _update_scan_progress(
        self,
        scan_id: str,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        stage: Optional[str] = None
    ) -> None:
        """Update scan progress in database and notify WebSocket subscribers."""
        try:
            update_data = {}
            if status:
                update_data["status"] = status
            if progress is not None:
                update_data["progress"] = progress
            if stage:
                update_data["current_stage"] = stage
            if status == "completed":
                update_data["completed_at"] = datetime.now(timezone.utc).isoformat()
            
            if update_data:
                supabase.update_scan(scan_id, update_data)
                
                # Notify WebSocket subscribers about progress
                try:
                    from app.services.scanner_orchestrator import scanner_orchestrator
                    
                    ws_data = {
                        "type": "progress" if status != "completed" else "result",
                        "status": {
                            "scan_id": scan_id,
                            "status": status or "in_progress",
                            "progress": progress or 0,
                            "current_stage": stage or "Processing"
                        }
                    }
                    
                    # If completed, include results in the notification
                    if status == "completed":
                        vulns = supabase.fetch_vulnerabilities(scan_id)
                        scan = supabase.fetch_scan(scan_id)
                        ws_data["results"] = {
                            "scan_id": scan_id,
                            "status": "completed",
                            "vulnerabilities": vulns,
                            "risk_score": scan.get("risk_score") if scan else None,
                            "risk_level": scan.get("risk_level") if scan else None
                        }
                    
                    scanner_orchestrator.notify_subscribers(scan_id, ws_data)
                except Exception as ws_err:
                    logger.debug(f"WebSocket notification failed (non-critical): {ws_err}")
        except Exception as e:
            logger.error(f"Failed to update scan progress: {e}")
