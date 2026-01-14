from typing import Dict, Any, List, Optional
import logging
try:
    from zapv2 import ZAPv2
except ImportError:  # pragma: no cover - optional dependency
    ZAPv2 = None
import asyncio
import uuid
import json
from pydantic import BaseModel

from .base_scanner import BaseScanner, ScannerConfig, ScanResult
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

class ZAPScannerConfig(BaseModel):
    api_key: str = ""
    host: str = "127.0.0.1"
    port: int = 8080
    path_prefix: str = ""
    debug: bool = False

class OWASPZAPScanner(BaseScanner):
    def __init__(self, config: ZAPScannerConfig):
        self.config = config
        self.zap = None
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self._initialized = False
    
    @staticmethod
    def _map_zap_risk_to_severity(risk: str) -> str:
        """Map ZAP risk levels to our severity levels.
        
        ZAP uses: High, Medium, Low, Informational
        We use: critical, high, medium, low, info
        """
        mapping = {
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Informational': 'info'
        }
        return mapping.get(risk, 'info')
    
    @staticmethod
    def _calculate_cvss_from_risk(risk: str, confidence: str) -> float:
        """Estimate CVSS score from ZAP risk and confidence levels.
        
        Args:
            risk: ZAP risk level (High, Medium, Low, Informational)
            confidence: ZAP confidence level (High, Medium, Low)
            
        Returns:
            Estimated CVSS score (0.0-10.0)
        """
        base_scores = {
            'High': 8.5,
            'Medium': 5.5,
            'Low': 3.0,
            'Informational': 0.5
        }
        
        confidence_multipliers = {
            'High': 1.0,
            'Medium': 0.85,
            'Low': 0.7
        }
        
        base = base_scores.get(risk, 0.5)
        multiplier = confidence_multipliers.get(confidence, 0.7)
        
        return round(base * multiplier, 1)

    async def initialize(self) -> bool:
        if ZAPv2 is None:
            logger.warning("OWASP ZAP client library not installed; skipping initialization")
            self._initialized = False
            return False
        try:
            # Initialize ZAP API client
            self.zap = ZAPv2(
                apikey=self.config.api_key,
                proxies={
                    'http': f'http://{self.config.host}:{self.config.port}',
                    'https': f'http://{self.config.host}:{self.config.port}'
                }
            )
            
            # Test connection
            version = self.zap.core.version
            logger.info(f"Successfully connected to OWASP ZAP {version}")
            self._initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize OWASP ZAP scanner: {str(e)}")
            self.zap = None
            self._initialized = False
            return False

    async def _ensure_client(self) -> None:
        """Ensure the ZAP API client is ready before using it."""
        if ZAPv2 is None:
            raise RuntimeError("OWASP ZAP client library not installed")
        if self.zap is None or not self._initialized:
            initialized = await self.initialize()
            if not initialized or self.zap is None:
                raise RuntimeError("OWASP ZAP client not available")

    def _fetch_stats(self, zap_client: Any) -> Dict[str, Any]:
        """Safely fetch statistics from the ZAP core API."""
        try:
            statistics_call = getattr(zap_client.core, 'statistics', None)
            if callable(statistics_call):
                stats_result = statistics_call('stats.')
                if isinstance(stats_result, dict):
                    return stats_result
                return {'data': stats_result}
        except Exception:
            logger.debug("Failed to fetch ZAP statistics", exc_info=True)
        return {}

    def _normalize_progress(self, value: Any) -> int:
        """Convert ZAP progress responses (strings/ints) into an int percentage."""
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            try:
                return int(float(value.strip()))
            except ValueError:
                pass
        return 0

    async def start_scan(self, config: ScannerConfig) -> str:
        """Start a new ZAP scan"""
        await self._ensure_client()
        if self.zap is None:
            raise RuntimeError("OWASP ZAP client not available")
        zap_client = self.zap
        try:
            scan_id = str(uuid.uuid4())
            
            # Create context for this scan
            context_id = zap_client.context.new_context(scan_id)
            
            # Configure target
            zap_client.context.include_in_context(context_id, f"^{config.target_url}.*$")
            
            # Check for deep scan mode
            deep_scan = getattr(config, 'deep_scan', False)
            use_ajax_spider = config.ajax_spider or deep_scan
            
            logger.info(f"[ZAP] Starting scan for {config.target_url} (deep_scan={deep_scan}, ajax_spider={use_ajax_spider})")
            
            # Configure scan duration limit from config (default 4 hours for thorough scanning)
            max_duration_mins = max(1, config.max_scan_duration // 60) if config.max_scan_duration else 240
            try:
                zap_client.ascan.set_option_max_scan_duration_in_mins(max_duration_mins)
                logger.info(f"[ZAP] Thorough scan mode: max duration set to {max_duration_mins} minutes")
            except Exception as e:
                logger.debug(f"[ZAP] Could not set max scan duration: {e}")
            
            # Spider the target
            spider_scan_id = zap_client.spider.scan(
                config.target_url,
                contextname=scan_id
            )
            
            # For deep scans, always use AJAX spider for JavaScript-heavy sites
            if use_ajax_spider:
                logger.info(f"[ZAP] Starting AJAX spider for JavaScript content")
                zap_client.ajaxSpider.scan(
                    config.target_url,
                    contextname=scan_id
                )
            
            # Configure scan policy based on depth
            if deep_scan:
                # Deep scan: enable all scan policies for thorough testing
                try:
                    zap_client.ascan.set_option_max_depth(10)
                    logger.info(f"[ZAP] Deep scan: max depth 10")
                except Exception as e:
                    logger.debug(f"[ZAP] Could not set advanced options: {e}")
            
            # Start active scan when spider completes
            active_scan_id = zap_client.ascan.scan(
                config.target_url,
                contextid=context_id
            )
            
            self.active_scans[scan_id] = {
                'context_id': context_id,
                'spider_id': spider_scan_id,
                'scan_id': active_scan_id,
                'start_time': utc_now(),
                'config': config.dict(),
                'deep_scan': deep_scan
            }
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start ZAP scan: {str(e)}")
            raise

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of ZAP scan"""
        try:
            await self._ensure_client()
        except RuntimeError:
            return {'status': 'unavailable'}
        if self.zap is None:
            return {'status': 'unavailable'}
        zap_client = self.zap
        try:
            if scan_id not in self.active_scans:
                return {'status': 'not_found'}
                
            scan_info = self.active_scans[scan_id]
            
            # Check spider progress
            spider_progress_raw = zap_client.spider.status(scan_info['spider_id'])
            spider_progress = self._normalize_progress(spider_progress_raw)
            
            # Check active scan progress 
            scan_progress_raw = zap_client.ascan.status(scan_info['scan_id'])
            scan_progress = self._normalize_progress(scan_progress_raw)
            
            return {
                'status': 'running' if scan_progress < 100 else 'completed',
                'spider_progress': spider_progress,
                'scan_progress': scan_progress,
                'start_time': scan_info['start_time'].isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting ZAP scan status: {str(e)}")
            return {'status': 'error', 'message': str(e)}

    async def get_scan_results(self, scan_id: str) -> ScanResult:
        """Get results from a ZAP scan"""
        await self._ensure_client()
        if self.zap is None:
            raise RuntimeError("OWASP ZAP client not available")
        zap_client = self.zap
        try:
            if scan_id not in self.active_scans:
                raise ValueError(f"Scan {scan_id} not found")

            scan_info = self.active_scans[scan_id]
            
            # Get alerts
            alerts = zap_client.core.alerts()
            
            # Format vulnerabilities with proper severity mapping
            vulnerabilities = []
            for alert in alerts:
                risk = alert.get('risk', 'Informational')
                confidence = alert.get('confidence', 'Medium')
                
                vuln = {
                    'name': alert.get('name'),
                    'title': alert.get('name'),
                    'description': alert.get('description', ''),
                    'risk': risk,  # Keep original ZAP risk level
                    'severity': self._map_zap_risk_to_severity(risk),  # Map to our severity levels
                    'cvss_score': self._calculate_cvss_from_risk(risk, confidence),  # Calculate CVSS
                    'confidence': confidence,
                    'url': alert.get('url'),
                    'location': alert.get('url'),
                    'param': alert.get('param'),
                    'parameter': alert.get('param'),
                    'evidence': alert.get('evidence'),
                    'solution': alert.get('solution'),
                    'recommendation': alert.get('solution'),
                    'references': alert.get('reference', '').split('\n') if alert.get('reference') else [],
                    'cwe_id': alert.get('cweid'),
                    'wasc_id': alert.get('wascid'),
                    'scanner_source': 'zap'
                }
                vulnerabilities.append(vuln)

            return ScanResult(
                scan_id=scan_id,
                target_url=scan_info['config']['target_url'],
                start_time=scan_info['start_time'],
                end_time=utc_now(),
                status='completed',
                vulnerabilities=vulnerabilities,
                raw_findings={
                    'alerts': alerts,
                    'spider_results': zap_client.spider.results(scan_info['spider_id']),
                    'stats': self._fetch_stats(zap_client)
                }
            )

        except Exception as e:
            logger.error(f"Error getting ZAP scan results: {str(e)}")
            raise

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running ZAP scan"""
        try:
            await self._ensure_client()
        except RuntimeError:
            return False
        if self.zap is None:
            return False
        zap_client = self.zap
        try:
            if scan_id not in self.active_scans:
                return False
                
            scan_info = self.active_scans[scan_id]
            
            # Stop spider and active scan
            zap_client.spider.stop(scan_info['spider_id'])
            zap_client.ascan.stop(scan_info['scan_id'])
            
            return True
            
        except Exception as e:
            logger.error(f"Error stopping ZAP scan: {str(e)}")
            return False

    async def cleanup_scan(self, scan_id: str) -> bool:
        """Clean up a completed ZAP scan"""
        try:
            await self._ensure_client()
        except RuntimeError:
            return False
        if self.zap is None:
            return False
        zap_client = self.zap
        try:
            if scan_id not in self.active_scans:
                return False
                
            scan_info = self.active_scans[scan_id]
            
            # Remove context
            zap_client.context.remove_context(scan_info['context_id'])
            
            # Clear alerts
            zap_client.alert.delete_all_alerts()
            
            # Remove from active scans
            del self.active_scans[scan_id]
            
            return True
            
        except Exception as e:
            logger.error(f"Error cleaning up ZAP scan: {str(e)}")
            return False

    async def shutdown(self) -> bool:
        """Shutdown ZAP scanner"""
        try:
            if self.zap:
                # Stop all active scans
                for scan_id in list(self.active_scans.keys()):
                    await self.stop_scan(scan_id)
                    await self.cleanup_scan(scan_id)
                
                # Additional cleanup if needed
                self.zap = None
                
            return True
            
        except Exception as e:
            logger.error(f"Error shutting down ZAP scanner: {str(e)}")
            return False


class ZAPScanner(OWASPZAPScanner):
    """Backward compatible wrapper that applies default configuration."""

    def __init__(self, config: Optional[ZAPScannerConfig] = None):
        super().__init__(config or ZAPScannerConfig())