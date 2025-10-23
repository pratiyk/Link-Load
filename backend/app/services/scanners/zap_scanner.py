from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
from zapv2 import ZAPv2
import asyncio
import uuid
import json
from pydantic import BaseModel

from .base_scanner import BaseScanner, ScannerConfig, ScanResult

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

    async def initialize(self) -> bool:
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
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize OWASP ZAP scanner: {str(e)}")
            return False

    async def start_scan(self, config: ScannerConfig) -> str:
        """Start a new ZAP scan"""
        try:
            scan_id = str(uuid.uuid4())
            
            # Create context for this scan
            context_id = self.zap.context.new_context(scan_id)
            
            # Configure target
            self.zap.context.include_in_context(context_id, f"^{config.target_url}.*$")
            
            # Spider the target
            spider_scan_id = self.zap.spider.scan(
                config.target_url,
                contextname=scan_id
            )
            
            if config.ajax_spider:
                self.zap.ajaxSpider.scan(
                    config.target_url,
                    contextname=scan_id
                )
            
            # Start active scan when spider completes
            active_scan_id = self.zap.ascan.scan(
                config.target_url,
                contextid=context_id
            )
            
            self.active_scans[scan_id] = {
                'context_id': context_id,
                'spider_id': spider_scan_id,
                'scan_id': active_scan_id,
                'start_time': datetime.utcnow(),
                'config': config.dict()
            }
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start ZAP scan: {str(e)}")
            raise

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of ZAP scan"""
        try:
            if scan_id not in self.active_scans:
                return {'status': 'not_found'}
                
            scan_info = self.active_scans[scan_id]
            
            # Check spider progress
            spider_progress = self.zap.spider.status(scan_info['spider_id'])
            
            # Check active scan progress 
            scan_progress = self.zap.ascan.status(scan_info['scan_id'])
            
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
        try:
            if scan_id not in self.active_scans:
                raise ValueError(f"Scan {scan_id} not found")

            scan_info = self.active_scans[scan_id]
            
            # Get alerts
            alerts = self.zap.core.alerts()
            
            # Format vulnerabilities
            vulnerabilities = []
            for alert in alerts:
                vuln = {
                    'name': alert.get('name'),
                    'risk': alert.get('risk'),
                    'confidence': alert.get('confidence'), 
                    'url': alert.get('url'),
                    'param': alert.get('param'),
                    'evidence': alert.get('evidence'),
                    'solution': alert.get('solution'),
                    'references': alert.get('reference', '').split('\n'),
                    'cwe_id': alert.get('cweid'),
                    'wasc_id': alert.get('wascid')
                }
                vulnerabilities.append(vuln)

            return ScanResult(
                scan_id=scan_id,
                target_url=scan_info['config']['target_url'],
                start_time=scan_info['start_time'],
                end_time=datetime.utcnow(),
                status='completed',
                vulnerabilities=vulnerabilities,
                raw_findings={
                    'alerts': alerts,
                    'spider_results': self.zap.spider.results(scan_info['spider_id']),
                    'stats': self.zap.core.statistics('stats.')
                }
            )

        except Exception as e:
            logger.error(f"Error getting ZAP scan results: {str(e)}")
            raise

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running ZAP scan"""
        try:
            if scan_id not in self.active_scans:
                return False
                
            scan_info = self.active_scans[scan_id]
            
            # Stop spider and active scan
            self.zap.spider.stop(scan_info['spider_id'])
            self.zap.ascan.stop(scan_info['scan_id'])
            
            return True
            
        except Exception as e:
            logger.error(f"Error stopping ZAP scan: {str(e)}")
            return False

    async def cleanup_scan(self, scan_id: str) -> bool:
        """Clean up a completed ZAP scan"""
        try:
            if scan_id not in self.active_scans:
                return False
                
            scan_info = self.active_scans[scan_id]
            
            # Remove context
            self.zap.context.remove_context(scan_info['context_id'])
            
            # Clear alerts
            self.zap.alert.delete_all_alerts()
            
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