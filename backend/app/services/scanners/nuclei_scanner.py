from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
import asyncio
import json
import uuid
import os
from pydantic import BaseModel

from .base_scanner import BaseScanner, ScannerConfig, ScanResult

logger = logging.getLogger(__name__)

class NucleiScannerConfig(BaseModel):
    binary_path: str = "nuclei"
    templates_dir: str = ""
    rate_limit: int = 150
    bulk_size: int = 25
    timeout: int = 10
    retries: int = 1
    debug: bool = False

class NucleiScanner(BaseScanner):
    def __init__(self, config: Optional[NucleiScannerConfig] = None):
        self.config = config or NucleiScannerConfig()
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        
    async def initialize(self) -> bool:
        """Initialize Nuclei scanner"""
        try:
            # Test nuclei installation
            proc = await asyncio.create_subprocess_exec(
                self.config.binary_path,
                '-version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                logger.error(f"Nuclei not found or error: {stderr.decode()}")
                return False
                
            version = stdout.decode().strip()
            logger.info(f"Successfully initialized Nuclei {version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Nuclei scanner: {str(e)}")
            return False

    async def start_scan(self, config: ScannerConfig) -> str:
        """Start a new Nuclei scan"""
        try:
            scan_id = str(uuid.uuid4())
            
            # Prepare output directory
            output_dir = f"nuclei_results_{scan_id}"
            os.makedirs(output_dir, exist_ok=True)
            
            # Build nuclei command
            cmd = [
                self.config.binary_path,
                '-target', config.target_url,
                '-json',
                '-output', f"{output_dir}/results.json",
                '-rate-limit', str(self.config.rate_limit),
                '-bulk-size', str(self.config.bulk_size),
                '-timeout', str(self.config.timeout),
                '-retries', str(self.config.retries)
            ]
            
            # Add template directory if specified
            if self.config.templates_dir:
                cmd.extend(['-templates', self.config.templates_dir])
            
            # Start nuclei process
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            self.active_scans[scan_id] = {
                'process': proc,
                'output_dir': output_dir,
                'start_time': datetime.utcnow(),
                'config': config.dict(),
                'cmd': cmd
            }
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start Nuclei scan: {str(e)}")
            raise

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of Nuclei scan"""
        try:
            if scan_id not in self.active_scans:
                return {'status': 'not_found'}
                
            scan_info = self.active_scans[scan_id]
            proc = scan_info['process']
            
            # Check if process is still running
            if proc.returncode is None:
                return {
                    'status': 'running',
                    'start_time': scan_info['start_time'].isoformat()
                }
            elif proc.returncode == 0:
                return {'status': 'completed'}
            else:
                return {'status': 'failed'}
                
        except Exception as e:
            logger.error(f"Error getting Nuclei scan status: {str(e)}")
            return {'status': 'error', 'message': str(e)}

    async def get_scan_results(self, scan_id: str) -> ScanResult:
        """Get results from a Nuclei scan"""
        try:
            if scan_id not in self.active_scans:
                raise ValueError(f"Scan {scan_id} not found")

            scan_info = self.active_scans[scan_id]
            results_file = f"{scan_info['output_dir']}/results.json"
            
            vulnerabilities = []
            
            # Read and parse results
            if os.path.exists(results_file):
                with open(results_file) as f:
                    for line in f:
                        finding = json.loads(line)
                        vuln = {
                            'name': finding.get('templateID'),
                            'severity': finding.get('info', {}).get('severity'),
                            'confidence': 'confirmed',
                            'description': finding.get('info', {}).get('description'),
                            'url': finding.get('matched-at'),
                            'evidence': finding.get('matcher-name'),
                            'solution': finding.get('info', {}).get('remediation'),
                            'references': finding.get('info', {}).get('reference', []),
                            'tags': finding.get('info', {}).get('tags', []),
                            'cwe_id': finding.get('info', {}).get('classification', {}).get('cwe-id'),
                            'raw_finding': finding
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
                    'command': scan_info['cmd'],
                    'output_file': results_file
                }
            )

        except Exception as e:
            logger.error(f"Error getting Nuclei scan results: {str(e)}")
            raise

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running Nuclei scan"""
        try:
            if scan_id not in self.active_scans:
                return False
                
            scan_info = self.active_scans[scan_id]
            proc = scan_info['process']
            
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    proc.kill()
            
            return True
            
        except Exception as e:
            logger.error(f"Error stopping Nuclei scan: {str(e)}")
            return False

    async def cleanup_scan(self, scan_id: str) -> bool:
        """Clean up a completed Nuclei scan"""
        try:
            if scan_id not in self.active_scans:
                return False
                
            scan_info = self.active_scans[scan_id]
            
            # Remove results directory
            output_dir = scan_info['output_dir']
            if os.path.exists(output_dir):
                for file in os.listdir(output_dir):
                    os.remove(os.path.join(output_dir, file))
                os.rmdir(output_dir)
            
            # Remove from active scans
            del self.active_scans[scan_id]
            
            return True
            
        except Exception as e:
            logger.error(f"Error cleaning up Nuclei scan: {str(e)}")
            return False

    async def shutdown(self) -> bool:
        """Shutdown Nuclei scanner"""
        try:
            # Stop all active scans
            for scan_id in list(self.active_scans.keys()):
                await self.stop_scan(scan_id)
                await self.cleanup_scan(scan_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error shutting down Nuclei scanner: {str(e)}")
            return False