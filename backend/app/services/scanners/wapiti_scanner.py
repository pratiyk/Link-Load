from typing import Dict, Any, List, Optional
import logging
import asyncio
import json
import uuid
import os
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel
import xml.etree.ElementTree as ET

from .base_scanner import BaseScanner, ScannerConfig, ScanResult, Vulnerability
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

# Fix for Windows asyncio event loop policy
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

class WapitiScannerConfig(BaseModel):
    binary_path: str = "wapiti"
    max_scan_time: int = 3600  # 1 hour
    max_parameters: int = 1000
    verify_ssl: bool = True
    debug: bool = False
    # Smaller, fast, high-signal default module set; can be overridden via env WAPITI_MODULES (comma-separated)
    modules: List[str] = [
        "xss", "sql", "csrf", "ssrf", "redirect", "http_headers", "cookieflags"
    ]

class WapitiScanner(BaseScanner):
    def __init__(self, config: Optional[WapitiScannerConfig] = None):
        import os as _os
        self.config = config or WapitiScannerConfig()
        # Optional: allow overriding modules via env var without code changes
        env_modules = _os.getenv("WAPITI_MODULES")
        if env_modules:
            try:
                parsed = [m.strip() for m in env_modules.split(",") if m.strip()]
                if parsed:
                    self.config.modules = parsed
                    logger.info(f"Wapiti modules overridden via env: {self.config.modules}")
            except Exception as e:
                logger.warning(f"Failed to parse WAPITI_MODULES env var: {e}")
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.is_windows = sys.platform == 'win32'
        
    async def initialize(self) -> bool:
        """Initialize Wapiti scanner"""
        try:
            # Test wapiti installation
            if self.is_windows:
                # Use subprocess.run for Windows
                def _run_version_windows():
                    env = os.environ.copy()
                    env['PYTHONIOENCODING'] = 'utf-8'
                    env['PYTHONUTF8'] = '1'
                    env['PYTHONLEGACYWINDOWSSTDIO'] = '0'
                    return subprocess.run(
                        [self.config.binary_path, '--version'],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        env=env
                    )

                result = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    _run_version_windows
                )
                if result.returncode != 0:
                    logger.error(f"Wapiti not found or error: {result.stderr}")
                    return False
                version = result.stdout.strip()
            else:
                # Use asyncio subprocess for Linux/Mac
                env = os.environ.copy()
                env['PYTHONIOENCODING'] = env.get('PYTHONIOENCODING', 'utf-8')
                env['PYTHONUTF8'] = env.get('PYTHONUTF8', '1')
                proc = await asyncio.create_subprocess_exec(
                    self.config.binary_path,
                    '--version',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
                stdout, stderr = await proc.communicate()
                
                if proc.returncode != 0:
                    logger.error(f"Wapiti not found or error: {stderr.decode()}")
                    return False
                version = stdout.decode().strip()
            
            logger.info(f"Successfully initialized Wapiti {version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Wapiti scanner: {str(e)}")
            return False

    async def start_scan(self, config: ScannerConfig) -> str:
        """Start a new Wapiti scan"""
        try:
            scan_id = str(uuid.uuid4())
            
            # Create output directory
            output_dir = f"wapiti_results_{scan_id}"
            os.makedirs(output_dir, exist_ok=True)
            
            logger.info(f"Starting Wapiti scan {scan_id} for {config.target_url}")
            
            # Build wapiti command
            cmd = [
                self.config.binary_path,
                '-u', config.target_url,
                '--format', 'json',
                '--output', f"{output_dir}/results.json",
                '--max-scan-time', str(self.config.max_scan_time),
                '--max-parameters', str(self.config.max_parameters)
            ]
            
            # Add modules based on scan depth
            if getattr(config, 'deep_scan', False):
                # Deep scan: comprehensive module set for thorough testing
                deep_modules = [
                    "xss", "sql", "csrf", "ssrf", "redirect", "http_headers", 
                    "cookieflags", "csp", "xxe", "exec", "file", "backup",
                    "htaccess", "methods", "ssl", "crlf", "permanentxss"
                ]
                cmd.extend(['-m', ','.join(deep_modules)])
                logger.info(f"[Wapiti] Deep scan mode enabled with {len(deep_modules)} modules")
            elif self.config.modules:
                # Standard/Quick: Use configured modules
                cmd.extend(['-m', ','.join(self.config.modules)])
            
            if not self.config.verify_ssl:
                cmd.append('--no-check-certificate')
            
            logger.info(f"Wapiti command: {' '.join(cmd)}")
                
            # Start wapiti process - use different approach for Windows
            if self.is_windows:
                # Windows: Use Popen directly in thread pool
                def run_wapiti_windows():
                    try:
                        # Set environment to avoid asyncio issues on Windows
                        env = os.environ.copy()
                        env['PYTHONASYNCIODEBUG'] = '0'
                        # Force UTF-8 output so Wapiti's banner doesn't crash on cp1252 consoles
                        env['PYTHONIOENCODING'] = 'utf-8'
                        env['PYTHONUTF8'] = '1'
                        env['PYTHONLEGACYWINDOWSSTDIO'] = '0'
                        
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=os.getcwd(),
                            env=env
                        )
                        logger.info(f"Wapiti process started with PID: {proc.pid}")
                        return proc
                    except Exception as e:
                        logger.error(f"Failed to start Wapiti process: {e}")
                        raise
                
                proc = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    run_wapiti_windows
                )
            else:
                # Linux/Mac: Use asyncio subprocess
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            
            self.active_scans[scan_id] = {
                'process': proc,
                'output_dir': output_dir,
                'start_time': utc_now(),
                'config': config.dict(),
                'cmd': cmd,
                'is_windows': self.is_windows
            }
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start Wapiti scan: {str(e)}")
            raise

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of Wapiti scan"""
        try:
            if scan_id not in self.active_scans:
                logger.warning(f"Wapiti scan {scan_id} not found in active scans")
                return {'status': 'not_found'}
                
            scan_info = self.active_scans[scan_id]
            proc = scan_info['process']
            is_windows = scan_info.get('is_windows', False)
            output_dir = scan_info['output_dir']
            results_file = f"{output_dir}/results.json"
            
            # Check if process is still running
            if is_windows:
                # Windows Popen object
                return_code = proc.poll()
            else:
                # Asyncio subprocess
                return_code = proc.returncode
            
            if return_code is None:
                # Still running
                return {
                    'status': 'running',
                    'start_time': scan_info['start_time'].isoformat()
                }
            else:
                # Process has finished - check if we have results
                # Wapiti sometimes exits with non-zero even when it found vulnerabilities
                if os.path.exists(results_file) and os.path.getsize(results_file) > 0:
                    # We have output, consider it completed
                    logger.info(f"Wapiti scan {scan_id} produced results (exit code: {return_code})")
                    return {'status': 'completed'}
                elif return_code == 0:
                    # Completed successfully but no results file yet
                    logger.info(f"Wapiti scan {scan_id} completed successfully")
                    return {'status': 'completed'}
                else:
                    # Failed with error and no results
                    logger.error(f"Wapiti scan {scan_id} failed with return code: {return_code}")
                    
                    # Try to get error output
                    try:
                        if is_windows:
                            # For Windows Popen, stderr might already be consumed
                            # Try to read any remaining data
                            if proc.stderr:
                                stderr = proc.stderr.read()
                            else:
                                stderr = b''
                        else:
                            stderr = b''
                        
                        if stderr:
                            error_msg = stderr.decode('utf-8', errors='ignore')
                            logger.error(f"Wapiti stderr: {error_msg}")
                            return {'status': 'failed', 'error': error_msg}
                    except Exception as e:
                        logger.debug(f"Could not read stderr: {e}")
                    
                    return {'status': 'failed', 'return_code': return_code}
                
        except Exception as e:
            logger.error(f"Error getting Wapiti scan status: {str(e)}")
            return {'status': 'error', 'message': str(e)}

    async def get_scan_results(self, scan_id: str) -> ScanResult:
        """Get results from a Wapiti scan"""
        try:
            if scan_id not in self.active_scans:
                raise ValueError(f"Scan {scan_id} not found")

            scan_info = self.active_scans[scan_id]
            results_file = f"{scan_info['output_dir']}/results.json"
            is_windows = scan_info.get('is_windows', False)
            
            vulnerabilities = []
            stderr_tail_lines: List[str] = []
            stdout_tail_lines: List[str] = []
            return_code: Optional[int] = None
            
            # Drain process pipes to capture any errors
            proc = scan_info.get('process')
            try:
                if proc is not None:
                    # Handle Windows vs Linux process
                    if is_windows:
                        # Windows Popen - use communicate in thread pool
                        def wait_for_process():
                            stdout, stderr = proc.communicate()
                            return stdout, stderr, proc.returncode
                        
                        out, err, return_code = await asyncio.get_event_loop().run_in_executor(
                            self.executor,
                            wait_for_process
                        )
                    else:
                        # Linux/Mac asyncio subprocess
                        out, err = await proc.communicate()
                        return_code = proc.returncode
                    
                    if out:
                        lines = out.decode(errors='ignore').splitlines()
                        stdout_tail_lines = lines[-50:]
                    if err:
                        lines = err.decode(errors='ignore').splitlines()
                        stderr_tail_lines = lines[-50:]
            except Exception as e:
                logger.debug(f"Failed to read Wapiti stdout/stderr: {e}")
            
            # Read and parse results
            if os.path.exists(results_file):
                try:
                    file_size = os.path.getsize(results_file)
                    logger.info(f"Reading Wapiti results file: {results_file} ({file_size} bytes)")
                    
                    if file_size == 0:
                        logger.warning(f"Wapiti results file is empty")
                    else:
                        with open(results_file, 'r', encoding='utf-8') as f:
                            results = json.load(f)
                            
                            # Parse vulnerabilities from each module's findings
                            for module_name, module_results in results.get('vulnerabilities', {}).items():
                                for finding in module_results:
                                    # Get the classification details from the classifications section
                                    classification = results.get('classifications', {}).get(module_name, {})
                                    description = classification.get('desc', finding.get('info', 'Unknown vulnerability'))
                                    solution = classification.get('sol', finding.get('solution', 'No specific solution provided'))
                                    
                                    # Build references from classification
                                    references = []
                                    if 'ref' in classification:
                                        references = list(classification['ref'].values())
                                    
                                    vuln = Vulnerability(
                                        name=module_name,  # Use category name as title
                                        description=description,
                                        severity=self._map_severity(finding.get('level', 2)),
                                        confidence='high',  # Wapiti doesn't provide confidence levels
                                        url=finding.get('path', ''),  # Use path as the affected URL
                                        parameter=finding.get('parameter', ''),
                                        evidence=finding.get('info', ''),
                                        solution=solution,
                                        references=references,
                                        tags=[finding.get('module', module_name)],
                                        cwe_id=None,  # Wapiti doesn't provide CWE directly
                                        raw_finding=finding
                                    )
                                    vulnerabilities.append(vuln.dict())
                            
                            logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Wapiti results")
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Wapiti JSON results: {e}")
                except Exception as e:
                    logger.error(f"Error reading Wapiti results: {e}")
            else:
                logger.warning(f"Wapiti results file not found: {results_file}")

            return ScanResult(
                scan_id=scan_id,
                target_url=scan_info['config']['target_url'],
                start_time=scan_info['start_time'],
                end_time=utc_now(),
                status='completed',
                vulnerabilities=vulnerabilities,
                raw_findings={
                    **(results if os.path.exists(results_file) else {}),
                    "process": {
                        "return_code": return_code,
                        "stderr_tail": stderr_tail_lines,
                        "stdout_tail": stdout_tail_lines,
                    }
                },
                scan_log=[
                    f"Scan completed with {len(vulnerabilities)} findings",
                    f"Command executed: {' '.join(scan_info['cmd'])}",
                    *( ["--- STDERR (tail) ---"] + stderr_tail_lines if stderr_tail_lines else [] ),
                ]
            )

        except Exception as e:
            logger.error(f"Error getting Wapiti scan results: {str(e)}")
            raise

    def _map_severity(self, wapiti_level) -> str:
        """Map Wapiti severity levels to standardized levels"""
        # Convert to string if it's an integer
        level_str = str(wapiti_level) if isinstance(wapiti_level, int) else wapiti_level
        
        severity_map = {
            '1': 'info',
            '2': 'low',
            '3': 'medium',
            '4': 'high',
            '5': 'critical',
            'info': 'info',
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical'
        }
        return severity_map.get(level_str.lower() if isinstance(level_str, str) else level_str, 'medium')

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running Wapiti scan"""
        try:
            if scan_id not in self.active_scans:
                return False
                
            scan_info = self.active_scans[scan_id]
            proc = scan_info['process']
            is_windows = scan_info.get('is_windows', False)
            
            def _wait_sync() -> bool:
                try:
                    proc.wait(timeout=5.0)
                    return True
                except subprocess.TimeoutExpired:
                    return False

            process_running = (proc.poll() if is_windows else proc.returncode) is None
            if process_running:
                proc.terminate()
                try:
                    if is_windows:
                        completed = await asyncio.get_event_loop().run_in_executor(self.executor, _wait_sync)
                        if not completed:
                            proc.kill()
                    else:
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    proc.kill()
            
            return True
            
        except Exception as e:
            logger.error(f"Error stopping Wapiti scan: {str(e)}")
            return False

    async def cleanup_scan(self, scan_id: str) -> bool:
        """Clean up a completed Wapiti scan"""
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
            logger.error(f"Error cleaning up Wapiti scan: {str(e)}")
            return False

    async def shutdown(self) -> bool:
        """Shutdown Wapiti scanner"""
        try:
            # Stop all active scans
            for scan_id in list(self.active_scans.keys()):
                await self.stop_scan(scan_id)
                await self.cleanup_scan(scan_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error shutting down Wapiti scanner: {str(e)}")
            return False