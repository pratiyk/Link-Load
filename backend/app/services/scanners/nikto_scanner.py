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
import csv

from .base_scanner import BaseScanner, ScannerConfig, ScanResult, Vulnerability
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

# Fix for Windows asyncio event loop policy
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# Check if running in Docker mode
def _is_docker_mode() -> bool:
    """Check if we should use Docker container for Nikto scans."""
    use_docker = os.getenv("NIKTO_USE_DOCKER", "false").lower() == "true"
    logger.info(f"Nikto Docker mode: {use_docker}")
    return use_docker

def _get_nikto_container() -> str:
    """Get the Nikto Docker container name."""
    return os.getenv("NIKTO_CONTAINER", "linkload-nikto")


class NiktoScannerConfig(BaseModel):
    """Configuration for Nikto scanner"""
    binary_path: str = "nikto.pl"  # Path to nikto.pl script
    plugins: str = "@@ALL"  # All plugins by default
    tuning: str = "123456789abc"  # All tuning options for complete scan (all test types)
    timeout: int = 30  # Request timeout in seconds (increased for thorough checks)
    useragent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    evasion: str = "1234567"  # All evasion techniques for complete scan


class NiktoScanner(BaseScanner):
    def __init__(self, config: Optional[NiktoScannerConfig] = None):
        import os as _os
        self.config = config or NiktoScannerConfig()
        # Check Docker mode from environment
        self.use_docker = _is_docker_mode()
        self.docker_container = _get_nikto_container()
        if self.use_docker:
            logger.info(f"Nikto running in Docker mode using container: {self.docker_container}")
        
        # Optional: allow overriding plugins via env var
        env_plugins = _os.getenv("NIKTO_PLUGINS")
        if env_plugins:
            self.config.plugins = env_plugins
            logger.info(f"Nikto plugins overridden via env: {self.config.plugins}")
        
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.is_windows = sys.platform == 'win32' and not self.use_docker

    async def initialize(self) -> bool:
        """Initialize Nikto scanner"""
        try:
            # Docker mode: Test via docker exec
            if self.use_docker:
                result = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: subprocess.run(
                        ['docker', 'exec', self.docker_container, 'perl', '/opt/nikto/program/nikto.pl', '-Version'],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                )
                if result.returncode != 0:
                    logger.error(f"Nikto Docker container not available: {result.stderr}")
                    return False
                version = result.stdout.strip() or result.stderr.strip()
                logger.info(f"Successfully initialized Nikto (Docker) {version}")
                return True
            
            # Test nikto installation (local binary mode)
            if self.is_windows:
                # Use subprocess.run for Windows
                def _run_version_windows():
                    env = os.environ.copy()
                    env['PYTHONIOENCODING'] = 'utf-8'
                    env['PYTHONUTF8'] = '1'
                    return subprocess.run(
                        ['perl', self.config.binary_path, '-Version'],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        env=env
                    )
                
                result = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    _run_version_windows
                )
            else:
                # Linux/Mac: Use subprocess
                result = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: subprocess.run(
                        ['perl', self.config.binary_path, '-Version'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                )
            
            if result.returncode != 0:
                logger.error(f"Nikto not available: {result.stderr}")
                return False
            
            version = result.stdout.strip() or result.stderr.strip()
            logger.info(f"Successfully initialized Nikto {version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Nikto scanner: {str(e)}")
            return False

    async def start_scan(self, config: ScannerConfig) -> str:
        """Start a new Nikto scan"""
        try:
            scan_id = str(uuid.uuid4())
            
            # Create output directory - use shared volume for Docker mode
            if self.use_docker:
                # Output to shared volume accessible by both containers
                output_dir = f"/shared/nikto_results_{scan_id}"
                local_output_dir = f"/shared/nikto_results_{scan_id}"
            else:
                output_dir = f"nikto_results_{scan_id}"
                local_output_dir = output_dir
            os.makedirs(local_output_dir, exist_ok=True)
            
            logger.info(f"Starting Nikto scan {scan_id} for {config.target_url}")
            
            # Build Nikto command arguments
            results_file = os.path.join(output_dir, "nikto_output.csv")
            
            nikto_args = [
                '-h', config.target_url,  # Target host
                '-Format', 'csv',  # Output format
                '-output', results_file,  # Output file
                '-Plugins', self.config.plugins,  # Plugins to run (all plugins)
                '-timeout', str(self.config.timeout),  # Request timeout
                '-useragent', self.config.useragent,  # User agent
                '-Tuning', self.config.tuning,  # All tuning options for complete scan
                '-evasion', self.config.evasion,  # All evasion techniques
            ]
            
            # Always enable comprehensive scanning features
            # -mutate: Enable all mutation tests
            # -Display: Show all possible output
            nikto_args.extend([
                '-mutate', '1234567',  # All mutation tests
                '-Display', 'V',  # Verbose output
            ])
            
            # Build full command
            if self.use_docker:
                cmd = ['docker', 'exec', self.docker_container, 'perl', '/opt/nikto/program/nikto.pl'] + nikto_args
                logger.info(f"Nikto Docker command: {' '.join(cmd)}")
            else:
                cmd = ['perl', self.config.binary_path] + nikto_args
                logger.info(f"Nikto command: {' '.join(cmd)}")
                
            # Start nikto process - use different approach for Windows (non-Docker)
            if self.is_windows and not self.use_docker:
                # Windows: Use Popen directly in thread pool
                def run_nikto_windows():
                    try:
                        # Set environment to avoid issues on Windows
                        env = os.environ.copy()
                        env['PYTHONIOENCODING'] = 'utf-8'
                        env['PYTHONUTF8'] = '1'
                        
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=os.getcwd(),
                            env=env
                        )
                        logger.info(f"Nikto process started with PID: {proc.pid}")
                        return proc
                    except Exception as e:
                        logger.error(f"Failed to start Nikto process: {e}")
                        raise
                
                proc = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    run_nikto_windows
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
            logger.error(f"Failed to start Nikto scan: {str(e)}")
            raise

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of Nikto scan"""
        if scan_id not in self.active_scans:
            return {'status': 'not_found', 'scan_id': scan_id}
        
        scan_info = self.active_scans[scan_id]
        proc = scan_info['process']
        is_windows = scan_info.get('is_windows', False)
        
        # Check if process is still running
        if is_windows:
            # Windows: proc is subprocess.Popen
            is_running = proc.poll() is None
        else:
            # Linux/Mac: proc is asyncio subprocess
            is_running = proc.returncode is None
        
        return {
            'status': 'running' if is_running else 'completed',
            'scan_id': scan_id,
            'start_time': scan_info['start_time'].isoformat(),
            'target_url': scan_info['config']['target_url']
        }

    async def get_scan_results(self, scan_id: str) -> ScanResult:
        """Get results from a Nikto scan"""
        try:
            if scan_id not in self.active_scans:
                raise ValueError(f"Scan {scan_id} not found")
            
            scan_info = self.active_scans[scan_id]
            proc = scan_info['process']
            output_dir = scan_info['output_dir']
            results_file = os.path.join(output_dir, "nikto_output.csv")
            is_windows = scan_info.get('is_windows', False)
            
            # Wait for process to complete and capture output
            stdout_tail_lines = []
            stderr_tail_lines = []
            return_code = None
            
            try:
                if is_windows:
                    # Windows: synchronous wait
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
                logger.debug(f"Failed to read Nikto stdout/stderr: {e}")
            
            # Parse Nikto CSV results
            vulnerabilities = []
            
            if os.path.exists(results_file):
                try:
                    file_size = os.path.getsize(results_file)
                    logger.info(f"Reading Nikto results file: {results_file} ({file_size} bytes)")
                    
                    if file_size == 0:
                        logger.warning(f"Nikto results file is empty: {results_file}")
                    else:
                        with open(results_file, 'r', encoding='utf-8', errors='ignore') as f:
                            csv_reader = csv.reader(f)
                            
                            for row_idx, row in enumerate(csv_reader):
                                # Skip header row and empty rows
                                if row_idx == 0 or not row or len(row) < 7:
                                    continue
                                
                                try:
                                    # Nikto CSV format: host, ip, port, vuln_id, method, url, description
                                    host = row[0] if len(row) > 0 else ''
                                    ip = row[1] if len(row) > 1 else ''
                                    port = row[2] if len(row) > 2 else ''
                                    vuln_id = row[3] if len(row) > 3 else ''
                                    method = row[4] if len(row) > 4 else ''
                                    url_path = row[5] if len(row) > 5 else ''
                                    description = row[6] if len(row) > 6 else ''
                                    
                                    # Build full URL
                                    full_url = f"http://{host}:{port}{url_path}" if host and port else url_path
                                    
                                    # Determine severity based on OSVDB ID or keywords
                                    severity = self._determine_severity(vuln_id, description)
                                    
                                    vuln = Vulnerability(
                                        name=f"Nikto Finding: {vuln_id}",
                                        description=description,
                                        severity=severity,
                                        confidence='medium',
                                        url=full_url,
                                        parameter=method,
                                        evidence=f"Host: {host}, IP: {ip}, Port: {port}",
                                        solution=self._get_solution(description),
                                        references=[f"OSVDB-{vuln_id}"] if vuln_id else [],
                                        tags=['nikto', 'web-scanner', method.lower() if method else 'general'],
                                        cwe_id=None,  # Nikto doesn't provide CWE directly
                                        raw_finding={
                                            'host': host,
                                            'ip': ip,
                                            'port': port,
                                            'vuln_id': vuln_id,
                                            'method': method,
                                            'url': url_path,
                                            'description': description
                                        }
                                    )
                                    vulnerabilities.append(vuln.dict())
                                except Exception as parse_err:
                                    logger.warning(f"Failed to parse Nikto CSV row {row_idx}: {parse_err}")
                                    continue
                        
                        logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Nikto results")
                except Exception as e:
                    logger.error(f"Failed to parse Nikto CSV results: {e}")
            else:
                logger.warning(f"Nikto results file not found: {results_file}")

            return ScanResult(
                scan_id=scan_id,
                target_url=scan_info['config']['target_url'],
                start_time=scan_info['start_time'],
                end_time=utc_now(),
                status='completed',
                vulnerabilities=vulnerabilities,
                raw_findings={
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
            logger.error(f"Error getting Nikto scan results: {str(e)}")
            raise

    def _determine_severity(self, vuln_id: str, description: str) -> str:
        """Determine severity based on vulnerability ID and description"""
        description_lower = description.lower()
        
        # High severity keywords
        if any(keyword in description_lower for keyword in [
            'sql injection', 'xss', 'cross-site scripting', 'remote code execution',
            'rce', 'authentication bypass', 'directory traversal', 'command injection',
            'file inclusion', 'arbitrary file', 'shell'
        ]):
            return 'high'
        
        # Medium severity keywords
        if any(keyword in description_lower for keyword in [
            'information disclosure', 'sensitive', 'password', 'configuration',
            'outdated', 'vulnerable version', 'csrf', 'clickjacking', 'insecure'
        ]):
            return 'medium'
        
        # Low severity by default
        return 'low'

    def _get_solution(self, description: str) -> str:
        """Generate solution based on finding description"""
        description_lower = description.lower()
        
        if 'outdated' in description_lower or 'version' in description_lower:
            return "Update the software to the latest stable version."
        elif 'configuration' in description_lower:
            return "Review and harden server configuration according to security best practices."
        elif 'information disclosure' in description_lower:
            return "Remove or restrict access to sensitive information."
        elif 'xss' in description_lower or 'cross-site scripting' in description_lower:
            return "Implement proper input validation and output encoding."
        elif 'sql injection' in description_lower:
            return "Use parameterized queries and input validation."
        else:
            return "Review the finding and apply appropriate security controls."

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running Nikto scan"""
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
            logger.error(f"Error stopping Nikto scan: {str(e)}")
            return False

    async def cleanup_scan(self, scan_id: str) -> bool:
        """Clean up a completed Nikto scan"""
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
            logger.error(f"Error cleaning up Nikto scan: {str(e)}")
            return False

    async def shutdown(self) -> bool:
        """Shutdown Nikto scanner"""
        try:
            # Stop all active scans
            for scan_id in list(self.active_scans.keys()):
                await self.stop_scan(scan_id)
                await self.cleanup_scan(scan_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error shutting down Nikto scanner: {str(e)}")
            return False
