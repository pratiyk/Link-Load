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

from .base_scanner import BaseScanner, ScannerConfig, ScanResult
from app.utils.datetime_utils import utc_now

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
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.is_windows = sys.platform == 'win32'
        
    async def initialize(self) -> bool:
        """Initialize Nuclei scanner"""
        try:
            # Test nuclei installation
            if self.is_windows:
                # Use subprocess.run for Windows
                result = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: subprocess.run(
                        [self.config.binary_path, '-version'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                )
                if result.returncode != 0:
                    logger.error(f"Nuclei not found or error: {result.stderr}")
                    return False
                version = result.stdout.strip()
            else:
                # Use asyncio subprocess for Linux/Mac
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
            # Use absolute paths to avoid cwd-related issues
            output_dir = os.path.abspath(os.path.join(os.getcwd(), f"nuclei_results_{scan_id}"))
            os.makedirs(output_dir, exist_ok=True)
            results_file = os.path.abspath(os.path.join(output_dir, "results.jsonl"))
            
            # Build nuclei command
            # Prefer an explicit templates directory when available
            templates_arg: List[str] = []
            templates_dir = (self.config.templates_dir or "").strip()
            if not templates_dir:
                # Fallback to user default nuclei-templates in home if present
                home_default = os.path.join(os.path.expanduser("~"), "nuclei-templates")
                if os.path.isdir(home_default):
                    templates_dir = home_default
            if templates_dir:
                templates_arg = ['-templates', templates_dir]

            cmd = [
                self.config.binary_path,
                '-u', config.target_url,
                '-jsonl',
                '-o', results_file,
                '-rate-limit', str(self.config.rate_limit),
                '-bulk-size', str(self.config.bulk_size),
                '-timeout', str(self.config.timeout),
                '-retries', str(self.config.retries)
            ] + templates_arg

            # Deep scan mode: use more thorough scanning options
            if getattr(config, 'deep_scan', False):
                logger.info(f"[Nuclei] Deep scan mode enabled for {config.target_url}")
                # Include all severity levels for deep scans
                cmd.extend(['-severity', 'critical,high,medium,low,info'])
                # Enable headless browser for JavaScript rendering
                cmd.append('-headless')
            else:
                # Quick/Standard: Include info level to capture technology detection
                # Many useful nuclei templates are info-level (tech detection, version disclosure)
                if not getattr(config, 'include_low_risk', True):
                    cmd.extend(['-severity', 'critical,high,medium'])
                else:
                    # Include info so tech detection and version disclosure findings appear
                    cmd.extend(['-severity', 'critical,high,medium,low,info'])

            # Optional debug output
            if self.config.debug:
                cmd.append('-debug')
            # Reduce non-essential output just in case
            cmd.append('-no-color')
            
            # Prepare environment (ensure Google CSE vars available to templates/dorkers)
            env = os.environ.copy()
            try:
                # Prefer settings if available via environment
                from app.core.config import settings
                if settings.GOOGLE_API_KEY:
                    env['GOOGLE_API_KEY'] = settings.GOOGLE_API_KEY
                cx = getattr(settings, 'GOOGLE_API_CX', None)
                if isinstance(cx, str) and cx.strip():
                    env['GOOGLE_API_CX'] = cx  # Search Engine ID
            except Exception:
                # Fallback to existing env only
                pass

            # Start nuclei process - use different approach for Windows
            if self.is_windows:
                # Windows: Use Popen directly in thread pool to avoid asyncio subprocess issues
                def run_nuclei_windows():
                    return subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=env,
                        cwd=output_dir
                    )
                
                proc = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    run_nuclei_windows
                )
            else:
                # Linux/Mac: Use asyncio subprocess
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    cwd=output_dir
                )
            
            self.active_scans[scan_id] = {
                'process': proc,
                'output_dir': output_dir,
                'start_time': utc_now(),
                'config': config.dict(),
                'cmd': cmd,
                'results_file': results_file,
                'is_windows': self.is_windows
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
            is_windows = scan_info.get('is_windows', False)
            results_file = scan_info.get('results_file') or f"{scan_info['output_dir']}/results.jsonl"
            
            # Check if process is still running
            if is_windows:
                # Windows Popen object
                return_code = proc.poll()
            else:
                # Asyncio subprocess
                return_code = proc.returncode
                
            if return_code is None:
                return {
                    'status': 'running',
                    'start_time': scan_info['start_time'].isoformat()
                }
            # Treat non-zero exit codes as completed if we still produced results
            has_output = False
            try:
                if results_file and os.path.exists(results_file) and os.path.getsize(results_file) > 0:
                    has_output = True
            except Exception:
                pass

            if return_code == 0 or has_output:
                return {'status': 'completed', 'return_code': return_code}
            return {'status': 'failed', 'return_code': return_code}
                
        except Exception as e:
            logger.error(f"Error getting Nuclei scan status: {str(e)}")
            return {'status': 'error', 'message': str(e)}

    async def get_scan_results(self, scan_id: str) -> ScanResult:
        """Get results from a Nuclei scan"""
        try:
            if scan_id not in self.active_scans:
                raise ValueError(f"Scan {scan_id} not found")

            scan_info = self.active_scans[scan_id]
            results_file = scan_info.get('results_file') or f"{scan_info['output_dir']}/results.jsonl"
            is_windows = scan_info.get('is_windows', False)
            
            vulnerabilities = []
            parsed_count = 0
            
            # Ensure process has fully exited before reading the file
            proc = scan_info['process']
            scan_cfg = scan_info.get('config', {})
            max_duration = int(scan_cfg.get('max_scan_duration') or 0)
            wait_timeout = max_duration if max_duration > 0 else self.config.timeout + 120
            stdout_bytes: bytes = b""
            stderr_bytes: bytes = b""
            timeout_triggered = False

            try:
                if is_windows:
                    # Windows Popen - use communicate in thread pool
                    def wait_for_process():
                        stdout, stderr = proc.communicate(timeout=wait_timeout)
                        return stdout, stderr
                    
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            self.executor,
                            wait_for_process
                        ),
                        timeout=wait_timeout + 5
                    )
                else:
                    # Linux/Mac asyncio subprocess
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=wait_timeout)
            except (asyncio.TimeoutError, subprocess.TimeoutExpired):
                timeout_triggered = True
                if is_windows:
                    proc.kill()
                    stdout_bytes, stderr_bytes = proc.communicate()
                else:
                    proc.kill()
                    stdout_bytes, stderr_bytes = await proc.communicate()

            # Small delay to let nuclei flush file buffers on Windows
            if not os.path.exists(results_file):
                await asyncio.sleep(0.5)

            # If the file exists but is empty, some Windows/CLI combinations write
            # results to stdout instead of the file. In that case, write stdout
            # into the results file so subsequent parsing can proceed normally.
            try:
                if os.path.exists(results_file) and os.path.getsize(results_file) == 0 and stdout_bytes:
                    try:
                        text_out = stdout_bytes.decode(errors='ignore')
                        # Only write if there appears to be JSON-like content
                        if text_out.strip():
                            with open(results_file, 'w', encoding='utf-8') as wf:
                                wf.write(text_out)
                    except Exception:
                        # Best-effort; continue to parsing fallback below
                        pass
            except Exception:
                # Ignore filesystem oddities and continue
                pass
            # Prefer parsing the output file; fallback to stdout only if file is missing/empty
            if os.path.exists(results_file):
                with open(results_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            finding = json.loads(line)
                        except Exception:
                            continue
                        info = finding.get('info', {}) or {}
                        classification = info.get('classification', {}) or {}
                        template_id = finding.get('template-id') or finding.get('templateID')
                        title = info.get('name') or template_id
                        vuln = {
                            'vuln_id': template_id,
                            'title': title,
                            'name': template_id,
                            'severity': info.get('severity'),
                            'cvss_score': classification.get('cvss-score') or classification.get('cvss_score') or 0.0,
                            'confidence': 'confirmed',
                            'description': info.get('description'),
                            'location': finding.get('matched-at'),
                            'url': finding.get('matched-at'),
                            'evidence': finding.get('matcher-name'),
                            'recommendation': info.get('remediation') or info.get('solution'),
                            'solution': info.get('remediation') or info.get('solution'),
                            'references': info.get('reference', []) if isinstance(info.get('reference'), list) else ([info.get('reference')] if info.get('reference') else []),
                            'tags': info.get('tags', []),
                            'cwe_id': classification.get('cwe-id') or classification.get('cwe_id'),
                            'discovered_at': utc_now(),
                            'raw_finding': finding
                        }
                        vulnerabilities.append(vuln)
                        parsed_count += 1

            # Fallback: drain any remaining stdout/stderr if file parsing yielded nothing
            if parsed_count == 0 and stdout_bytes:
                stdout_text = stdout_bytes.decode(errors='ignore') if stdout_bytes else ""
                for line in stdout_text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                    except Exception:
                        continue
                    info = finding.get('info', {}) or {}
                    classification = info.get('classification', {}) or {}
                    template_id = finding.get('template-id') or finding.get('templateID')
                    title = info.get('name') or template_id
                    vuln = {
                        'vuln_id': template_id,
                        'title': title,
                        'name': template_id,
                        'severity': info.get('severity'),
                        'cvss_score': classification.get('cvss-score') or classification.get('cvss_score') or 0.0,
                        'confidence': 'confirmed',
                        'description': info.get('description'),
                        'location': finding.get('matched-at'),
                        'url': finding.get('matched-at'),
                        'evidence': finding.get('matcher-name'),
                        'recommendation': info.get('remediation') or info.get('solution'),
                        'solution': info.get('remediation') or info.get('solution'),
                        'references': info.get('reference', []) if isinstance(info.get('reference'), list) else ([info.get('reference')] if info.get('reference') else []),
                        'tags': info.get('tags', []),
                        'cwe_id': classification.get('cwe-id') or classification.get('cwe_id'),
                        'discovered_at': utc_now(),
                        'raw_finding': finding
                    }
                    vulnerabilities.append(vuln)
                    parsed_count += 1

            if stderr_bytes:
                try:
                    scan_info['stderr_tail'] = stderr_bytes.decode(errors='ignore')[-4000:]
                except Exception:
                    scan_info['stderr_tail'] = None

            return ScanResult(
                scan_id=scan_id,
                target_url=scan_info['config']['target_url'],
                start_time=scan_info['start_time'],
                end_time=utc_now(),
                status='completed',
                vulnerabilities=vulnerabilities,
                raw_findings={
                    'command': scan_info['cmd'],
                    'output_file': results_file,
                    'output_file_exists': os.path.exists(results_file),
                    'stdout_lines_parsed': parsed_count,
                    'stderr_tail': scan_info.get('stderr_tail'),
                    'return_code': proc.returncode,
                    'timeout_triggered': timeout_triggered
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