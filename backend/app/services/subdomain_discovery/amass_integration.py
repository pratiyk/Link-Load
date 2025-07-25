import asyncio
import subprocess
import json
import tempfile
import os
from typing import List, Set, Dict
from pathlib import Path
from ...utils.logging import subdomain_logger

class AmassService:
    def __init__(self):
        self.logger = subdomain_logger
        self.timeout = 600  # 10 minutes timeout
        
    async def discover_subdomains(self, domain: str, passive_only: bool = True) -> Set[str]:
        """
        Use Amass to discover subdomains
        """
        try:
            self.logger.info(f"Starting Amass discovery for {domain}")
            
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Build Amass command
            cmd = [
                'amass', 'enum',
                '-d', domain,
                '-json', temp_path,
                '-timeout', '10'
            ]
            
            if passive_only:
                cmd.append('-passive')
            
            # Run Amass
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                self.logger.warning(f"Amass timeout for {domain}")
                return set()
            
            # Parse JSON results
            subdomains = set()
            if os.path.exists(temp_path):
                try:
                    with open(temp_path, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    data = json.loads(line.strip())
                                    if 'name' in data:
                                        subdomain = data['name']
                                        if self._is_valid_subdomain(subdomain):
                                            subdomains.add(subdomain)
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    self.logger.error(f"Error parsing Amass results: {str(e)}")
                
                # Clean up temp file
                os.unlink(temp_path)
            
            self.logger.info(f"Amass found {len(subdomains)} subdomains for {domain}")
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Amass error for {domain}: {str(e)}")
            return set()
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """
        Validate subdomain format
        """
        return (
            '.' in subdomain and 
            not subdomain.startswith('.') and 
            not subdomain.endswith('.') and
            len(subdomain) < 253
        )
