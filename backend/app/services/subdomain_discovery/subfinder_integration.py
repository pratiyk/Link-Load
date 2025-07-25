import asyncio
import subprocess
import json
import tempfile
import os
from typing import List, Set
from pathlib import Path
from ...utils.logging import subdomain_logger

class SubfinderService:
    def __init__(self):
        self.logger = subdomain_logger
        self.timeout = 300  # 5 minutes timeout
        
    async def discover_subdomains(self, domain: str) -> Set[str]:
        """
        Use Subfinder to discover subdomains
        """
        try:
            self.logger.info(f"Starting Subfinder discovery for {domain}")
            
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Build Subfinder command
            cmd = [
                'subfinder',
                '-d', domain,
                '-o', temp_path,
                '-silent',
                '-all',
                '-max-time', '5'
            ]
            
            # Run Subfinder
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
                self.logger.warning(f"Subfinder timeout for {domain}")
                return set()
            
            # Read results from temp file
            subdomains = set()
            if os.path.exists(temp_path):
                with open(temp_path, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and self._is_valid_subdomain(subdomain):
                            subdomains.add(subdomain)
                
                # Clean up temp file
                os.unlink(temp_path)
            
            self.logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Subfinder error for {domain}: {str(e)}")
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
