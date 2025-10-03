# app/services/subdomain_discovery/subfinder_integration.py
import asyncio
import subprocess
import tempfile
import os
from typing import Set
from ...utils.logging import subdomain_logger

class SubfinderService:
    def __init__(self):
        self.logger = subdomain_logger
        self.timeout = 300

    async def discover_subdomains(self, domain: str) -> Set[str]:
        """Use Subfinder to discover subdomains (with fallback)"""
        try:
            self.logger.info(f"Starting Subfinder discovery for {domain}")
            
            # Check if subfinder is installed
            result = await asyncio.create_subprocess_exec(
                'subfinder', '--version',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await result.wait()
            
            if result.returncode != 0:
                self.logger.warning("Subfinder not found, using fallback discovery")
                return await self._fallback_discovery(domain)
            
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Build Subfinder command
            cmd = ['subfinder', '-d', domain, '-o', temp_path, '-silent', '-all', '-max-time', '5']
            
            # Run Subfinder
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                process.kill()
                self.logger.warning(f"Subfinder timeout for {domain}")
                return await self._fallback_discovery(domain)
            
            # Read results
            subdomains = set()
            if os.path.exists(temp_path):
                with open(temp_path, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and self._is_valid_subdomain(subdomain):
                            subdomains.add(subdomain)
                os.unlink(temp_path)
            
            self.logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
            return subdomains
            
        except Exception as e:
            self.logger.error(f"Subfinder error for {domain}: {str(e)}")
            return await self._fallback_discovery(domain)
    
    async def _fallback_discovery(self, domain: str) -> Set[str]:
        """Fallback discovery when Subfinder is not available"""
        self.logger.info(f"Using fallback discovery for {domain}")
        common_subdomains = {
            f"www.{domain}",
            f"mail.{domain}",
            f"api.{domain}",
            f"app.{domain}",
            f"admin.{domain}",
            domain  # Include the main domain
        }
        return common_subdomains
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        return ('.' in subdomain and 
                not subdomain.startswith('.') and 
                not subdomain.endswith('.') and
                len(subdomain) < 253)
