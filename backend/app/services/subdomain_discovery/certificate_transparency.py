import asyncio
import httpx
import json
from typing import Set, List
from urllib.parse import quote
from ...utils.logging import subdomain_logger

class CertificateTransparencyService:
    def __init__(self):
        self.logger = subdomain_logger
        self.timeout = 30
        
        # Certificate transparency log sources
        self.sources = [
            "https://crt.sh/?q={domain}&output=json",
            "https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
    
    async def discover_subdomains(self, domain: str) -> Set[str]:
        """
        Discover subdomains using Certificate Transparency logs
        """
        try:
            self.logger.info(f"Starting Certificate Transparency discovery for {domain}")
            
            all_subdomains = set()
            
            # Query all CT sources concurrently
            tasks = []
            for source_url in self.sources:
                if "crt.sh" in source_url:
                    tasks.append(self._query_crt_sh(domain))
                elif "certspotter" in source_url:
                    tasks.append(self._query_certspotter(domain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            for result in results:
                if isinstance(result, set):
                    all_subdomains.update(result)
                elif isinstance(result, Exception):
                    self.logger.warning(f"CT source error: {str(result)}")
            
            self.logger.info(f"Certificate Transparency found {len(all_subdomains)} subdomains for {domain}")
            return all_subdomains
            
        except Exception as e:
            self.logger.error(f"Certificate Transparency error for {domain}: {str(e)}")
            return set()
    
    async def _query_crt_sh(self, domain: str) -> Set[str]:
        """
        Query crt.sh for certificate transparency data
        """
        subdomains = set()
        url = f"https://crt.sh/?q={quote(domain)}&output=json"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                data = response.json()
                for cert in data:
                    if 'name_value' in cert:
                        # name_value can contain multiple domains separated by newlines
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            if name and self._is_valid_subdomain(name, domain):
                                # Remove wildcard prefix
                                if name.startswith('*.'):
                                    name = name[2:]
                                subdomains.add(name)
                                
        except Exception as e:
            self.logger.warning(f"crt.sh query failed: {str(e)}")
            
        return subdomains
    
    async def _query_certspotter(self, domain: str) -> Set[str]:
        """
        Query CertSpotter for certificate transparency data
        """
        subdomains = set()
        url = f"https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                data = response.json()
                for cert in data:
                    if 'dns_names' in cert:
                        for name in cert['dns_names']:
                            if name and self._is_valid_subdomain(name, domain):
                                # Remove wildcard prefix
                                if name.startswith('*.'):
                                    name = name[2:]
                                subdomains.add(name)
                                
        except Exception as e:
            self.logger.warning(f"CertSpotter query failed: {str(e)}")
            
        return subdomains
    
    def _is_valid_subdomain(self, subdomain: str, base_domain: str) -> bool:
        """
        Validate subdomain format and ensure it belongs to base domain
        """
        return (
            subdomain.endswith('.' + base_domain) or subdomain == base_domain and
            '.' in subdomain and 
            not subdomain.startswith('.') and 
            not subdomain.endswith('.') and
            len(subdomain) < 253
        )
