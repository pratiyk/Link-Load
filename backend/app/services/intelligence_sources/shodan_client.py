import asyncio
import httpx
import os
from dotenv import load_dotenv
from typing import Dict, List, Optional, Any
from ...utils.logging import attack_surface_logger

load_dotenv()
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
class ShodanClient:
    def __init__(self, api_key: str):
        self.api_key = SHODAN_API_KEY
        self.base_url = "https://api.shodan.io"
        self.logger = attack_surface_logger
        
    async def get_host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get host information from Shodan
        """
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{self.base_url}/shodan/host/{ip}",
                    params={'key': self.api_key}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_host_data(data)
                elif response.status_code == 404:
                    self.logger.info(f"Host {ip} not found in Shodan")
                    return None
                else:
                    self.logger.error(f"Shodan API error for {ip}: {response.status_code}")
                    return None
                    
        except Exception as e:
            self.logger.error(f"Shodan query error for {ip}: {str(e)}")
            return None
    
    async def search_hosts(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for hosts using Shodan search
        """
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{self.base_url}/shodan/host/search",
                    params={
                        'key': self.api_key,
                        'query': query,
                        'limit': limit
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    results = []
                    
                    for match in data.get('matches', []):
                        results.append(self._parse_host_data(match))
                    
                    return results
                else:
                    self.logger.error(f"Shodan search error: {response.status_code}")
                    return []
                    
        except Exception as e:
            self.logger.error(f"Shodan search error: {str(e)}")
            return []
    
    def _parse_host_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse and normalize Shodan host data
        """
        return {
            'ip': data.get('ip_str'),
            'ports': data.get('ports', []),
            'hostnames': data.get('hostnames', []),
            'country': data.get('location', {}).get('country_name'),
            'city': data.get('location', {}).get('city'),
            'org': data.get('org'),
            'isp': data.get('isp'),
            'asn': data.get('asn'),
            'os': data.get('os'),
            'services': [
                {
                    'port': service.get('port'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    'banner': service.get('data', '')[:200]  # Truncate banner
                }
                for service in data.get('data', [])
            ],
            'vulnerabilities': data.get('vulns', []),
            'last_update': data.get('last_update'),
            'tags': data.get('tags', [])
        }
        
