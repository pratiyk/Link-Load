from typing import Dict, Any, Optional
from app.services.intelligence_sources.base_intel import BaseIntelligence
import aiohttp
import json
import logging

logger = logging.getLogger(__name__)

class NVDIntelligenceSource(BaseIntelligence):
    """National Vulnerability Database (NVD) intelligence source"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.initialized = False

    async def initialize(self) -> bool:
        self.initialized = True
        return True

    async def get_intel(self, title: str, description: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get vulnerability information from NVD"""
        if not self.initialized:
            await self.initialize()

        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    "keywordSearch": title
                }
                async with session.get(self.base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("vulnerabilities"):
                            vuln = data["vulnerabilities"][0]["cve"]
                            return {
                                "threat_type": "CVE",
                                "confidence": 0.8,
                                "last_seen": None,  # NVD doesn't provide this
                                "raw_data": vuln
                            }
        except Exception as e:
            logger.error(f"Error fetching NVD data: {e}")
        return None

    async def update_feed(self) -> bool:
        """Update is not needed for NVD as it's real-time"""
        return True