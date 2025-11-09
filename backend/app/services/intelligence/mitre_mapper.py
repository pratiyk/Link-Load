from typing import List, Dict, Any
import json
import os
from loguru import logger
import aiohttp
import asyncio
from datetime import datetime, timedelta, timezone

from app.utils.datetime_utils import utc_now

class MITREMapper:
    def __init__(self):
        self.cache_file = "cache/mitre_data.json"
        self.cache_ttl = timedelta(days=7)  # Update MITRE data weekly
        self.techniques = {}
        self.tactics = {}
        self.load_cache()
    
    def load_cache(self):
        """Load MITRE ATT&CK data from cache or fetch new data"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                    
                cache_time = datetime.fromisoformat(cache.get('timestamp', '2000-01-01'))
                if cache_time.tzinfo is None:
                    cache_time = cache_time.replace(tzinfo=timezone.utc)
                if utc_now() - cache_time < self.cache_ttl:
                    self.techniques = cache.get('techniques', {})
                    self.tactics = cache.get('tactics', {})
                    return
                    
            # Cache missing or expired, fetch new data
            asyncio.run(self.update_mitre_data())
            
        except Exception as e:
            logger.error(f"Error loading MITRE cache: {str(e)}")
            
    async def update_mitre_data(self):
        """Fetch latest MITRE ATT&CK data"""
        try:
            async with aiohttp.ClientSession() as session:
                # Fetch Enterprise ATT&CK
                async with session.get(
                    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
                ) as response:
                    data = await response.json()
                    
                # Process techniques and tactics
                for obj in data.get('objects', []):
                    if obj.get('type') == 'attack-pattern':
                        self.techniques[obj['id']] = {
                            'name': obj.get('name'),
                            'description': obj.get('description', ''),
                            'tactics': [p['phase_name'] for p in obj.get('kill_chain_phases', [])],
                            'mitigations': obj.get('x_mitre_mitigations', [])
                        }
                    elif obj.get('type') == 'x-mitre-tactic':
                        self.tactics[obj['id']] = {
                            'name': obj.get('name'),
                            'description': obj.get('description', '')
                        }
                
                # Update cache
                cache = {
                    'timestamp': utc_now().isoformat(),
                    'techniques': self.techniques,
                    'tactics': self.tactics
                }
                
                os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
                with open(self.cache_file, 'w') as f:
                    json.dump(cache, f)
                    
        except Exception as e:
            logger.error(f"Error updating MITRE data: {str(e)}")
    
    async def map_vulnerability(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Map vulnerability to MITRE ATT&CK techniques and tactics"""
        try:
            # Extract relevant text for matching
            text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('technical_details', '')}"
            text = text.lower()
            
            matched_techniques = []
            matched_tactics = []
            
            # Match techniques
            for tech_id, tech in self.techniques.items():
                if any(keyword in text for keyword in tech['name'].lower().split()):
                    matched_techniques.append({
                        'technique_id': tech_id,
                        'name': tech['name'],
                        'description': tech['description'],
                        'mitigations': tech['mitigations']
                    })
                    
                    # Add associated tactics
                    for tactic in tech['tactics']:
                        if tactic not in matched_tactics:
                            matched_tactics.append(tactic)
            
            return {
                'techniques': matched_techniques,
                'tactics': matched_tactics,
                'confidence': self._calculate_mapping_confidence(matched_techniques)
            }
            
        except Exception as e:
            logger.error(f"Error mapping vulnerability: {str(e)}")
            return {
                'techniques': [],
                'tactics': [],
                'confidence': 0.0
            }
    
    def _calculate_mapping_confidence(self, matched_techniques: List[Dict]) -> float:
        """Calculate confidence score for MITRE mapping"""
        if not matched_techniques:
            return 0.0
            
        # More matches = higher confidence, but with diminishing returns
        base_confidence = min(len(matched_techniques) * 0.3, 0.9)
        
        # Adjust based on technique completeness
        technique_scores = []
        for technique in matched_techniques:
            score = 0.0
            if technique.get('description'):
                score += 0.3
            if technique.get('mitigations'):
                score += 0.2
            technique_scores.append(score)
            
        avg_technique_score = sum(technique_scores) / len(technique_scores)
        return min(base_confidence + avg_technique_score, 1.0)

# Global mapper instance
mitre_mapper = MITREMapper()