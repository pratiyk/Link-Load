"""
API endpoint to provide dynamic MITRE ATT&CK techniques from MITRE CTI (Enterprise Matrix).
Uses stix2 and taxii2-client to fetch and cache techniques.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import threading
import time

try:
    from taxii2client.v20 import Server
    from stix2 import Filter
except ImportError:
    raise ImportError("Please install stix2 and taxii2-client: pip install stix2 taxii2-client")

router = APIRouter()

# Cache for techniques (refresh every 24h)
_mitre_cache = {
    'techniques': [],
    'last_fetch': 0
}
_CACHE_TTL = 60 * 60 * 24  # 24 hours
_CACHE_LOCK = threading.Lock()

MITRE_TAXII_URL = 'https://cti-taxii.mitre.org/taxii/'
ENTERPRISE_COLLECTION_NAME = 'Enterprise ATT&CK'


def fetch_mitre_techniques():
    server = Server(MITRE_TAXII_URL)
    api_root = server.api_roots[0]
    # Find the Enterprise ATT&CK collection
    collection = None
    for c in api_root.collections:
        if c.title == ENTERPRISE_COLLECTION_NAME:
            collection = c
            break
    if not collection:
        raise Exception('Enterprise ATT&CK collection not found')
    # Fetch all attack-patterns (techniques)
    attack_patterns = collection.get_objects(filters=[Filter('type', '=', 'attack-pattern')])
    # Only keep relevant fields
    techniques = [
        {
            'id': obj.get('external_references', [{}])[0].get('external_id', obj.get('id')),
            'name': obj.get('name'),
            'description': obj.get('description'),
            'tactics': obj.get('kill_chain_phases', []),
            'platforms': obj.get('x_mitre_platforms', []),
            'url': next((ref.get('url') for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), None)
        }
        for obj in attack_patterns.get('objects', [])
        if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False)
    ]
    return techniques


def get_cached_techniques():
    now = time.time()
    with _CACHE_LOCK:
        if now - _mitre_cache['last_fetch'] > _CACHE_TTL or not _mitre_cache['techniques']:
            try:
                _mitre_cache['techniques'] = fetch_mitre_techniques()
                _mitre_cache['last_fetch'] = now
            except Exception as e:
                if not _mitre_cache['techniques']:
                    raise HTTPException(status_code=500, detail=f"Failed to fetch MITRE techniques: {e}")
    return _mitre_cache['techniques']


@router.get("/mitre/techniques", response_class=JSONResponse)
def get_mitre_techniques():
    """Return all MITRE ATT&CK Enterprise techniques (cached, dynamic)."""
    return get_cached_techniques()
