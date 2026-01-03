"""
API endpoint to provide dynamic MITRE ATT&CK techniques from MITRE CTI (Enterprise Matrix).
Uses stix2 and taxii2-client to fetch and cache techniques.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import json
import logging
import threading
import time
from pathlib import Path

try:
    from taxii2client.v20 import Server
    from stix2 import Filter
except ImportError:
    raise ImportError("Please install stix2 and taxii2-client: pip install stix2 taxii2-client")

router = APIRouter()
logger = logging.getLogger(__name__)

# Cache for techniques (refresh every 24h)
_mitre_cache = {
    'techniques': [],
    'last_fetch': 0
}
_CACHE_TTL = 60 * 60 * 24  # 24 hours
_CACHE_LOCK = threading.Lock()
_CACHE_FILE_PATH = Path(__file__).resolve().parent.parent.parent / 'docs' / 'mitre_techniques_cache.json'

MITRE_TAXII_URL = 'https://cti-taxii.mitre.org/taxii/'
ENTERPRISE_COLLECTION_NAME = 'Enterprise ATT&CK'


def _write_offline_cache(techniques):
    try:
        _CACHE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            'meta': {
                'cached_at': int(time.time()),
                'source': 'mitre-taxii'
            },
            'techniques': techniques
        }
        with _CACHE_FILE_PATH.open('w', encoding='utf-8') as cache_file:
            json.dump(payload, cache_file, indent=2)
    except Exception as exc:
        logger.debug('Unable to write MITRE cache file: %s', exc)


def _load_offline_cache():
    if not _CACHE_FILE_PATH.exists():
        return []
    try:
        with _CACHE_FILE_PATH.open('r', encoding='utf-8') as cache_file:
            payload = json.load(cache_file)
        if isinstance(payload, dict):
            techniques = payload.get('techniques', [])
        elif isinstance(payload, list):
            techniques = payload
        else:
            techniques = []
        return [tech for tech in techniques if isinstance(tech, dict)]
    except Exception as exc:
        logger.warning('Failed to load MITRE offline cache: %s', exc)
        return []


def fetch_mitre_techniques():
    try:
        server = Server(MITRE_TAXII_URL)
        api_root = server.api_roots[0]
        collection = None
        for c in api_root.collections:
            if c.title == ENTERPRISE_COLLECTION_NAME:
                collection = c
                break
        if not collection:
            raise Exception('Enterprise ATT&CK collection not found')
        attack_patterns = collection.get_objects(filters=[Filter('type', '=', 'attack-pattern')])
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
        _write_offline_cache(techniques)
        return techniques
    except Exception as exc:
        logger.warning('Live MITRE TAXII fetch failed, falling back to cache: %s', exc)
        cached = _load_offline_cache()
        if cached:
            return cached
        raise RuntimeError('MITRE TAXII fetch failed and no offline cache is available') from exc


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
