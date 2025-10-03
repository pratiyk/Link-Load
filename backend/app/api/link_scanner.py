import json
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, validator
import httpx
import os
import base64
import logging
from datetime import datetime
from dotenv import load_dotenv
from supabase import create_client, Client
from slowapi import Limiter
from slowapi.util import get_remote_address

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# No prefix here; mount in main.py under /api
router = APIRouter()

# API keys
VT_API_KEY = os.getenv("VT_API_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

supabase: Client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        logging.info("Supabase client initialized successfully")
    except Exception as e:
        logging.error(f"Failed to initialize Supabase: {e}")
        supabase = None
else:
    logging.warning("Supabase disabled (missing credentials)")

class ScanRequest(BaseModel):
    url: str

    @validator('url')
    def validate_url(cls, v):
        """Validate URL format and prevent injection attacks"""
        if not v or len(v) < 10:
            raise ValueError("URL must be at least 10 characters long")
        
        # Must start with http:// or https://
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        
        # Prevent common injection patterns
        dangerous_patterns = ['javascript:', 'data:', 'vbscript:', '<', '>']
        if any(pattern in v.lower() for pattern in dangerous_patterns):
            raise ValueError("URL contains potentially dangerous content")
        
        return v

def encode_url_for_vt(url: str) -> str:
    """URL-safe base64 encoding without padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

async def store_scan_result(url: str, result: dict, request: Request):
    """Persist scan result to Supabase."""
    if not supabase:
        logging.debug("Supabase disabled—skipping storage")
        return

    record = {
        "url": url,
        "safe": result["safe"],
        "confidence": result["confidence"],
        "sources": result["sources"],
        "scan_timestamp": datetime.utcnow().isoformat(),
        "user_ip": request.client.host,
        "user_agent": request.headers.get("user-agent", ""),
    }
    try:
        res = supabase.table("scanned_urls").insert(record).execute()
        if res.status_code not in (200, 201, 204):
            logging.error(f"Supabase insert failed [status={res.status_code}]: {res.data}")
        else:
            logging.info(f"Stored scan for {url} in Supabase")
    except Exception as e:
        logging.error(f"Error storing scan result: {e}")

async def get_cached_result(url: str):
    """Return today's cached scan if available."""
    if not supabase:
        return None
    cutoff = datetime.utcnow().strftime("%Y-%m-%dT00:00:00")
    try:
        res = (
            supabase.table("scanned_urls")
            .select("*")
            .eq("url", url)
            .gte("scan_timestamp", cutoff)
            .order("scan_timestamp", desc=True)
            .limit(1)
            .execute()
        )
        if res.data:
            entry = res.data[0]
            logging.info(f"Cache hit for {url}")
            return {
                "url": entry["url"],
                "safe": entry["safe"],
                "confidence": entry["confidence"],
                "sources": entry["sources"],
                "cached": True,
                "scan_date": entry["scan_timestamp"],
            }
    except Exception as e:
        logging.error(f"Cache lookup failed: {e}")
    return None

@router.post("/scan-url")
async def scan_url(req: ScanRequest, request: Request):
    """Scan a URL using multiple threat intelligence sources."""
    url = req.url.strip()
    logging.info(f"Scanning URL: {url}")

    # Check cache
    cached = await get_cached_result(url)
    if cached:
        return cached

    result = {"url": url, "safe": True, "confidence": 100, "sources": []}

    async with httpx.AsyncClient(timeout=15) as client:
        # Google Safe Browsing
        try:
            gsb = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
                json={
                    "client": {"clientId": "link&load", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
            )
            logging.debug(f"GSB status: {gsb.status_code}")
            if gsb.json().get("matches"):
                result.update({"safe": False, "confidence": 90})
                result["sources"].append("Google Safe Browsing")
        except Exception as e:
            logging.error(f"GSB error: {e}")

        # VirusTotal
        try:
            vt = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VT_API_KEY},
                data={"url": url},
            )
            logging.debug(f"VT submit status: {vt.status_code}")
            if vt.status_code == 200:
                enc = encode_url_for_vt(url)
                report = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{enc}",
                    headers={"x-apikey": VT_API_KEY},
                )
                stats = report.json()["data"]["attributes"]["last_analysis_stats"]
                logging.debug(f"VT stats: {stats}")
                if stats.get("malicious", 0) > 0:
                    result.update({"safe": False, "confidence": 95})
                    result["sources"].append("VirusTotal")
        except Exception as e:
            logging.error(f"VT error: {e}")

        # PhishTank
        try:
            ph = await client.get(PHISHTANK_URL)
            logging.debug(f"PhishTank status: {ph.status_code}")
            if ph.status_code == 200 and any(e.get("url") == url for e in ph.json()):
                result.update({"safe": False, "confidence": 98})
                result["sources"].append("PhishTank")
        except Exception as e:
            logging.error(f"PhishTank error: {e}")

    if not result["sources"]:
        result["sources"] = ["All sources clear"]

    # Persist
    await store_scan_result(url, result, request)
    logging.info(f"Scan result: {json.dumps(result)}")
    return result

@router.get("/scan-history")
async def scan_history(limit: int = 50):
    """Retrieve recent scan history."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Storage unavailable")
    res = (
        supabase.table("scanned_urls")
        .select("url,safe,confidence,sources,scan_timestamp")
        .order("scan_timestamp", desc=True)
        .limit(limit)
        .execute()
    )
    return {"total": len(res.data), "scans": res.data}

@router.get("/scan-stats")
async def scan_stats():
    """Retrieve scan statistics."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Storage unavailable")
    total = supabase.table("scanned_urls").select("id", count="exact").execute().count
    safe = supabase.table("scanned_urls").select("id", count="exact").eq("safe", True).execute().count
    recent = (
        supabase.table("scanned_urls")
        .select("id", count="exact")
        .gte("scan_timestamp", datetime.utcnow().strftime("%Y-%m-%dT00:00:00"))
        .execute().count
    )
    return {
        "total_scans": total,
        "safe_scans": safe,
        "unsafe_scans": total - safe,
        "recent_scans_24h": recent,
        "safety_rate": round((safe / total * 100), 2) if total else 0,
    }
