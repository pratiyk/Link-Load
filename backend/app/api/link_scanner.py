from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

# Load API keys from environment
VT_API_KEY = os.getenv("VT_API_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"  # simple JSON feed

class ScanRequest(BaseModel):
    url: str

@router.post("/api/scan-url")
async def scan_url(data: ScanRequest):
    url = data.url
    result = {
        "url": url,
        "safe": True,
        "confidence": 100,
        "source": []
    }

    try:
        async with httpx.AsyncClient() as client:
            # 1. Google Safe Browsing
            gsb_payload = {
                "client": {"clientId": "linkandload", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            gsb_res = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
                json=gsb_payload
            )
            gsb_data = gsb_res.json()
            if gsb_data.get("matches"):
                result["safe"] = False
                result["confidence"] = 90
                result["source"].append("Google Safe Browsing")

            # 2. VirusTotal
            vt_res = await client.get(
                f"https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VT_API_KEY},
                params={"url": url}
            )
            if vt_res.status_code == 200:
                vt_id = vt_res.json()["data"]["id"]
                vt_report = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{vt_id}",
                    headers={"x-apikey": VT_API_KEY}
                )
                stats = vt_report.json()["data"]["attributes"]["last_analysis_stats"]
                if stats["malicious"] > 0:
                    result["safe"] = False
                    result["confidence"] = max(result["confidence"], 95)
                    result["source"].append("VirusTotal")

            # 3. PhishTank (optional open database check)
            phish_data = await client.get(PHISHTANK_URL)
            if phish_data.status_code == 200:
                for entry in phish_data.json():
                    if entry.get("url") == url:
                        result["safe"] = False
                        result["confidence"] = 98
                        result["source"].append("PhishTank")
                        break

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    result["source"] = ", ".join(result["source"]) or "All sources clear"
    return result
