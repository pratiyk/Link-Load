from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx
import os
import base64
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

VT_API_KEY = os.getenv("VT_API_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"

class ScanRequest(BaseModel):
    url: str

def encode_url_for_vt(url: str) -> str:
    url_bytes = url.encode('utf-8')
    b64_bytes = base64.urlsafe_b64encode(url_bytes)
    b64_str = b64_bytes.decode('utf-8').strip('=')
    return b64_str

@router.post("/scan-url")
async def scan_url(data: ScanRequest):
    url = data.url
    result = {
        "url": url,
        "safe": True,
        "confidence": 100,
        "sources": []
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
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
                result["sources"].append("Google Safe Browsing")

            # 2. VirusTotal
            vt_submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VT_API_KEY},
                data={"url": url}
            )
            if vt_submit.status_code == 200:
                # Use base64-encoded URL for GET request
                encoded_url = encode_url_for_vt(url)
                vt_report = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
                    headers={"x-apikey": VT_API_KEY}
                )
                if vt_report.status_code == 200:
                    stats = vt_report.json()["data"]["attributes"]["last_analysis_stats"]
                    if stats.get("malicious", 0) > 0:
                        result["safe"] = False
                        result["confidence"] = max(result["confidence"], 95)
                        result["sources"].append("VirusTotal")

            # 3. PhishTank
            phish_res = await client.get(PHISHTANK_URL)
            if phish_res.status_code == 200:
                try:
                    phish_list = phish_res.json()
                    for entry in phish_list:
                        if entry.get("url") == url:
                            result["safe"] = False
                            result["confidence"] = 98
                            result["sources"].append("PhishTank")
                            break
                except Exception:
                    pass

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not result["sources"]:
        result["sources"] = ["All sources clear"]
    return result
