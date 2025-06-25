from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
import os
import logging
import httpx
from dotenv import load_dotenv

load_dotenv()
LEAK_LOOKUP_API_KEY = os.getenv("LEAK_LOOKUP_API_KEY")
RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")

logger = logging.getLogger(__name__)
router = APIRouter()

class ScanRequest(BaseModel):
    email: EmailStr

@router.post("/darkweb_scan")
async def darkweb_scan(request: ScanRequest):
    email = request.email
    results = []

    # === Leak-Lookup ===
    leak_lookup_url = "https://leak-lookup.com/api/search"
    payload = {
        "key": LEAK_LOOKUP_API_KEY,
        "type": "email_address",
        "query": email
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(leak_lookup_url, json=payload)
        res.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error(f"Leak-Lookup request failed: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Leak-Lookup API failed")

    data = res.json()
    if data.get("error") == "true":
        logger.error(f"Leak-Lookup API error: {data.get('message')}")
    else:
        leak_data = []
        for site, leaks in data.get("message", {}).items():
            for leak in leaks:
                leak["breach_site"] = site
                leak_data.append(leak)
        results.append({"source": "Leak-Lookup", "data": leak_data})

    # === BreachDirectory via RapidAPI ===
    bd_url = "https://breachdirectory.p.rapidapi.com/"
    params = {"func": "auto", "term": email}
    headers = {
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
        "X-RapidAPI-Key": RAPIDAPI_KEY,
        "Accept": "application/json"
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            res = await client.get(bd_url, headers=headers, params=params)
        res.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error(f"BreachDirectory request failed: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="BreachDirectory API failed")

    breach_data = res.json()
    if isinstance(breach_data, list):
        results.append({"source": "BreachDirectory", "data": breach_data})

    if not results:
        raise HTTPException(status_code=404, detail="No dark web records found for this email.")

    return results
