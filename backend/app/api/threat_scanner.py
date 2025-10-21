from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from app.utils.threat_sources import get_virustotal_score, get_abuseipdb_score, get_shodan_info

from app.core.config import settings
router = APIRouter(prefix=settings.API_PREFIX)

class ThreatInput(BaseModel):
    domain: Optional[str] = None
    ip: Optional[str] = None

@router.post("/scan-threat")
def scan_threat(data: ThreatInput):
    if not data.domain and not data.ip:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one of domain or ip must be provided"
        )

    vt_score = get_virustotal_score(data.domain) if data.domain else None
    abuse_score = get_abuseipdb_score(data.ip) if data.ip else None
    shodan_info = get_shodan_info(data.ip) if data.ip else None

    if vt_score is None and abuse_score is None and shodan_info is None:
        raise HTTPException(status_code=400, detail="Error fetching data from threat sources")

    result = {
        "domain_analysis": vt_score,
        "ip_abuse_analysis": abuse_score,
        "shodan_info": shodan_info,
        "risk_classification": classify_risk(vt_score, abuse_score)
    }
    return result

def classify_risk(vt_score, abuse_score):
    malicious_count = vt_score.get("malicious", 0) if vt_score else 0
    abuse_confidence = abuse_score.get("abuseConfidenceScore", 0) if abuse_score else 0

    if malicious_count > 5 or abuse_confidence > 75:
        return "High"
    elif malicious_count > 1 or abuse_confidence > 30:
        return "Medium"
    return "Low"
