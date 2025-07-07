from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import os
import joblib
import pandas as pd
from urllib.parse import urlparse
import tldextract
import re
import socket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../ml_models/phishing_detection/phishing_detector_model.pkl")
)
try:
    model = joblib.load(MODEL_PATH)
    logger.info(f"Model loaded from {MODEL_PATH}")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    raise RuntimeError(f"Model loading failed: {e}")

router = APIRouter()

class URLRequest(BaseModel):
    url: str

def resolves(hostname: str) -> int:
    try:
        socket.gethostbyname(hostname)
        return 1
    except Exception:
        return 0

def extract_features(url: str) -> pd.DataFrame:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    domain = tldextract.extract(url)
    first_dir_length = len(parsed.path.split("/")[1]) if len(parsed.path.split("/")) > 1 else 0

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "has_at_symbol": int("@" in url),
        "has_double_slash": int('//' in url[8:]),
        "has_ip_address": int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname))),
        "has_https": int(parsed.scheme.lower() == "https"),
        "count_www": url.count("www"),
        "count_subdomain": len(domain.subdomain.split(".")) if domain.subdomain else 0,
        "first_dir_length": first_dir_length,
        "has_php_or_html": int(any(x in url for x in [".php", ".html", ".htm"])),
        "dns_resolves": resolves(hostname),
        "whois_registered": 1
    }

    feature_cols = [
        "url_length", "hostname_length", "path_length", "num_dots", "num_hyphens",
        "has_at_symbol", "has_double_slash", "has_ip_address", "has_https",
        "count_www", "count_subdomain", "first_dir_length", "has_php_or_html",
        "dns_resolves", "whois_registered"
    ]
    return pd.DataFrame([[features[col] for col in feature_cols]], columns=feature_cols)

@router.post("/phishing/predict")
async def predict_phishing(payload: URLRequest):
    url = payload.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    try:
        features = extract_features(url)
        pred = int(model.predict(features)[0])
        proba = float(model.predict_proba(features)[0][1])
        return {"url": url, "is_phishing": pred, "probability": proba}
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail="Prediction failed")
