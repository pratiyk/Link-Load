import os
import requests
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")


def get_virustotal_score(domain: str):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return None
    data = resp.json()
    return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})


def get_abuseipdb_score(ip: str):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
    if resp.status_code != 200:
        return None
    data = resp.json()
    return data.get("data", {})


def get_shodan_info(ip: str):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    resp = requests.get(url)
    if resp.status_code != 200:
        return None
    return resp.json()
