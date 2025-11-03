import requests, time

backend = "http://localhost:8000"

def main():
    payload = {
        "target_url": "http://testphp.vulnweb.com",
        "scan_types": ["nuclei"],
        "options": {
            "enable_ai_analysis": False,
            "enable_mitre_mapping": True,
            "include_low_risk": True,
            "deep_scan": False,
            "timeout_minutes": 10
        }
    }

    print("Starting scan against:", payload["target_url"])
    r = requests.post(f"{backend}/api/v1/scans/comprehensive/start", json=payload, timeout=30)
    print("Start status:", r.status_code)
    print("Response:", r.text[:200])
    r.raise_for_status()
    scan_id = r.json()["scan_id"]

    print("Scan ID:", scan_id)

    deadline = time.time() + 600
    last_status = None
    while time.time() < deadline:
        s = requests.get(f"{backend}/api/v1/scans/comprehensive/{scan_id}/status", timeout=15)
        if s.status_code != 200:
            print("Status fetch non-200:", s.status_code, s.text[:200])
            time.sleep(3)
            continue
        data = s.json()
        if data != last_status:
            print("Status:", data)
            last_status = data
        if data.get("status") in ("completed", "failed"):
            break
        time.sleep(5)

    res = requests.get(f"{backend}/api/v1/scans/comprehensive/{scan_id}/result", timeout=60)
    print("Results status:", res.status_code)
    if res.status_code == 200:
        j = res.json()
        print("Vulns:", len(j.get("vulnerabilities", [])))
        for v in j.get("vulnerabilities", [])[:10]:
            print("-", v.get("severity"), v.get("title"), "at", (v.get("location") or ""))
        ra = j.get("risk_assessment", {})
        print("Risk:", ra.get("overall_risk_score"), ra.get("risk_level"))
    else:
        print("Result body:", res.text[:500])

if __name__ == "__main__":
    main()
