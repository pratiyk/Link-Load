# Link&Load
## Lock, stock, and two smoking bad URLs.
A modular cybersecurity platform for scanning malicious links, monitoring threats, and integrating secure-by-design practices in applications.
Link & Load helps developers, analysts, and small businesses stay ahead of cyber threats by offering a security-first, plug-and-play system that integrates:
- Malicious URL detection
- Threat intelligence aggregation
- Secure API-first architecture
- Audit-friendly reporting (coming soon)

### Use Cases:
- Scan suspicious links before opening (Phishing & Malware Prevention)
- Integrate into internal tools for link safety assurance
- Cyber awareness training for non-technical teams
- Lightweight toolkit for Red/Blue team ops (e.g., during CTFs)
- Security layer for customer-facing apps

### Core features:
- URL reputation checker (API integration)
- Basic header security scanner
- Vulnerability dashboard

### Setup & Usage:
```
# Clone
git clone https://github.com/yourusername/link-load
cd link-load

# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
cd ../frontend
npm install
npm start

```
***
#### 13-06-2025
The Link Scanner module is now fully implemented. This feature allows users to input a URL and receive a consolidated threat analysis report based on multiple cybersecurity APIs. It helps detect malicious links, phishing URLs, and suspicious activity before interacting with the site.
![alt text](image.png)
######  How it Works:
 - The frontend takes a URL input from the user.
 - It sends the URL to the backend using a POST request.
 - The backend then queries multiple APIs to scan the link:
   - Google Safe Browsing API for malware/phishing detection.
   - VirusTotal API for detailed file/URL analysis.
   - PhishTank API for crowdsourced phishing detection.
 - The results from all three sources are returned and displayed in a clean, formatted JSON view on the frontend.
