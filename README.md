# Link&Load
## Lock, stock, and two smoking bad URLs.
A modular cybersecurity platform for scanning malicious links, monitoring threats, and integrating secure-by-design practices in applications.
Link & Load is an open-source cybersecurity platform that scans suspicious URLs, analyzes threat intelligence from multiple sources, detects vulnerabilities in software packages, and automates remediation recommendations. Built with a modern, scalable architecture (React + FastAPI), the project integrates real-world cybersecurity tools and APIs, empowering users with proactive defense, real-time insights, and secure compliance-ready features. The suite is designed for use by security teams, researchers, and organizations seeking enterprise-grade security automation.

### Use Cases:
- Scan suspicious links before opening (Phishing & Malware Prevention)
- Integrate into internal tools for link safety assurance
- Cyber awareness training for non-technical teams
- Lightweight toolkit for Red/Blue team ops (e.g., during CTFs)
- Security layer for customer-facing apps

### Core features:
- Link Scanner (detects bad links)
- Threat Intel (shows IP/domain behavior)
- Vulnerability Scanner (checks libraries)

### Future Scope:
- Automated Vulnerability Assessment & Remediation (Next Module) (Continuously scans installed packages on servers or containers and suggests or applies security patches.)
- Dark Web Monitoring (Monitors paste sites, leak databases, and darknet forums for sensitive info leaks.)
- Attack Surface Mapping (Identifies all public-facing assets (subdomains, open ports, services))
- Role-Based Access Control (RBAC) & Secure Audit Logs (mplements user-level security, role segregation, and immutable logs.)
- Compliance Reporting Dashboard (Helps organizations meet compliance (GDPR, ISO, HIPAA) by summarizing security posture.)
- Static & Dynamic Malware Analysis (Accepts uploaded files for sandbox-based behavioral analysis and static inspection.)

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

***
#### 15-06-2025
I have successfully implemented the Threat Score Aggregator module. This new feature enhances the project’s cybersecurity capabilities by aggregating threat intelligence from multiple external APIs to assess the risk associated with a domain or IP address.
![image](https://github.com/user-attachments/assets/8f84f099-308f-43b2-bd5c-d90fb0c1e9ad)
######  How it Works: 
 - The user inputs a domain or IP address in the frontend React app.
 - The input is sent to the backend FastAPI server.
 - The backend queries three key cybersecurity services:
   - VirusTotal API: Provides analysis of domain reputation and detects malicious activity.
   - AbuseIPDB API: Offers insights on IP address abuse history and confidence scores.
   - Shodan API: Retrieves detailed information about the IP’s open ports, services, and vulnerabilities.
 - The backend processes and aggregates this data, classifying the overall risk level (High, Medium, or Low).
 - The frontend displays the detailed report and risk classification in a user-friendly format.

***
#### 17-06-2025
The Vulnerability Scanner module is now fully implemented, providing a seamless way to scan software packages for known security vulnerabilities by querying multiple trusted vulnerability databases. It integrates a React frontend user interface with a FastAPI backend API, combining data from OSV.dev and the National Vulnerability Database (NVD) to deliver comprehensive vulnerability reports.
![image](https://github.com/user-attachments/assets/a4971f20-6db9-43b5-8b66-5c78d059febf)
######  How it Works: 
- The user inputs a package name, selects its ecosystem, and optionally enters a version in the React frontend.
- The frontend sends this data via POST request to the FastAPI backend /api/scan-vulnerabilities endpoint.
- The backend queries two key vulnerability data sources:
   - OSV.dev API: Retrieves vulnerability info for the given package and version.
   - NVD API: Searches for related CVE entries based on the package name.
- The backend processes and merges results from both sources, formatting details like vulnerability ID, summary, severity, affected versions, and data source.
- The aggregated vulnerability data is returned to the frontend.
- The frontend displays a user-friendly list of vulnerabilities, including severity and affected versions, with loading and error handling.

***
#### 20-06-2025
I have successfully completed the Remediation Module of the Link & Load cybersecurity platform. The Remediation Module takes the output from the Vulnerability Scanner and classifies each vulnerability into Low, Medium, High, or Critical risk levels based on CVSS severity scores, generates actionable fix commands tailored to each software ecosystem (e.g., pip, npm, cargo, go, etc.) and automatically determines whether each issue is fixable via upgrade or requires manual review.
![image](https://github.com/user-attachments/assets/21a90afb-d81b-4f8a-b481-6ad655938028)
######  How it Works:
- It accepts a list of vulnerabilities (ID, package, ecosystem, and severity) passed from the Vulnerability Scanner module.
- Each vulnerability is categorized into: Low, Medium, High, or Critical based on CVSS scores.
- Uses the package ecosystem to generate appropriate update commands:
   - PyPI: pip install --upgrade <package>
   - npm: npm update <package>
   - Go: go get -u <package>
   - RubyGems, crates.io, etc.
- A detailed UI displays each vulnerability
-  Download the remediation strategy as a .txt file and a .sh shell script with all commands for batch execution.




