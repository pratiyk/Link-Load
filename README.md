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
- Automated Vulnerability Assessment & Remediation (Continuously scans installed packages on servers or containers and suggests or applies security patches.)

### Future Scope:
- Dark Web Monitoring (Next Module) (Monitors paste sites, leak databases, and darknet forums for sensitive info leaks.)
- Attack Surface Mapping (Identifies all public-facing assets (subdomains, open ports, services))
- Role-Based Access Control (RBAC) & Secure Audit Logs (mplements user-level security, role segregation, and immutable logs.)
- Compliance Reporting Dashboard (Helps organizations meet compliance (GDPR, ISO, HIPAA) by summarizing security posture.)
- Static & Dynamic Malware Analysis (Accepts uploaded files for sandbox-based behavioral analysis and static inspection.)
- Smart Contract Auditing & Crypto Compliance
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

*** 
### 07-07-2025
This module uses a trained LightGBM machine learning model to predict whether a given URL is likely to be a phishing link.
It extracts key URL-based features (e.g., length, subdomains, use of IP address, special characters, DNS resolution, etc.) to analyze risk and returns a probability score and label.
![image](https://github.com/user-attachments/assets/4eeb5650-762b-4a44-8cb9-104941df888d)

### Project Structure:
```
├── backend/
│   ├── alembic/
│   ├── app/
│   │   ├── api/
│   │   │   ├── darkweb_scanner.py
│   │   │   ├── link_scanner.py
│   │   │   ├── phishing_detector.py
│   │   │   ├── remediation.py
│   │   │   ├── threat_scanner.py
│   │   │   ├── vulnerability_scanner.py
│   │   │   └── __init__.py
│   │   ├── main.py
│   │   ├── services/
│   │   ├── utils/
│   │   │   ├── threat_sources.py
│   │   │   └── vulnerability_sources.py
│   │   └── __init__.py
│   ├── ml_models/
│   │   └── phishing_detection/
│   │       ├── data/
│   │       │   ├── alexa/
│   │       │   │   └── top-1m.csv
│   │       │   ├── labeled_url_dataset.csv
│   │       │   ├── phishing_dataset_with_features.csv
│   │       │   ├── phishtank/
│   │       │   │   └── phishtank_urls.csv
│   │       │   └── StealthPhisher2025.csv
│   │       └── phishing_detector_model.pkl
│   ├── requirements.txt
│   ├── tests/
│   └── venv/
│       ├── Include/
│       ├── Lib/
│       │   └── site-packages/
│       │       ├── annotated_types/
│       │       │   ├── py.typed
│       │       │   ├── test_cases.py
│       │       │   └── __init__.py
│       │       ├── annotated_types-0.7.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── anyio/
│       │       │   ├── abc/
│       │       │   │   ├── _eventloop.py
│       │       │   │   ├── _resources.py
│       │       │   │   ├── _sockets.py
│       │       │   │   ├── _streams.py
│       │       │   │   ├── _subprocesses.py
│       │       │   │   ├── _tasks.py
│       │       │   │   ├── _testing.py
│       │       │   │   └── __init__.py
│       │       │   ├── from_thread.py
│       │       │   ├── lowlevel.py
│       │       │   ├── py.typed
│       │       │   ├── pytest_plugin.py
│       │       │   ├── streams/
│       │       │   │   ├── buffered.py
│       │       │   │   ├── file.py
│       │       │   │   ├── memory.py
│       │       │   │   ├── stapled.py
│       │       │   │   ├── text.py
│       │       │   │   ├── tls.py
│       │       │   │   └── __init__.py
│       │       │   ├── to_interpreter.py
│       │       │   ├── to_process.py
│       │       │   ├── to_thread.py
│       │       │   ├── _backends/
│       │       │   │   ├── _asyncio.py
│       │       │   │   ├── _trio.py
│       │       │   │   └── __init__.py
│       │       │   ├── _core/
│       │       │   │   ├── _asyncio_selector_thread.py
│       │       │   │   ├── _eventloop.py
│       │       │   │   ├── _exceptions.py
│       │       │   │   ├── _fileio.py
│       │       │   │   ├── _resources.py
│       │       │   │   ├── _signals.py
│       │       │   │   ├── _sockets.py
│       │       │   │   ├── _streams.py
│       │       │   │   ├── _subprocesses.py
│       │       │   │   ├── _synchronization.py
│       │       │   │   ├── _tasks.py
│       │       │   │   ├── _tempfile.py
│       │       │   │   ├── _testing.py
│       │       │   │   ├── _typedattr.py
│       │       │   │   └── __init__.py
│       │       │   └── __init__.py
│       │       ├── anyio-4.9.0.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── certifi/
│       │       │   ├── cacert.pem
│       │       │   ├── core.py
│       │       │   ├── py.typed
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── certifi-2025.6.15.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── charset_normalizer/
│       │       │   ├── api.py
│       │       │   ├── cd.py
│       │       │   ├── cli/
│       │       │   │   ├── __init__.py
│       │       │   │   └── __main__.py
│       │       │   ├── constant.py
│       │       │   ├── legacy.py
│       │       │   ├── md.cp312-win_amd64.pyd
│       │       │   ├── md.py
│       │       │   ├── md__mypyc.cp312-win_amd64.pyd
│       │       │   ├── models.py
│       │       │   ├── py.typed
│       │       │   ├── utils.py
│       │       │   ├── version.py
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── charset_normalizer-3.4.2.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── click/
│       │       │   ├── core.py
│       │       │   ├── decorators.py
│       │       │   ├── exceptions.py
│       │       │   ├── formatting.py
│       │       │   ├── globals.py
│       │       │   ├── parser.py
│       │       │   ├── py.typed
│       │       │   ├── shell_completion.py
│       │       │   ├── termui.py
│       │       │   ├── testing.py
│       │       │   ├── types.py
│       │       │   ├── utils.py
│       │       │   ├── _compat.py
│       │       │   ├── _termui_impl.py
│       │       │   ├── _textwrap.py
│       │       │   ├── _winconsole.py
│       │       │   └── __init__.py
│       │       ├── click-8.2.1.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── colorama/
│       │       │   ├── ansi.py
│       │       │   ├── ansitowin32.py
│       │       │   ├── initialise.py
│       │       │   ├── tests/
│       │       │   │   ├── ansitowin32_test.py
│       │       │   │   ├── ansi_test.py
│       │       │   │   ├── initialise_test.py
│       │       │   │   ├── isatty_test.py
│       │       │   │   ├── utils.py
│       │       │   │   ├── winterm_test.py
│       │       │   │   └── __init__.py
│       │       │   ├── win32.py
│       │       │   ├── winterm.py
│       │       │   └── __init__.py
│       │       ├── colorama-0.4.6.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── dateutil/
│       │       │   ├── easter.py
│       │       │   ├── parser/
│       │       │   │   ├── isoparser.py
│       │       │   │   ├── _parser.py
│       │       │   │   └── __init__.py
│       │       │   ├── relativedelta.py
│       │       │   ├── rrule.py
│       │       │   ├── tz/
│       │       │   │   ├── tz.py
│       │       │   │   ├── win.py
│       │       │   │   ├── _common.py
│       │       │   │   ├── _factories.py
│       │       │   │   └── __init__.py
│       │       │   ├── tzwin.py
│       │       │   ├── utils.py
│       │       │   ├── zoneinfo/
│       │       │   │   ├── dateutil-zoneinfo.tar.gz
│       │       │   │   ├── rebuild.py
│       │       │   │   └── __init__.py
│       │       │   ├── _common.py
│       │       │   ├── _version.py
│       │       │   └── __init__.py
│       │       ├── dns/
│       │       │   ├── asyncbackend.py
│       │       │   ├── asyncquery.py
│       │       │   ├── asyncresolver.py
│       │       │   ├── dnssec.py
│       │       │   ├── dnssecalgs/
│       │       │   │   ├── base.py
│       │       │   │   ├── cryptography.py
│       │       │   │   ├── dsa.py
│       │       │   │   ├── ecdsa.py
│       │       │   │   ├── eddsa.py
│       │       │   │   ├── rsa.py
│       │       │   │   └── __init__.py
│       │       │   ├── dnssectypes.py
│       │       │   ├── e164.py
│       │       │   ├── edns.py
│       │       │   ├── entropy.py
│       │       │   ├── enum.py
│       │       │   ├── exception.py
│       │       │   ├── flags.py
│       │       │   ├── grange.py
│       │       │   ├── immutable.py
│       │       │   ├── inet.py
│       │       │   ├── ipv4.py
│       │       │   ├── ipv6.py
│       │       │   ├── message.py
│       │       │   ├── name.py
│       │       │   ├── namedict.py
│       │       │   ├── nameserver.py
│       │       │   ├── node.py
│       │       │   ├── opcode.py
│       │       │   ├── py.typed
│       │       │   ├── query.py
│       │       │   ├── quic/
│       │       │   │   ├── _asyncio.py
│       │       │   │   ├── _common.py
│       │       │   │   ├── _sync.py
│       │       │   │   ├── _trio.py
│       │       │   │   └── __init__.py
│       │       │   ├── rcode.py
│       │       │   ├── rdata.py
│       │       │   ├── rdataclass.py
│       │       │   ├── rdataset.py
│       │       │   ├── rdatatype.py
│       │       │   ├── rdtypes/
│       │       │   │   ├── ANY/
│       │       │   │   │   ├── AFSDB.py
│       │       │   │   │   ├── AMTRELAY.py
│       │       │   │   │   ├── AVC.py
│       │       │   │   │   ├── CAA.py
│       │       │   │   │   ├── CDNSKEY.py
│       │       │   │   │   ├── CDS.py
│       │       │   │   │   ├── CERT.py
│       │       │   │   │   ├── CNAME.py
│       │       │   │   │   ├── CSYNC.py
│       │       │   │   │   ├── DLV.py
│       │       │   │   │   ├── DNAME.py
│       │       │   │   │   ├── DNSKEY.py
│       │       │   │   │   ├── DS.py
│       │       │   │   │   ├── EUI48.py
│       │       │   │   │   ├── EUI64.py
│       │       │   │   │   ├── GPOS.py
│       │       │   │   │   ├── HINFO.py
│       │       │   │   │   ├── HIP.py
│       │       │   │   │   ├── ISDN.py
│       │       │   │   │   ├── L32.py
│       │       │   │   │   ├── L64.py
│       │       │   │   │   ├── LOC.py
│       │       │   │   │   ├── LP.py
│       │       │   │   │   ├── MX.py
│       │       │   │   │   ├── NID.py
│       │       │   │   │   ├── NINFO.py
│       │       │   │   │   ├── NS.py
│       │       │   │   │   ├── NSEC.py
│       │       │   │   │   ├── NSEC3.py
│       │       │   │   │   ├── NSEC3PARAM.py
│       │       │   │   │   ├── OPENPGPKEY.py
│       │       │   │   │   ├── OPT.py
│       │       │   │   │   ├── PTR.py
│       │       │   │   │   ├── RESINFO.py
│       │       │   │   │   ├── RP.py
│       │       │   │   │   ├── RRSIG.py
│       │       │   │   │   ├── RT.py
│       │       │   │   │   ├── SMIMEA.py
│       │       │   │   │   ├── SOA.py
│       │       │   │   │   ├── SPF.py
│       │       │   │   │   ├── SSHFP.py
│       │       │   │   │   ├── TKEY.py
│       │       │   │   │   ├── TLSA.py
│       │       │   │   │   ├── TSIG.py
│       │       │   │   │   ├── TXT.py
│       │       │   │   │   ├── URI.py
│       │       │   │   │   ├── WALLET.py
│       │       │   │   │   ├── X25.py
│       │       │   │   │   ├── ZONEMD.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── CH/
│       │       │   │   │   ├── A.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── dnskeybase.py
│       │       │   │   ├── dsbase.py
│       │       │   │   ├── euibase.py
│       │       │   │   ├── IN/
│       │       │   │   │   ├── A.py
│       │       │   │   │   ├── AAAA.py
│       │       │   │   │   ├── APL.py
│       │       │   │   │   ├── DHCID.py
│       │       │   │   │   ├── HTTPS.py
│       │       │   │   │   ├── IPSECKEY.py
│       │       │   │   │   ├── KX.py
│       │       │   │   │   ├── NAPTR.py
│       │       │   │   │   ├── NSAP.py
│       │       │   │   │   ├── NSAP_PTR.py
│       │       │   │   │   ├── PX.py
│       │       │   │   │   ├── SRV.py
│       │       │   │   │   ├── SVCB.py
│       │       │   │   │   ├── WKS.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── mxbase.py
│       │       │   │   ├── nsbase.py
│       │       │   │   ├── svcbbase.py
│       │       │   │   ├── tlsabase.py
│       │       │   │   ├── txtbase.py
│       │       │   │   ├── util.py
│       │       │   │   └── __init__.py
│       │       │   ├── renderer.py
│       │       │   ├── resolver.py
│       │       │   ├── reversename.py
│       │       │   ├── rrset.py
│       │       │   ├── serial.py
│       │       │   ├── set.py
│       │       │   ├── tokenizer.py
│       │       │   ├── transaction.py
│       │       │   ├── tsig.py
│       │       │   ├── tsigkeyring.py
│       │       │   ├── ttl.py
│       │       │   ├── update.py
│       │       │   ├── version.py
│       │       │   ├── versioned.py
│       │       │   ├── win32util.py
│       │       │   ├── wire.py
│       │       │   ├── xfr.py
│       │       │   ├── zone.py
│       │       │   ├── zonefile.py
│       │       │   ├── zonetypes.py
│       │       │   ├── _asyncbackend.py
│       │       │   ├── _asyncio_backend.py
│       │       │   ├── _ddr.py
│       │       │   ├── _features.py
│       │       │   ├── _immutable_ctx.py
│       │       │   ├── _trio_backend.py
│       │       │   └── __init__.py
│       │       ├── dnspython-2.7.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── dotenv/
│       │       │   ├── cli.py
│       │       │   ├── ipython.py
│       │       │   ├── main.py
│       │       │   ├── parser.py
│       │       │   ├── py.typed
│       │       │   ├── variables.py
│       │       │   ├── version.py
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── email_validator/
│       │       │   ├── deliverability.py
│       │       │   ├── exceptions_types.py
│       │       │   ├── py.typed
│       │       │   ├── rfc_constants.py
│       │       │   ├── syntax.py
│       │       │   ├── validate_email.py
│       │       │   ├── version.py
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── email_validator-2.2.0.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── fastapi/
│       │       │   ├── applications.py
│       │       │   ├── background.py
│       │       │   ├── cli.py
│       │       │   ├── concurrency.py
│       │       │   ├── datastructures.py
│       │       │   ├── dependencies/
│       │       │   │   ├── models.py
│       │       │   │   ├── utils.py
│       │       │   │   └── __init__.py
│       │       │   ├── encoders.py
│       │       │   ├── exceptions.py
│       │       │   ├── exception_handlers.py
│       │       │   ├── logger.py
│       │       │   ├── middleware/
│       │       │   │   ├── cors.py
│       │       │   │   ├── gzip.py
│       │       │   │   ├── httpsredirect.py
│       │       │   │   ├── trustedhost.py
│       │       │   │   ├── wsgi.py
│       │       │   │   └── __init__.py
│       │       │   ├── openapi/
│       │       │   │   ├── constants.py
│       │       │   │   ├── docs.py
│       │       │   │   ├── models.py
│       │       │   │   ├── utils.py
│       │       │   │   └── __init__.py
│       │       │   ├── params.py
│       │       │   ├── param_functions.py
│       │       │   ├── py.typed
│       │       │   ├── requests.py
│       │       │   ├── responses.py
│       │       │   ├── routing.py
│       │       │   ├── security/
│       │       │   │   ├── api_key.py
│       │       │   │   ├── base.py
│       │       │   │   ├── http.py
│       │       │   │   ├── oauth2.py
│       │       │   │   ├── open_id_connect_url.py
│       │       │   │   ├── utils.py
│       │       │   │   └── __init__.py
│       │       │   ├── staticfiles.py
│       │       │   ├── templating.py
│       │       │   ├── testclient.py
│       │       │   ├── types.py
│       │       │   ├── utils.py
│       │       │   ├── websockets.py
│       │       │   ├── _compat.py
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── fastapi-0.115.12.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   └── WHEEL
│       │       ├── filelock/
│       │       │   ├── asyncio.py
│       │       │   ├── py.typed
│       │       │   ├── version.py
│       │       │   ├── _api.py
│       │       │   ├── _error.py
│       │       │   ├── _soft.py
│       │       │   ├── _unix.py
│       │       │   ├── _util.py
│       │       │   ├── _windows.py
│       │       │   └── __init__.py
│       │       ├── filelock-3.18.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── h11/
│       │       │   ├── py.typed
│       │       │   ├── _abnf.py
│       │       │   ├── _connection.py
│       │       │   ├── _events.py
│       │       │   ├── _headers.py
│       │       │   ├── _readers.py
│       │       │   ├── _receivebuffer.py
│       │       │   ├── _state.py
│       │       │   ├── _util.py
│       │       │   ├── _version.py
│       │       │   ├── _writers.py
│       │       │   └── __init__.py
│       │       ├── h11-0.16.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── httpcore/
│       │       │   ├── py.typed
│       │       │   ├── _api.py
│       │       │   ├── _async/
│       │       │   │   ├── connection.py
│       │       │   │   ├── connection_pool.py
│       │       │   │   ├── http11.py
│       │       │   │   ├── http2.py
│       │       │   │   ├── http_proxy.py
│       │       │   │   ├── interfaces.py
│       │       │   │   ├── socks_proxy.py
│       │       │   │   └── __init__.py
│       │       │   ├── _backends/
│       │       │   │   ├── anyio.py
│       │       │   │   ├── auto.py
│       │       │   │   ├── base.py
│       │       │   │   ├── mock.py
│       │       │   │   ├── sync.py
│       │       │   │   ├── trio.py
│       │       │   │   └── __init__.py
│       │       │   ├── _exceptions.py
│       │       │   ├── _models.py
│       │       │   ├── _ssl.py
│       │       │   ├── _sync/
│       │       │   │   ├── connection.py
│       │       │   │   ├── connection_pool.py
│       │       │   │   ├── http11.py
│       │       │   │   ├── http2.py
│       │       │   │   ├── http_proxy.py
│       │       │   │   ├── interfaces.py
│       │       │   │   ├── socks_proxy.py
│       │       │   │   └── __init__.py
│       │       │   ├── _synchronization.py
│       │       │   ├── _trace.py
│       │       │   ├── _utils.py
│       │       │   └── __init__.py
│       │       ├── httpcore-1.0.9.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.md
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── httptools/
│       │       │   ├── parser/
│       │       │   │   ├── cparser.pxd
│       │       │   │   ├── errors.py
│       │       │   │   ├── parser.cp312-win_amd64.pyd
│       │       │   │   ├── parser.pyx
│       │       │   │   ├── python.pxd
│       │       │   │   ├── url_cparser.pxd
│       │       │   │   ├── url_parser.cp312-win_amd64.pyd
│       │       │   │   ├── url_parser.pyx
│       │       │   │   └── __init__.py
│       │       │   ├── _version.py
│       │       │   └── __init__.py
│       │       ├── httptools-0.6.4.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── httpx/
│       │       │   ├── py.typed
│       │       │   ├── _api.py
│       │       │   ├── _auth.py
│       │       │   ├── _client.py
│       │       │   ├── _config.py
│       │       │   ├── _content.py
│       │       │   ├── _decoders.py
│       │       │   ├── _exceptions.py
│       │       │   ├── _main.py
│       │       │   ├── _models.py
│       │       │   ├── _multipart.py
│       │       │   ├── _status_codes.py
│       │       │   ├── _transports/
│       │       │   │   ├── asgi.py
│       │       │   │   ├── base.py
│       │       │   │   ├── default.py
│       │       │   │   ├── mock.py
│       │       │   │   ├── wsgi.py
│       │       │   │   └── __init__.py
│       │       │   ├── _types.py
│       │       │   ├── _urlparse.py
│       │       │   ├── _urls.py
│       │       │   ├── _utils.py
│       │       │   ├── __init__.py
│       │       │   └── __version__.py
│       │       ├── httpx-0.28.1.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.md
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   └── WHEEL
│       │       ├── idna/
│       │       │   ├── codec.py
│       │       │   ├── compat.py
│       │       │   ├── core.py
│       │       │   ├── idnadata.py
│       │       │   ├── intranges.py
│       │       │   ├── package_data.py
│       │       │   ├── py.typed
│       │       │   ├── uts46data.py
│       │       │   └── __init__.py
│       │       ├── idna-3.10.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE.md
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── joblib/
│       │       │   ├── backports.py
│       │       │   ├── compressor.py
│       │       │   ├── disk.py
│       │       │   ├── executor.py
│       │       │   ├── externals/
│       │       │   │   ├── cloudpickle/
│       │       │   │   │   ├── cloudpickle.py
│       │       │   │   │   ├── cloudpickle_fast.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── loky/
│       │       │   │   │   ├── backend/
│       │       │   │   │   │   ├── context.py
│       │       │   │   │   │   ├── fork_exec.py
│       │       │   │   │   │   ├── popen_loky_posix.py
│       │       │   │   │   │   ├── popen_loky_win32.py
│       │       │   │   │   │   ├── process.py
│       │       │   │   │   │   ├── queues.py
│       │       │   │   │   │   ├── reduction.py
│       │       │   │   │   │   ├── resource_tracker.py
│       │       │   │   │   │   ├── spawn.py
│       │       │   │   │   │   ├── synchronize.py
│       │       │   │   │   │   ├── utils.py
│       │       │   │   │   │   ├── _posix_reduction.py
│       │       │   │   │   │   ├── _win_reduction.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── cloudpickle_wrapper.py
│       │       │   │   │   ├── initializers.py
│       │       │   │   │   ├── process_executor.py
│       │       │   │   │   ├── reusable_executor.py
│       │       │   │   │   ├── _base.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── func_inspect.py
│       │       │   ├── hashing.py
│       │       │   ├── logger.py
│       │       │   ├── memory.py
│       │       │   ├── numpy_pickle.py
│       │       │   ├── numpy_pickle_compat.py
│       │       │   ├── numpy_pickle_utils.py
│       │       │   ├── parallel.py
│       │       │   ├── pool.py
│       │       │   ├── test/
│       │       │   │   ├── common.py
│       │       │   │   ├── data/
│       │       │   │   │   ├── create_numpy_pickle.py
│       │       │   │   │   ├── joblib_0.10.0_compressed_pickle_py27_np16.gz
│       │       │   │   │   ├── joblib_0.10.0_compressed_pickle_py27_np17.gz
│       │       │   │   │   ├── joblib_0.10.0_compressed_pickle_py33_np18.gz
│       │       │   │   │   ├── joblib_0.10.0_compressed_pickle_py34_np19.gz
│       │       │   │   │   ├── joblib_0.10.0_compressed_pickle_py35_np19.gz
│       │       │   │   │   ├── joblib_0.10.0_pickle_py27_np17.pkl
│       │       │   │   │   ├── joblib_0.10.0_pickle_py27_np17.pkl.bz2
│       │       │   │   │   ├── joblib_0.10.0_pickle_py27_np17.pkl.gzip
│       │       │   │   │   ├── joblib_0.10.0_pickle_py27_np17.pkl.lzma
│       │       │   │   │   ├── joblib_0.10.0_pickle_py27_np17.pkl.xz
│       │       │   │   │   ├── joblib_0.10.0_pickle_py33_np18.pkl
│       │       │   │   │   ├── joblib_0.10.0_pickle_py33_np18.pkl.bz2
│       │       │   │   │   ├── joblib_0.10.0_pickle_py33_np18.pkl.gzip
│       │       │   │   │   ├── joblib_0.10.0_pickle_py33_np18.pkl.lzma
│       │       │   │   │   ├── joblib_0.10.0_pickle_py33_np18.pkl.xz
│       │       │   │   │   ├── joblib_0.10.0_pickle_py34_np19.pkl
│       │       │   │   │   ├── joblib_0.10.0_pickle_py34_np19.pkl.bz2
│       │       │   │   │   ├── joblib_0.10.0_pickle_py34_np19.pkl.gzip
│       │       │   │   │   ├── joblib_0.10.0_pickle_py34_np19.pkl.lzma
│       │       │   │   │   ├── joblib_0.10.0_pickle_py34_np19.pkl.xz
│       │       │   │   │   ├── joblib_0.10.0_pickle_py35_np19.pkl
│       │       │   │   │   ├── joblib_0.10.0_pickle_py35_np19.pkl.bz2
│       │       │   │   │   ├── joblib_0.10.0_pickle_py35_np19.pkl.gzip
│       │       │   │   │   ├── joblib_0.10.0_pickle_py35_np19.pkl.lzma
│       │       │   │   │   ├── joblib_0.10.0_pickle_py35_np19.pkl.xz
│       │       │   │   │   ├── joblib_0.11.0_compressed_pickle_py36_np111.gz
│       │       │   │   │   ├── joblib_0.11.0_pickle_py36_np111.pkl
│       │       │   │   │   ├── joblib_0.11.0_pickle_py36_np111.pkl.bz2
│       │       │   │   │   ├── joblib_0.11.0_pickle_py36_np111.pkl.gzip
│       │       │   │   │   ├── joblib_0.11.0_pickle_py36_np111.pkl.lzma
│       │       │   │   │   ├── joblib_0.11.0_pickle_py36_np111.pkl.xz
│       │       │   │   │   ├── joblib_0.8.4_compressed_pickle_py27_np17.gz
│       │       │   │   │   ├── joblib_0.9.2_compressed_pickle_py27_np16.gz
│       │       │   │   │   ├── joblib_0.9.2_compressed_pickle_py27_np17.gz
│       │       │   │   │   ├── joblib_0.9.2_compressed_pickle_py34_np19.gz
│       │       │   │   │   ├── joblib_0.9.2_compressed_pickle_py35_np19.gz
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np16.pkl
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np16.pkl_01.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np16.pkl_02.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np16.pkl_03.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np16.pkl_04.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np17.pkl
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np17.pkl_01.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np17.pkl_02.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np17.pkl_03.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py27_np17.pkl_04.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py33_np18.pkl
│       │       │   │   │   ├── joblib_0.9.2_pickle_py33_np18.pkl_01.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py33_np18.pkl_02.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py33_np18.pkl_03.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py33_np18.pkl_04.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py34_np19.pkl
│       │       │   │   │   ├── joblib_0.9.2_pickle_py34_np19.pkl_01.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py34_np19.pkl_02.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py34_np19.pkl_03.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py34_np19.pkl_04.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py35_np19.pkl
│       │       │   │   │   ├── joblib_0.9.2_pickle_py35_np19.pkl_01.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py35_np19.pkl_02.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py35_np19.pkl_03.npy
│       │       │   │   │   ├── joblib_0.9.2_pickle_py35_np19.pkl_04.npy
│       │       │   │   │   ├── joblib_0.9.4.dev0_compressed_cache_size_pickle_py35_np19.gz
│       │       │   │   │   ├── joblib_0.9.4.dev0_compressed_cache_size_pickle_py35_np19.gz_01.npy.z
│       │       │   │   │   ├── joblib_0.9.4.dev0_compressed_cache_size_pickle_py35_np19.gz_02.npy.z
│       │       │   │   │   ├── joblib_0.9.4.dev0_compressed_cache_size_pickle_py35_np19.gz_03.npy.z
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── testutils.py
│       │       │   │   ├── test_backports.py
│       │       │   │   ├── test_cloudpickle_wrapper.py
│       │       │   │   ├── test_config.py
│       │       │   │   ├── test_dask.py
│       │       │   │   ├── test_disk.py
│       │       │   │   ├── test_func_inspect.py
│       │       │   │   ├── test_func_inspect_special_encoding.py
│       │       │   │   ├── test_hashing.py
│       │       │   │   ├── test_init.py
│       │       │   │   ├── test_logger.py
│       │       │   │   ├── test_memmapping.py
│       │       │   │   ├── test_memory.py
│       │       │   │   ├── test_memory_async.py
│       │       │   │   ├── test_missing_multiprocessing.py
│       │       │   │   ├── test_module.py
│       │       │   │   ├── test_numpy_pickle.py
│       │       │   │   ├── test_numpy_pickle_compat.py
│       │       │   │   ├── test_numpy_pickle_utils.py
│       │       │   │   ├── test_parallel.py
│       │       │   │   ├── test_store_backends.py
│       │       │   │   ├── test_testing.py
│       │       │   │   ├── test_utils.py
│       │       │   │   └── __init__.py
│       │       │   ├── testing.py
│       │       │   ├── _cloudpickle_wrapper.py
│       │       │   ├── _dask.py
│       │       │   ├── _memmapping_reducer.py
│       │       │   ├── _multiprocessing_helpers.py
│       │       │   ├── _parallel_backends.py
│       │       │   ├── _store_backends.py
│       │       │   ├── _utils.py
│       │       │   └── __init__.py
│       │       ├── joblib-1.5.1.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── lightgbm/
│       │       │   ├── basic.py
│       │       │   ├── callback.py
│       │       │   ├── compat.py
│       │       │   ├── dask.py
│       │       │   ├── engine.py
│       │       │   ├── lib/
│       │       │   │   └── lib_lightgbm.lib
│       │       │   ├── libpath.py
│       │       │   ├── plotting.py
│       │       │   ├── py.typed
│       │       │   ├── sklearn.py
│       │       │   ├── VERSION.txt
│       │       │   └── __init__.py
│       │       ├── lightgbm-4.6.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   └── WHEEL
│       │       ├── numpy/
│       │       │   ├── char/
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── conftest.py
│       │       │   ├── core/
│       │       │   │   ├── arrayprint.py
│       │       │   │   ├── defchararray.py
│       │       │   │   ├── einsumfunc.py
│       │       │   │   ├── fromnumeric.py
│       │       │   │   ├── function_base.py
│       │       │   │   ├── getlimits.py
│       │       │   │   ├── multiarray.py
│       │       │   │   ├── numeric.py
│       │       │   │   ├── numerictypes.py
│       │       │   │   ├── overrides.py
│       │       │   │   ├── overrides.pyi
│       │       │   │   ├── records.py
│       │       │   │   ├── shape_base.py
│       │       │   │   ├── umath.py
│       │       │   │   ├── _dtype.py
│       │       │   │   ├── _dtype.pyi
│       │       │   │   ├── _dtype_ctypes.py
│       │       │   │   ├── _dtype_ctypes.pyi
│       │       │   │   ├── _internal.py
│       │       │   │   ├── _multiarray_umath.py
│       │       │   │   ├── _utils.py
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── ctypeslib/
│       │       │   │   ├── _ctypeslib.py
│       │       │   │   ├── _ctypeslib.pyi
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── doc/
│       │       │   │   └── ufuncs.py
│       │       │   ├── dtypes.py
│       │       │   ├── dtypes.pyi
│       │       │   ├── exceptions.py
│       │       │   ├── exceptions.pyi
│       │       │   ├── f2py/
│       │       │   │   ├── auxfuncs.py
│       │       │   │   ├── auxfuncs.pyi
│       │       │   │   ├── capi_maps.py
│       │       │   │   ├── capi_maps.pyi
│       │       │   │   ├── cb_rules.py
│       │       │   │   ├── cb_rules.pyi
│       │       │   │   ├── cfuncs.py
│       │       │   │   ├── cfuncs.pyi
│       │       │   │   ├── common_rules.py
│       │       │   │   ├── common_rules.pyi
│       │       │   │   ├── crackfortran.py
│       │       │   │   ├── crackfortran.pyi
│       │       │   │   ├── diagnose.py
│       │       │   │   ├── diagnose.pyi
│       │       │   │   ├── f2py2e.py
│       │       │   │   ├── f2py2e.pyi
│       │       │   │   ├── f90mod_rules.py
│       │       │   │   ├── f90mod_rules.pyi
│       │       │   │   ├── func2subr.py
│       │       │   │   ├── func2subr.pyi
│       │       │   │   ├── rules.py
│       │       │   │   ├── rules.pyi
│       │       │   │   ├── setup.cfg
│       │       │   │   ├── src/
│       │       │   │   │   ├── fortranobject.c
│       │       │   │   │   └── fortranobject.h
│       │       │   │   ├── symbolic.py
│       │       │   │   ├── symbolic.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── src/
│       │       │   │   │   │   ├── abstract_interface/
│       │       │   │   │   │   │   ├── foo.f90
│       │       │   │   │   │   │   └── gh18403_mod.f90
│       │       │   │   │   │   ├── array_from_pyobj/
│       │       │   │   │   │   │   └── wrapmodule.c
│       │       │   │   │   │   ├── assumed_shape/
│       │       │   │   │   │   │   ├── foo_free.f90
│       │       │   │   │   │   │   ├── foo_mod.f90
│       │       │   │   │   │   │   ├── foo_use.f90
│       │       │   │   │   │   │   └── precision.f90
│       │       │   │   │   │   ├── block_docstring/
│       │       │   │   │   │   │   └── foo.f
│       │       │   │   │   │   ├── callback/
│       │       │   │   │   │   │   ├── foo.f
│       │       │   │   │   │   │   ├── gh17797.f90
│       │       │   │   │   │   │   ├── gh18335.f90
│       │       │   │   │   │   │   ├── gh25211.f
│       │       │   │   │   │   │   ├── gh25211.pyf
│       │       │   │   │   │   │   └── gh26681.f90
│       │       │   │   │   │   ├── cli/
│       │       │   │   │   │   │   ├── gh_22819.pyf
│       │       │   │   │   │   │   ├── hi77.f
│       │       │   │   │   │   │   └── hiworld.f90
│       │       │   │   │   │   ├── common/
│       │       │   │   │   │   │   ├── block.f
│       │       │   │   │   │   │   └── gh19161.f90
│       │       │   │   │   │   ├── crackfortran/
│       │       │   │   │   │   │   ├── accesstype.f90
│       │       │   │   │   │   │   ├── common_with_division.f
│       │       │   │   │   │   │   ├── data_common.f
│       │       │   │   │   │   │   ├── data_multiplier.f
│       │       │   │   │   │   │   ├── data_stmts.f90
│       │       │   │   │   │   │   ├── data_with_comments.f
│       │       │   │   │   │   │   ├── foo_deps.f90
│       │       │   │   │   │   │   ├── gh15035.f
│       │       │   │   │   │   │   ├── gh17859.f
│       │       │   │   │   │   │   ├── gh22648.pyf
│       │       │   │   │   │   │   ├── gh23533.f
│       │       │   │   │   │   │   ├── gh23598.f90
│       │       │   │   │   │   │   ├── gh23598Warn.f90
│       │       │   │   │   │   │   ├── gh23879.f90
│       │       │   │   │   │   │   ├── gh27697.f90
│       │       │   │   │   │   │   ├── gh2848.f90
│       │       │   │   │   │   │   ├── operators.f90
│       │       │   │   │   │   │   ├── privatemod.f90
│       │       │   │   │   │   │   ├── publicmod.f90
│       │       │   │   │   │   │   ├── pubprivmod.f90
│       │       │   │   │   │   │   └── unicode_comment.f90
│       │       │   │   │   │   ├── f2cmap/
│       │       │   │   │   │   │   └── isoFortranEnvMap.f90
│       │       │   │   │   │   ├── isocintrin/
│       │       │   │   │   │   │   └── isoCtests.f90
│       │       │   │   │   │   ├── kind/
│       │       │   │   │   │   │   └── foo.f90
│       │       │   │   │   │   ├── mixed/
│       │       │   │   │   │   │   ├── foo.f
│       │       │   │   │   │   │   ├── foo_fixed.f90
│       │       │   │   │   │   │   └── foo_free.f90
│       │       │   │   │   │   ├── modules/
│       │       │   │   │   │   │   ├── gh25337/
│       │       │   │   │   │   │   │   ├── data.f90
│       │       │   │   │   │   │   │   └── use_data.f90
│       │       │   │   │   │   │   ├── gh26920/
│       │       │   │   │   │   │   │   ├── two_mods_with_no_public_entities.f90
│       │       │   │   │   │   │   │   └── two_mods_with_one_public_routine.f90
│       │       │   │   │   │   │   ├── module_data_docstring.f90
│       │       │   │   │   │   │   └── use_modules.f90
│       │       │   │   │   │   ├── negative_bounds/
│       │       │   │   │   │   │   └── issue_20853.f90
│       │       │   │   │   │   ├── parameter/
│       │       │   │   │   │   │   ├── constant_array.f90
│       │       │   │   │   │   │   ├── constant_both.f90
│       │       │   │   │   │   │   ├── constant_compound.f90
│       │       │   │   │   │   │   ├── constant_integer.f90
│       │       │   │   │   │   │   ├── constant_non_compound.f90
│       │       │   │   │   │   │   └── constant_real.f90
│       │       │   │   │   │   ├── quoted_character/
│       │       │   │   │   │   │   └── foo.f
│       │       │   │   │   │   ├── regression/
│       │       │   │   │   │   │   ├── AB.inc
│       │       │   │   │   │   │   ├── assignOnlyModule.f90
│       │       │   │   │   │   │   ├── datonly.f90
│       │       │   │   │   │   │   ├── f77comments.f
│       │       │   │   │   │   │   ├── f77fixedform.f95
│       │       │   │   │   │   │   ├── f90continuation.f90
│       │       │   │   │   │   │   ├── incfile.f90
│       │       │   │   │   │   │   ├── inout.f90
│       │       │   │   │   │   │   ├── lower_f2py_fortran.f90
│       │       │   │   │   │   │   └── mod_derived_types.f90
│       │       │   │   │   │   ├── return_character/
│       │       │   │   │   │   │   ├── foo77.f
│       │       │   │   │   │   │   └── foo90.f90
│       │       │   │   │   │   ├── return_complex/
│       │       │   │   │   │   │   ├── foo77.f
│       │       │   │   │   │   │   └── foo90.f90
│       │       │   │   │   │   ├── return_integer/
│       │       │   │   │   │   │   ├── foo77.f
│       │       │   │   │   │   │   └── foo90.f90
│       │       │   │   │   │   ├── return_logical/
│       │       │   │   │   │   │   ├── foo77.f
│       │       │   │   │   │   │   └── foo90.f90
│       │       │   │   │   │   ├── return_real/
│       │       │   │   │   │   │   ├── foo77.f
│       │       │   │   │   │   │   └── foo90.f90
│       │       │   │   │   │   ├── routines/
│       │       │   │   │   │   │   ├── funcfortranname.f
│       │       │   │   │   │   │   ├── funcfortranname.pyf
│       │       │   │   │   │   │   ├── subrout.f
│       │       │   │   │   │   │   └── subrout.pyf
│       │       │   │   │   │   ├── size/
│       │       │   │   │   │   │   └── foo.f90
│       │       │   │   │   │   ├── string/
│       │       │   │   │   │   │   ├── char.f90
│       │       │   │   │   │   │   ├── fixed_string.f90
│       │       │   │   │   │   │   ├── gh24008.f
│       │       │   │   │   │   │   ├── gh24662.f90
│       │       │   │   │   │   │   ├── gh25286.f90
│       │       │   │   │   │   │   ├── gh25286.pyf
│       │       │   │   │   │   │   ├── gh25286_bc.pyf
│       │       │   │   │   │   │   ├── scalar_string.f90
│       │       │   │   │   │   │   └── string.f
│       │       │   │   │   │   └── value_attrspec/
│       │       │   │   │   │       └── gh21665.f90
│       │       │   │   │   ├── test_abstract_interface.py
│       │       │   │   │   ├── test_array_from_pyobj.py
│       │       │   │   │   ├── test_assumed_shape.py
│       │       │   │   │   ├── test_block_docstring.py
│       │       │   │   │   ├── test_callback.py
│       │       │   │   │   ├── test_character.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_crackfortran.py
│       │       │   │   │   ├── test_data.py
│       │       │   │   │   ├── test_docs.py
│       │       │   │   │   ├── test_f2cmap.py
│       │       │   │   │   ├── test_f2py2e.py
│       │       │   │   │   ├── test_isoc.py
│       │       │   │   │   ├── test_kind.py
│       │       │   │   │   ├── test_mixed.py
│       │       │   │   │   ├── test_modules.py
│       │       │   │   │   ├── test_parameter.py
│       │       │   │   │   ├── test_pyf_src.py
│       │       │   │   │   ├── test_quoted_character.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   ├── test_return_character.py
│       │       │   │   │   ├── test_return_complex.py
│       │       │   │   │   ├── test_return_integer.py
│       │       │   │   │   ├── test_return_logical.py
│       │       │   │   │   ├── test_return_real.py
│       │       │   │   │   ├── test_routines.py
│       │       │   │   │   ├── test_semicolon_split.py
│       │       │   │   │   ├── test_size.py
│       │       │   │   │   ├── test_string.py
│       │       │   │   │   ├── test_symbolic.py
│       │       │   │   │   ├── test_value_attrspec.py
│       │       │   │   │   ├── util.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── use_rules.py
│       │       │   │   ├── use_rules.pyi
│       │       │   │   ├── _backends/
│       │       │   │   │   ├── meson.build.template
│       │       │   │   │   ├── _backend.py
│       │       │   │   │   ├── _backend.pyi
│       │       │   │   │   ├── _distutils.py
│       │       │   │   │   ├── _distutils.pyi
│       │       │   │   │   ├── _meson.py
│       │       │   │   │   ├── _meson.pyi
│       │       │   │   │   ├── __init__.py
│       │       │   │   │   └── __init__.pyi
│       │       │   │   ├── _isocbind.py
│       │       │   │   ├── _isocbind.pyi
│       │       │   │   ├── _src_pyf.py
│       │       │   │   ├── _src_pyf.pyi
│       │       │   │   ├── __init__.py
│       │       │   │   ├── __init__.pyi
│       │       │   │   ├── __main__.py
│       │       │   │   ├── __version__.py
│       │       │   │   └── __version__.pyi
│       │       │   ├── fft/
│       │       │   │   ├── helper.py
│       │       │   │   ├── helper.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_helper.py
│       │       │   │   │   ├── test_pocketfft.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _helper.py
│       │       │   │   ├── _helper.pyi
│       │       │   │   ├── _pocketfft.py
│       │       │   │   ├── _pocketfft.pyi
│       │       │   │   ├── _pocketfft_umath.cp312-win_amd64.lib
│       │       │   │   ├── _pocketfft_umath.cp312-win_amd64.pyd
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── lib/
│       │       │   │   ├── array_utils.py
│       │       │   │   ├── array_utils.pyi
│       │       │   │   ├── format.py
│       │       │   │   ├── format.pyi
│       │       │   │   ├── introspect.py
│       │       │   │   ├── introspect.pyi
│       │       │   │   ├── mixins.py
│       │       │   │   ├── mixins.pyi
│       │       │   │   ├── npyio.py
│       │       │   │   ├── npyio.pyi
│       │       │   │   ├── recfunctions.py
│       │       │   │   ├── recfunctions.pyi
│       │       │   │   ├── scimath.py
│       │       │   │   ├── scimath.pyi
│       │       │   │   ├── stride_tricks.py
│       │       │   │   ├── stride_tricks.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── py2-np0-objarr.npy
│       │       │   │   │   │   ├── py2-objarr.npy
│       │       │   │   │   │   ├── py2-objarr.npz
│       │       │   │   │   │   ├── py3-objarr.npy
│       │       │   │   │   │   ├── py3-objarr.npz
│       │       │   │   │   │   ├── python3.npy
│       │       │   │   │   │   └── win64python2.npy
│       │       │   │   │   ├── test_arraypad.py
│       │       │   │   │   ├── test_arraysetops.py
│       │       │   │   │   ├── test_arrayterator.py
│       │       │   │   │   ├── test_array_utils.py
│       │       │   │   │   ├── test_format.py
│       │       │   │   │   ├── test_function_base.py
│       │       │   │   │   ├── test_histograms.py
│       │       │   │   │   ├── test_index_tricks.py
│       │       │   │   │   ├── test_io.py
│       │       │   │   │   ├── test_loadtxt.py
│       │       │   │   │   ├── test_mixins.py
│       │       │   │   │   ├── test_nanfunctions.py
│       │       │   │   │   ├── test_packbits.py
│       │       │   │   │   ├── test_polynomial.py
│       │       │   │   │   ├── test_recfunctions.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   ├── test_shape_base.py
│       │       │   │   │   ├── test_stride_tricks.py
│       │       │   │   │   ├── test_twodim_base.py
│       │       │   │   │   ├── test_type_check.py
│       │       │   │   │   ├── test_ufunclike.py
│       │       │   │   │   ├── test_utils.py
│       │       │   │   │   ├── test__datasource.py
│       │       │   │   │   ├── test__iotools.py
│       │       │   │   │   ├── test__version.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── user_array.py
│       │       │   │   ├── user_array.pyi
│       │       │   │   ├── _arraypad_impl.py
│       │       │   │   ├── _arraypad_impl.pyi
│       │       │   │   ├── _arraysetops_impl.py
│       │       │   │   ├── _arraysetops_impl.pyi
│       │       │   │   ├── _arrayterator_impl.py
│       │       │   │   ├── _arrayterator_impl.pyi
│       │       │   │   ├── _array_utils_impl.py
│       │       │   │   ├── _array_utils_impl.pyi
│       │       │   │   ├── _datasource.py
│       │       │   │   ├── _datasource.pyi
│       │       │   │   ├── _format_impl.py
│       │       │   │   ├── _format_impl.pyi
│       │       │   │   ├── _function_base_impl.py
│       │       │   │   ├── _function_base_impl.pyi
│       │       │   │   ├── _histograms_impl.py
│       │       │   │   ├── _histograms_impl.pyi
│       │       │   │   ├── _index_tricks_impl.py
│       │       │   │   ├── _index_tricks_impl.pyi
│       │       │   │   ├── _iotools.py
│       │       │   │   ├── _iotools.pyi
│       │       │   │   ├── _nanfunctions_impl.py
│       │       │   │   ├── _nanfunctions_impl.pyi
│       │       │   │   ├── _npyio_impl.py
│       │       │   │   ├── _npyio_impl.pyi
│       │       │   │   ├── _polynomial_impl.py
│       │       │   │   ├── _polynomial_impl.pyi
│       │       │   │   ├── _scimath_impl.py
│       │       │   │   ├── _scimath_impl.pyi
│       │       │   │   ├── _shape_base_impl.py
│       │       │   │   ├── _shape_base_impl.pyi
│       │       │   │   ├── _stride_tricks_impl.py
│       │       │   │   ├── _stride_tricks_impl.pyi
│       │       │   │   ├── _twodim_base_impl.py
│       │       │   │   ├── _twodim_base_impl.pyi
│       │       │   │   ├── _type_check_impl.py
│       │       │   │   ├── _type_check_impl.pyi
│       │       │   │   ├── _ufunclike_impl.py
│       │       │   │   ├── _ufunclike_impl.pyi
│       │       │   │   ├── _user_array_impl.py
│       │       │   │   ├── _user_array_impl.pyi
│       │       │   │   ├── _utils_impl.py
│       │       │   │   ├── _utils_impl.pyi
│       │       │   │   ├── _version.py
│       │       │   │   ├── _version.pyi
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── linalg/
│       │       │   │   ├── lapack_lite.cp312-win_amd64.lib
│       │       │   │   ├── lapack_lite.cp312-win_amd64.pyd
│       │       │   │   ├── lapack_lite.pyi
│       │       │   │   ├── linalg.py
│       │       │   │   ├── linalg.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_deprecations.py
│       │       │   │   │   ├── test_linalg.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _linalg.py
│       │       │   │   ├── _linalg.pyi
│       │       │   │   ├── _umath_linalg.cp312-win_amd64.lib
│       │       │   │   ├── _umath_linalg.cp312-win_amd64.pyd
│       │       │   │   ├── _umath_linalg.pyi
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── ma/
│       │       │   │   ├── API_CHANGES.txt
│       │       │   │   ├── core.py
│       │       │   │   ├── core.pyi
│       │       │   │   ├── extras.py
│       │       │   │   ├── extras.pyi
│       │       │   │   ├── LICENSE
│       │       │   │   ├── mrecords.py
│       │       │   │   ├── mrecords.pyi
│       │       │   │   ├── README.rst
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_arrayobject.py
│       │       │   │   │   ├── test_core.py
│       │       │   │   │   ├── test_deprecations.py
│       │       │   │   │   ├── test_extras.py
│       │       │   │   │   ├── test_mrecords.py
│       │       │   │   │   ├── test_old_ma.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   ├── test_subclassing.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── testutils.py
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── matlib.py
│       │       │   ├── matlib.pyi
│       │       │   ├── matrixlib/
│       │       │   │   ├── defmatrix.py
│       │       │   │   ├── defmatrix.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_defmatrix.py
│       │       │   │   │   ├── test_interaction.py
│       │       │   │   │   ├── test_masked_matrix.py
│       │       │   │   │   ├── test_matrix_linalg.py
│       │       │   │   │   ├── test_multiarray.py
│       │       │   │   │   ├── test_numeric.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── polynomial/
│       │       │   │   ├── chebyshev.py
│       │       │   │   ├── chebyshev.pyi
│       │       │   │   ├── hermite.py
│       │       │   │   ├── hermite.pyi
│       │       │   │   ├── hermite_e.py
│       │       │   │   ├── hermite_e.pyi
│       │       │   │   ├── laguerre.py
│       │       │   │   ├── laguerre.pyi
│       │       │   │   ├── legendre.py
│       │       │   │   ├── legendre.pyi
│       │       │   │   ├── polynomial.py
│       │       │   │   ├── polynomial.pyi
│       │       │   │   ├── polyutils.py
│       │       │   │   ├── polyutils.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_chebyshev.py
│       │       │   │   │   ├── test_classes.py
│       │       │   │   │   ├── test_hermite.py
│       │       │   │   │   ├── test_hermite_e.py
│       │       │   │   │   ├── test_laguerre.py
│       │       │   │   │   ├── test_legendre.py
│       │       │   │   │   ├── test_polynomial.py
│       │       │   │   │   ├── test_polyutils.py
│       │       │   │   │   ├── test_printing.py
│       │       │   │   │   ├── test_symbol.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _polybase.py
│       │       │   │   ├── _polybase.pyi
│       │       │   │   ├── _polytypes.pyi
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── py.typed
│       │       │   ├── random/
│       │       │   │   ├── bit_generator.cp312-win_amd64.lib
│       │       │   │   ├── bit_generator.cp312-win_amd64.pyd
│       │       │   │   ├── bit_generator.pxd
│       │       │   │   ├── bit_generator.pyi
│       │       │   │   ├── c_distributions.pxd
│       │       │   │   ├── lib/
│       │       │   │   │   └── npyrandom.lib
│       │       │   │   ├── LICENSE.md
│       │       │   │   ├── mtrand.cp312-win_amd64.lib
│       │       │   │   ├── mtrand.cp312-win_amd64.pyd
│       │       │   │   ├── mtrand.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── generator_pcg64_np121.pkl.gz
│       │       │   │   │   │   ├── generator_pcg64_np126.pkl.gz
│       │       │   │   │   │   ├── mt19937-testset-1.csv
│       │       │   │   │   │   ├── mt19937-testset-2.csv
│       │       │   │   │   │   ├── pcg64-testset-1.csv
│       │       │   │   │   │   ├── pcg64-testset-2.csv
│       │       │   │   │   │   ├── pcg64dxsm-testset-1.csv
│       │       │   │   │   │   ├── pcg64dxsm-testset-2.csv
│       │       │   │   │   │   ├── philox-testset-1.csv
│       │       │   │   │   │   ├── philox-testset-2.csv
│       │       │   │   │   │   ├── sfc64-testset-1.csv
│       │       │   │   │   │   ├── sfc64-testset-2.csv
│       │       │   │   │   │   ├── sfc64_np126.pkl.gz
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_direct.py
│       │       │   │   │   ├── test_extending.py
│       │       │   │   │   ├── test_generator_mt19937.py
│       │       │   │   │   ├── test_generator_mt19937_regressions.py
│       │       │   │   │   ├── test_random.py
│       │       │   │   │   ├── test_randomstate.py
│       │       │   │   │   ├── test_randomstate_regression.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   ├── test_seed_sequence.py
│       │       │   │   │   ├── test_smoke.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _bounded_integers.cp312-win_amd64.lib
│       │       │   │   ├── _bounded_integers.cp312-win_amd64.pyd
│       │       │   │   ├── _bounded_integers.pxd
│       │       │   │   ├── _bounded_integers.pyi
│       │       │   │   ├── _common.cp312-win_amd64.lib
│       │       │   │   ├── _common.cp312-win_amd64.pyd
│       │       │   │   ├── _common.pxd
│       │       │   │   ├── _common.pyi
│       │       │   │   ├── _examples/
│       │       │   │   │   ├── cffi/
│       │       │   │   │   │   ├── extending.py
│       │       │   │   │   │   └── parse.py
│       │       │   │   │   ├── cython/
│       │       │   │   │   │   ├── extending.pyx
│       │       │   │   │   │   ├── extending_distributions.pyx
│       │       │   │   │   │   └── meson.build
│       │       │   │   │   └── numba/
│       │       │   │   │       ├── extending.py
│       │       │   │   │       └── extending_distributions.py
│       │       │   │   ├── _generator.cp312-win_amd64.lib
│       │       │   │   ├── _generator.cp312-win_amd64.pyd
│       │       │   │   ├── _generator.pyi
│       │       │   │   ├── _mt19937.cp312-win_amd64.lib
│       │       │   │   ├── _mt19937.cp312-win_amd64.pyd
│       │       │   │   ├── _mt19937.pyi
│       │       │   │   ├── _pcg64.cp312-win_amd64.lib
│       │       │   │   ├── _pcg64.cp312-win_amd64.pyd
│       │       │   │   ├── _pcg64.pyi
│       │       │   │   ├── _philox.cp312-win_amd64.lib
│       │       │   │   ├── _philox.cp312-win_amd64.pyd
│       │       │   │   ├── _philox.pyi
│       │       │   │   ├── _pickle.py
│       │       │   │   ├── _pickle.pyi
│       │       │   │   ├── _sfc64.cp312-win_amd64.lib
│       │       │   │   ├── _sfc64.cp312-win_amd64.pyd
│       │       │   │   ├── _sfc64.pyi
│       │       │   │   ├── __init__.pxd
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── rec/
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── strings/
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── testing/
│       │       │   │   ├── overrides.py
│       │       │   │   ├── overrides.pyi
│       │       │   │   ├── print_coercion_tables.py
│       │       │   │   ├── print_coercion_tables.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_utils.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _private/
│       │       │   │   │   ├── extbuild.py
│       │       │   │   │   ├── extbuild.pyi
│       │       │   │   │   ├── utils.py
│       │       │   │   │   ├── utils.pyi
│       │       │   │   │   ├── __init__.py
│       │       │   │   │   └── __init__.pyi
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── tests/
│       │       │   │   ├── test_configtool.py
│       │       │   │   ├── test_ctypeslib.py
│       │       │   │   ├── test_lazyloading.py
│       │       │   │   ├── test_matlib.py
│       │       │   │   ├── test_numpy_config.py
│       │       │   │   ├── test_numpy_version.py
│       │       │   │   ├── test_public_api.py
│       │       │   │   ├── test_reloading.py
│       │       │   │   ├── test_scripts.py
│       │       │   │   ├── test_warnings.py
│       │       │   │   ├── test__all__.py
│       │       │   │   └── __init__.py
│       │       │   ├── typing/
│       │       │   │   ├── mypy_plugin.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── fail/
│       │       │   │   │   │   │   ├── arithmetic.pyi
│       │       │   │   │   │   │   ├── arrayprint.pyi
│       │       │   │   │   │   │   ├── arrayterator.pyi
│       │       │   │   │   │   │   ├── array_constructors.pyi
│       │       │   │   │   │   │   ├── array_like.pyi
│       │       │   │   │   │   │   ├── array_pad.pyi
│       │       │   │   │   │   │   ├── bitwise_ops.pyi
│       │       │   │   │   │   │   ├── char.pyi
│       │       │   │   │   │   │   ├── chararray.pyi
│       │       │   │   │   │   │   ├── comparisons.pyi
│       │       │   │   │   │   │   ├── constants.pyi
│       │       │   │   │   │   │   ├── datasource.pyi
│       │       │   │   │   │   │   ├── dtype.pyi
│       │       │   │   │   │   │   ├── einsumfunc.pyi
│       │       │   │   │   │   │   ├── flatiter.pyi
│       │       │   │   │   │   │   ├── fromnumeric.pyi
│       │       │   │   │   │   │   ├── histograms.pyi
│       │       │   │   │   │   │   ├── index_tricks.pyi
│       │       │   │   │   │   │   ├── lib_function_base.pyi
│       │       │   │   │   │   │   ├── lib_polynomial.pyi
│       │       │   │   │   │   │   ├── lib_utils.pyi
│       │       │   │   │   │   │   ├── lib_version.pyi
│       │       │   │   │   │   │   ├── linalg.pyi
│       │       │   │   │   │   │   ├── ma.pyi
│       │       │   │   │   │   │   ├── memmap.pyi
│       │       │   │   │   │   │   ├── modules.pyi
│       │       │   │   │   │   │   ├── multiarray.pyi
│       │       │   │   │   │   │   ├── ndarray.pyi
│       │       │   │   │   │   │   ├── ndarray_misc.pyi
│       │       │   │   │   │   │   ├── nditer.pyi
│       │       │   │   │   │   │   ├── nested_sequence.pyi
│       │       │   │   │   │   │   ├── npyio.pyi
│       │       │   │   │   │   │   ├── numerictypes.pyi
│       │       │   │   │   │   │   ├── random.pyi
│       │       │   │   │   │   │   ├── rec.pyi
│       │       │   │   │   │   │   ├── scalars.pyi
│       │       │   │   │   │   │   ├── shape.pyi
│       │       │   │   │   │   │   ├── shape_base.pyi
│       │       │   │   │   │   │   ├── stride_tricks.pyi
│       │       │   │   │   │   │   ├── strings.pyi
│       │       │   │   │   │   │   ├── testing.pyi
│       │       │   │   │   │   │   ├── twodim_base.pyi
│       │       │   │   │   │   │   ├── type_check.pyi
│       │       │   │   │   │   │   ├── ufunclike.pyi
│       │       │   │   │   │   │   ├── ufuncs.pyi
│       │       │   │   │   │   │   ├── ufunc_config.pyi
│       │       │   │   │   │   │   └── warnings_and_errors.pyi
│       │       │   │   │   │   ├── misc/
│       │       │   │   │   │   │   └── extended_precision.pyi
│       │       │   │   │   │   ├── mypy.ini
│       │       │   │   │   │   ├── pass/
│       │       │   │   │   │   │   ├── arithmetic.py
│       │       │   │   │   │   │   ├── arrayprint.py
│       │       │   │   │   │   │   ├── arrayterator.py
│       │       │   │   │   │   │   ├── array_constructors.py
│       │       │   │   │   │   │   ├── array_like.py
│       │       │   │   │   │   │   ├── bitwise_ops.py
│       │       │   │   │   │   │   ├── comparisons.py
│       │       │   │   │   │   │   ├── dtype.py
│       │       │   │   │   │   │   ├── einsumfunc.py
│       │       │   │   │   │   │   ├── flatiter.py
│       │       │   │   │   │   │   ├── fromnumeric.py
│       │       │   │   │   │   │   ├── index_tricks.py
│       │       │   │   │   │   │   ├── lib_user_array.py
│       │       │   │   │   │   │   ├── lib_utils.py
│       │       │   │   │   │   │   ├── lib_version.py
│       │       │   │   │   │   │   ├── literal.py
│       │       │   │   │   │   │   ├── ma.py
│       │       │   │   │   │   │   ├── mod.py
│       │       │   │   │   │   │   ├── modules.py
│       │       │   │   │   │   │   ├── multiarray.py
│       │       │   │   │   │   │   ├── ndarray_conversion.py
│       │       │   │   │   │   │   ├── ndarray_misc.py
│       │       │   │   │   │   │   ├── ndarray_shape_manipulation.py
│       │       │   │   │   │   │   ├── nditer.py
│       │       │   │   │   │   │   ├── numeric.py
│       │       │   │   │   │   │   ├── numerictypes.py
│       │       │   │   │   │   │   ├── random.py
│       │       │   │   │   │   │   ├── recfunctions.py
│       │       │   │   │   │   │   ├── scalars.py
│       │       │   │   │   │   │   ├── shape.py
│       │       │   │   │   │   │   ├── simple.py
│       │       │   │   │   │   │   ├── simple_py3.py
│       │       │   │   │   │   │   ├── ufunclike.py
│       │       │   │   │   │   │   ├── ufuncs.py
│       │       │   │   │   │   │   ├── ufunc_config.py
│       │       │   │   │   │   │   └── warnings_and_errors.py
│       │       │   │   │   │   └── reveal/
│       │       │   │   │   │       ├── arithmetic.pyi
│       │       │   │   │   │       ├── arraypad.pyi
│       │       │   │   │   │       ├── arrayprint.pyi
│       │       │   │   │   │       ├── arraysetops.pyi
│       │       │   │   │   │       ├── arrayterator.pyi
│       │       │   │   │   │       ├── array_api_info.pyi
│       │       │   │   │   │       ├── array_constructors.pyi
│       │       │   │   │   │       ├── bitwise_ops.pyi
│       │       │   │   │   │       ├── char.pyi
│       │       │   │   │   │       ├── chararray.pyi
│       │       │   │   │   │       ├── comparisons.pyi
│       │       │   │   │   │       ├── constants.pyi
│       │       │   │   │   │       ├── ctypeslib.pyi
│       │       │   │   │   │       ├── datasource.pyi
│       │       │   │   │   │       ├── dtype.pyi
│       │       │   │   │   │       ├── einsumfunc.pyi
│       │       │   │   │   │       ├── emath.pyi
│       │       │   │   │   │       ├── fft.pyi
│       │       │   │   │   │       ├── flatiter.pyi
│       │       │   │   │   │       ├── fromnumeric.pyi
│       │       │   │   │   │       ├── getlimits.pyi
│       │       │   │   │   │       ├── histograms.pyi
│       │       │   │   │   │       ├── index_tricks.pyi
│       │       │   │   │   │       ├── lib_function_base.pyi
│       │       │   │   │   │       ├── lib_polynomial.pyi
│       │       │   │   │   │       ├── lib_utils.pyi
│       │       │   │   │   │       ├── lib_version.pyi
│       │       │   │   │   │       ├── linalg.pyi
│       │       │   │   │   │       ├── ma.pyi
│       │       │   │   │   │       ├── matrix.pyi
│       │       │   │   │   │       ├── memmap.pyi
│       │       │   │   │   │       ├── mod.pyi
│       │       │   │   │   │       ├── modules.pyi
│       │       │   │   │   │       ├── multiarray.pyi
│       │       │   │   │   │       ├── nbit_base_example.pyi
│       │       │   │   │   │       ├── ndarray_assignability.pyi
│       │       │   │   │   │       ├── ndarray_conversion.pyi
│       │       │   │   │   │       ├── ndarray_misc.pyi
│       │       │   │   │   │       ├── ndarray_shape_manipulation.pyi
│       │       │   │   │   │       ├── nditer.pyi
│       │       │   │   │   │       ├── nested_sequence.pyi
│       │       │   │   │   │       ├── npyio.pyi
│       │       │   │   │   │       ├── numeric.pyi
│       │       │   │   │   │       ├── numerictypes.pyi
│       │       │   │   │   │       ├── polynomial_polybase.pyi
│       │       │   │   │   │       ├── polynomial_polyutils.pyi
│       │       │   │   │   │       ├── polynomial_series.pyi
│       │       │   │   │   │       ├── random.pyi
│       │       │   │   │   │       ├── rec.pyi
│       │       │   │   │   │       ├── scalars.pyi
│       │       │   │   │   │       ├── shape.pyi
│       │       │   │   │   │       ├── shape_base.pyi
│       │       │   │   │   │       ├── stride_tricks.pyi
│       │       │   │   │   │       ├── strings.pyi
│       │       │   │   │   │       ├── testing.pyi
│       │       │   │   │   │       ├── twodim_base.pyi
│       │       │   │   │   │       ├── type_check.pyi
│       │       │   │   │   │       ├── ufunclike.pyi
│       │       │   │   │   │       ├── ufuncs.pyi
│       │       │   │   │   │       ├── ufunc_config.pyi
│       │       │   │   │   │       └── warnings_and_errors.pyi
│       │       │   │   │   ├── test_isfile.py
│       │       │   │   │   ├── test_runtime.py
│       │       │   │   │   ├── test_typing.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── version.py
│       │       │   ├── version.pyi
│       │       │   ├── _array_api_info.py
│       │       │   ├── _array_api_info.pyi
│       │       │   ├── _configtool.py
│       │       │   ├── _configtool.pyi
│       │       │   ├── _core/
│       │       │   │   ├── arrayprint.py
│       │       │   │   ├── arrayprint.pyi
│       │       │   │   ├── cversions.py
│       │       │   │   ├── defchararray.py
│       │       │   │   ├── defchararray.pyi
│       │       │   │   ├── einsumfunc.py
│       │       │   │   ├── einsumfunc.pyi
│       │       │   │   ├── fromnumeric.py
│       │       │   │   ├── fromnumeric.pyi
│       │       │   │   ├── function_base.py
│       │       │   │   ├── function_base.pyi
│       │       │   │   ├── getlimits.py
│       │       │   │   ├── getlimits.pyi
│       │       │   │   ├── include/
│       │       │   │   │   └── numpy/
│       │       │   │   │       ├── arrayobject.h
│       │       │   │   │       ├── arrayscalars.h
│       │       │   │   │       ├── dtype_api.h
│       │       │   │   │       ├── halffloat.h
│       │       │   │   │       ├── ndarrayobject.h
│       │       │   │   │       ├── ndarraytypes.h
│       │       │   │   │       ├── npy_2_compat.h
│       │       │   │   │       ├── npy_2_complexcompat.h
│       │       │   │   │       ├── npy_3kcompat.h
│       │       │   │   │       ├── npy_common.h
│       │       │   │   │       ├── npy_cpu.h
│       │       │   │   │       ├── npy_endian.h
│       │       │   │   │       ├── npy_math.h
│       │       │   │   │       ├── npy_no_deprecated_api.h
│       │       │   │   │       ├── npy_os.h
│       │       │   │   │       ├── numpyconfig.h
│       │       │   │   │       ├── random/
│       │       │   │   │       │   ├── bitgen.h
│       │       │   │   │       │   ├── distributions.h
│       │       │   │   │       │   ├── libdivide.h
│       │       │   │   │       │   └── LICENSE.txt
│       │       │   │   │       ├── ufuncobject.h
│       │       │   │   │       ├── utils.h
│       │       │   │   │       ├── _neighborhood_iterator_imp.h
│       │       │   │   │       ├── _numpyconfig.h
│       │       │   │   │       ├── _public_dtype_api_table.h
│       │       │   │   │       ├── __multiarray_api.c
│       │       │   │   │       ├── __multiarray_api.h
│       │       │   │   │       ├── __ufunc_api.c
│       │       │   │   │       └── __ufunc_api.h
│       │       │   │   ├── lib/
│       │       │   │   │   ├── npy-pkg-config/
│       │       │   │   │   │   ├── mlib.ini
│       │       │   │   │   │   └── npymath.ini
│       │       │   │   │   ├── npymath.lib
│       │       │   │   │   └── pkgconfig/
│       │       │   │   │       └── numpy.pc
│       │       │   │   ├── memmap.py
│       │       │   │   ├── memmap.pyi
│       │       │   │   ├── multiarray.py
│       │       │   │   ├── multiarray.pyi
│       │       │   │   ├── numeric.py
│       │       │   │   ├── numeric.pyi
│       │       │   │   ├── numerictypes.py
│       │       │   │   ├── numerictypes.pyi
│       │       │   │   ├── overrides.py
│       │       │   │   ├── overrides.pyi
│       │       │   │   ├── printoptions.py
│       │       │   │   ├── printoptions.pyi
│       │       │   │   ├── records.py
│       │       │   │   ├── records.pyi
│       │       │   │   ├── shape_base.py
│       │       │   │   ├── shape_base.pyi
│       │       │   │   ├── strings.py
│       │       │   │   ├── strings.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── astype_copy.pkl
│       │       │   │   │   │   ├── generate_umath_validation_data.cpp
│       │       │   │   │   │   ├── recarray_from_file.fits
│       │       │   │   │   │   ├── umath-validation-set-arccos.csv
│       │       │   │   │   │   ├── umath-validation-set-arccosh.csv
│       │       │   │   │   │   ├── umath-validation-set-arcsin.csv
│       │       │   │   │   │   ├── umath-validation-set-arcsinh.csv
│       │       │   │   │   │   ├── umath-validation-set-arctan.csv
│       │       │   │   │   │   ├── umath-validation-set-arctanh.csv
│       │       │   │   │   │   ├── umath-validation-set-cbrt.csv
│       │       │   │   │   │   ├── umath-validation-set-cos.csv
│       │       │   │   │   │   ├── umath-validation-set-cosh.csv
│       │       │   │   │   │   ├── umath-validation-set-exp.csv
│       │       │   │   │   │   ├── umath-validation-set-exp2.csv
│       │       │   │   │   │   ├── umath-validation-set-expm1.csv
│       │       │   │   │   │   ├── umath-validation-set-log.csv
│       │       │   │   │   │   ├── umath-validation-set-log10.csv
│       │       │   │   │   │   ├── umath-validation-set-log1p.csv
│       │       │   │   │   │   ├── umath-validation-set-log2.csv
│       │       │   │   │   │   ├── umath-validation-set-README.txt
│       │       │   │   │   │   ├── umath-validation-set-sin.csv
│       │       │   │   │   │   ├── umath-validation-set-sinh.csv
│       │       │   │   │   │   ├── umath-validation-set-tan.csv
│       │       │   │   │   │   └── umath-validation-set-tanh.csv
│       │       │   │   │   ├── examples/
│       │       │   │   │   │   ├── cython/
│       │       │   │   │   │   │   ├── checks.pyx
│       │       │   │   │   │   │   ├── meson.build
│       │       │   │   │   │   │   └── setup.py
│       │       │   │   │   │   └── limited_api/
│       │       │   │   │   │       ├── limited_api1.c
│       │       │   │   │   │       ├── limited_api2.pyx
│       │       │   │   │   │       ├── limited_api_latest.c
│       │       │   │   │   │       ├── meson.build
│       │       │   │   │   │       └── setup.py
│       │       │   │   │   ├── test_abc.py
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_argparse.py
│       │       │   │   │   ├── test_arraymethod.py
│       │       │   │   │   ├── test_arrayobject.py
│       │       │   │   │   ├── test_arrayprint.py
│       │       │   │   │   ├── test_array_api_info.py
│       │       │   │   │   ├── test_array_coercion.py
│       │       │   │   │   ├── test_array_interface.py
│       │       │   │   │   ├── test_casting_floatingpoint_errors.py
│       │       │   │   │   ├── test_casting_unittests.py
│       │       │   │   │   ├── test_conversion_utils.py
│       │       │   │   │   ├── test_cpu_dispatcher.py
│       │       │   │   │   ├── test_cpu_features.py
│       │       │   │   │   ├── test_custom_dtypes.py
│       │       │   │   │   ├── test_cython.py
│       │       │   │   │   ├── test_datetime.py
│       │       │   │   │   ├── test_defchararray.py
│       │       │   │   │   ├── test_deprecations.py
│       │       │   │   │   ├── test_dlpack.py
│       │       │   │   │   ├── test_dtype.py
│       │       │   │   │   ├── test_einsum.py
│       │       │   │   │   ├── test_errstate.py
│       │       │   │   │   ├── test_extint128.py
│       │       │   │   │   ├── test_function_base.py
│       │       │   │   │   ├── test_getlimits.py
│       │       │   │   │   ├── test_half.py
│       │       │   │   │   ├── test_hashtable.py
│       │       │   │   │   ├── test_indexerrors.py
│       │       │   │   │   ├── test_indexing.py
│       │       │   │   │   ├── test_item_selection.py
│       │       │   │   │   ├── test_limited_api.py
│       │       │   │   │   ├── test_longdouble.py
│       │       │   │   │   ├── test_machar.py
│       │       │   │   │   ├── test_memmap.py
│       │       │   │   │   ├── test_mem_overlap.py
│       │       │   │   │   ├── test_mem_policy.py
│       │       │   │   │   ├── test_multiarray.py
│       │       │   │   │   ├── test_multithreading.py
│       │       │   │   │   ├── test_nditer.py
│       │       │   │   │   ├── test_nep50_promotions.py
│       │       │   │   │   ├── test_numeric.py
│       │       │   │   │   ├── test_numerictypes.py
│       │       │   │   │   ├── test_overrides.py
│       │       │   │   │   ├── test_print.py
│       │       │   │   │   ├── test_protocols.py
│       │       │   │   │   ├── test_records.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   ├── test_scalarbuffer.py
│       │       │   │   │   ├── test_scalarinherit.py
│       │       │   │   │   ├── test_scalarmath.py
│       │       │   │   │   ├── test_scalarprint.py
│       │       │   │   │   ├── test_scalar_ctors.py
│       │       │   │   │   ├── test_scalar_methods.py
│       │       │   │   │   ├── test_shape_base.py
│       │       │   │   │   ├── test_simd.py
│       │       │   │   │   ├── test_simd_module.py
│       │       │   │   │   ├── test_stringdtype.py
│       │       │   │   │   ├── test_strings.py
│       │       │   │   │   ├── test_ufunc.py
│       │       │   │   │   ├── test_umath.py
│       │       │   │   │   ├── test_umath_accuracy.py
│       │       │   │   │   ├── test_umath_complex.py
│       │       │   │   │   ├── test_unicode.py
│       │       │   │   │   ├── test__exceptions.py
│       │       │   │   │   ├── _locales.py
│       │       │   │   │   └── _natype.py
│       │       │   │   ├── umath.py
│       │       │   │   ├── umath.pyi
│       │       │   │   ├── _add_newdocs.py
│       │       │   │   ├── _add_newdocs.pyi
│       │       │   │   ├── _add_newdocs_scalars.py
│       │       │   │   ├── _add_newdocs_scalars.pyi
│       │       │   │   ├── _asarray.py
│       │       │   │   ├── _asarray.pyi
│       │       │   │   ├── _dtype.py
│       │       │   │   ├── _dtype.pyi
│       │       │   │   ├── _dtype_ctypes.py
│       │       │   │   ├── _dtype_ctypes.pyi
│       │       │   │   ├── _exceptions.py
│       │       │   │   ├── _exceptions.pyi
│       │       │   │   ├── _internal.py
│       │       │   │   ├── _internal.pyi
│       │       │   │   ├── _machar.py
│       │       │   │   ├── _machar.pyi
│       │       │   │   ├── _methods.py
│       │       │   │   ├── _methods.pyi
│       │       │   │   ├── _multiarray_tests.cp312-win_amd64.lib
│       │       │   │   ├── _multiarray_tests.cp312-win_amd64.pyd
│       │       │   │   ├── _multiarray_umath.cp312-win_amd64.lib
│       │       │   │   ├── _multiarray_umath.cp312-win_amd64.pyd
│       │       │   │   ├── _operand_flag_tests.cp312-win_amd64.lib
│       │       │   │   ├── _operand_flag_tests.cp312-win_amd64.pyd
│       │       │   │   ├── _rational_tests.cp312-win_amd64.lib
│       │       │   │   ├── _rational_tests.cp312-win_amd64.pyd
│       │       │   │   ├── _simd.cp312-win_amd64.lib
│       │       │   │   ├── _simd.cp312-win_amd64.pyd
│       │       │   │   ├── _simd.pyi
│       │       │   │   ├── _string_helpers.py
│       │       │   │   ├── _string_helpers.pyi
│       │       │   │   ├── _struct_ufunc_tests.cp312-win_amd64.lib
│       │       │   │   ├── _struct_ufunc_tests.cp312-win_amd64.pyd
│       │       │   │   ├── _type_aliases.py
│       │       │   │   ├── _type_aliases.pyi
│       │       │   │   ├── _ufunc_config.py
│       │       │   │   ├── _ufunc_config.pyi
│       │       │   │   ├── _umath_tests.cp312-win_amd64.lib
│       │       │   │   ├── _umath_tests.cp312-win_amd64.pyd
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── _distributor_init.py
│       │       │   ├── _distributor_init.pyi
│       │       │   ├── _expired_attrs_2_0.py
│       │       │   ├── _expired_attrs_2_0.pyi
│       │       │   ├── _globals.py
│       │       │   ├── _globals.pyi
│       │       │   ├── _pyinstaller/
│       │       │   │   ├── hook-numpy.py
│       │       │   │   ├── hook-numpy.pyi
│       │       │   │   ├── tests/
│       │       │   │   │   ├── pyinstaller-smoke.py
│       │       │   │   │   ├── test_pyinstaller.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── _pytesttester.py
│       │       │   ├── _pytesttester.pyi
│       │       │   ├── _typing/
│       │       │   │   ├── _add_docstring.py
│       │       │   │   ├── _array_like.py
│       │       │   │   ├── _callable.pyi
│       │       │   │   ├── _char_codes.py
│       │       │   │   ├── _dtype_like.py
│       │       │   │   ├── _extended_precision.py
│       │       │   │   ├── _nbit.py
│       │       │   │   ├── _nbit_base.py
│       │       │   │   ├── _nbit_base.pyi
│       │       │   │   ├── _nested_sequence.py
│       │       │   │   ├── _scalars.py
│       │       │   │   ├── _shape.py
│       │       │   │   ├── _ufunc.py
│       │       │   │   ├── _ufunc.pyi
│       │       │   │   └── __init__.py
│       │       │   ├── _utils/
│       │       │   │   ├── _convertions.py
│       │       │   │   ├── _convertions.pyi
│       │       │   │   ├── _inspect.py
│       │       │   │   ├── _inspect.pyi
│       │       │   │   ├── _pep440.py
│       │       │   │   ├── _pep440.pyi
│       │       │   │   ├── __init__.py
│       │       │   │   └── __init__.pyi
│       │       │   ├── __config__.py
│       │       │   ├── __config__.pyi
│       │       │   ├── __init__.cython-30.pxd
│       │       │   ├── __init__.pxd
│       │       │   ├── __init__.py
│       │       │   └── __init__.pyi
│       │       ├── numpy-2.3.1.dist-info/
│       │       │   ├── DELVEWHEEL
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── numpy.libs/
│       │       │   ├── libscipy_openblas64_-13e2df515630b4a41f92893938845698.dll
│       │       │   └── msvcp140-263139962577ecda4cd9469ca360a746.dll
│       │       ├── pandas/
│       │       │   ├── api/
│       │       │   │   ├── extensions/
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── indexers/
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── interchange/
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── types/
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── typing/
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── arrays/
│       │       │   │   └── __init__.py
│       │       │   ├── compat/
│       │       │   │   ├── compressors.py
│       │       │   │   ├── numpy/
│       │       │   │   │   ├── function.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── pickle_compat.py
│       │       │   │   ├── pyarrow.py
│       │       │   │   ├── _constants.py
│       │       │   │   ├── _optional.py
│       │       │   │   └── __init__.py
│       │       │   ├── conftest.py
│       │       │   ├── core/
│       │       │   │   ├── accessor.py
│       │       │   │   ├── algorithms.py
│       │       │   │   ├── api.py
│       │       │   │   ├── apply.py
│       │       │   │   ├── arraylike.py
│       │       │   │   ├── arrays/
│       │       │   │   │   ├── arrow/
│       │       │   │   │   │   ├── accessors.py
│       │       │   │   │   │   ├── array.py
│       │       │   │   │   │   ├── extension_types.py
│       │       │   │   │   │   ├── _arrow_utils.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── boolean.py
│       │       │   │   │   ├── categorical.py
│       │       │   │   │   ├── datetimelike.py
│       │       │   │   │   ├── datetimes.py
│       │       │   │   │   ├── floating.py
│       │       │   │   │   ├── integer.py
│       │       │   │   │   ├── interval.py
│       │       │   │   │   ├── masked.py
│       │       │   │   │   ├── numeric.py
│       │       │   │   │   ├── numpy_.py
│       │       │   │   │   ├── period.py
│       │       │   │   │   ├── sparse/
│       │       │   │   │   │   ├── accessor.py
│       │       │   │   │   │   ├── array.py
│       │       │   │   │   │   ├── scipy_sparse.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── string_.py
│       │       │   │   │   ├── string_arrow.py
│       │       │   │   │   ├── timedeltas.py
│       │       │   │   │   ├── _arrow_string_mixins.py
│       │       │   │   │   ├── _mixins.py
│       │       │   │   │   ├── _ranges.py
│       │       │   │   │   ├── _utils.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── array_algos/
│       │       │   │   │   ├── datetimelike_accumulations.py
│       │       │   │   │   ├── masked_accumulations.py
│       │       │   │   │   ├── masked_reductions.py
│       │       │   │   │   ├── putmask.py
│       │       │   │   │   ├── quantile.py
│       │       │   │   │   ├── replace.py
│       │       │   │   │   ├── take.py
│       │       │   │   │   ├── transforms.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── base.py
│       │       │   │   ├── common.py
│       │       │   │   ├── computation/
│       │       │   │   │   ├── align.py
│       │       │   │   │   ├── api.py
│       │       │   │   │   ├── check.py
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── engines.py
│       │       │   │   │   ├── eval.py
│       │       │   │   │   ├── expr.py
│       │       │   │   │   ├── expressions.py
│       │       │   │   │   ├── ops.py
│       │       │   │   │   ├── parsing.py
│       │       │   │   │   ├── pytables.py
│       │       │   │   │   ├── scope.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── config_init.py
│       │       │   │   ├── construction.py
│       │       │   │   ├── dtypes/
│       │       │   │   │   ├── api.py
│       │       │   │   │   ├── astype.py
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── cast.py
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── concat.py
│       │       │   │   │   ├── dtypes.py
│       │       │   │   │   ├── generic.py
│       │       │   │   │   ├── inference.py
│       │       │   │   │   ├── missing.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── flags.py
│       │       │   │   ├── frame.py
│       │       │   │   ├── generic.py
│       │       │   │   ├── groupby/
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── categorical.py
│       │       │   │   │   ├── generic.py
│       │       │   │   │   ├── groupby.py
│       │       │   │   │   ├── grouper.py
│       │       │   │   │   ├── indexing.py
│       │       │   │   │   ├── numba_.py
│       │       │   │   │   ├── ops.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── indexers/
│       │       │   │   │   ├── objects.py
│       │       │   │   │   ├── utils.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── indexes/
│       │       │   │   │   ├── accessors.py
│       │       │   │   │   ├── api.py
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── category.py
│       │       │   │   │   ├── datetimelike.py
│       │       │   │   │   ├── datetimes.py
│       │       │   │   │   ├── extension.py
│       │       │   │   │   ├── frozen.py
│       │       │   │   │   ├── interval.py
│       │       │   │   │   ├── multi.py
│       │       │   │   │   ├── period.py
│       │       │   │   │   ├── range.py
│       │       │   │   │   ├── timedeltas.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── indexing.py
│       │       │   │   ├── interchange/
│       │       │   │   │   ├── buffer.py
│       │       │   │   │   ├── column.py
│       │       │   │   │   ├── dataframe.py
│       │       │   │   │   ├── dataframe_protocol.py
│       │       │   │   │   ├── from_dataframe.py
│       │       │   │   │   ├── utils.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── internals/
│       │       │   │   │   ├── api.py
│       │       │   │   │   ├── array_manager.py
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── blocks.py
│       │       │   │   │   ├── concat.py
│       │       │   │   │   ├── construction.py
│       │       │   │   │   ├── managers.py
│       │       │   │   │   ├── ops.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── methods/
│       │       │   │   │   ├── describe.py
│       │       │   │   │   ├── selectn.py
│       │       │   │   │   ├── to_dict.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── missing.py
│       │       │   │   ├── nanops.py
│       │       │   │   ├── ops/
│       │       │   │   │   ├── array_ops.py
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── dispatch.py
│       │       │   │   │   ├── docstrings.py
│       │       │   │   │   ├── invalid.py
│       │       │   │   │   ├── mask_ops.py
│       │       │   │   │   ├── missing.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── resample.py
│       │       │   │   ├── reshape/
│       │       │   │   │   ├── api.py
│       │       │   │   │   ├── concat.py
│       │       │   │   │   ├── encoding.py
│       │       │   │   │   ├── melt.py
│       │       │   │   │   ├── merge.py
│       │       │   │   │   ├── pivot.py
│       │       │   │   │   ├── reshape.py
│       │       │   │   │   ├── tile.py
│       │       │   │   │   ├── util.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── roperator.py
│       │       │   │   ├── sample.py
│       │       │   │   ├── series.py
│       │       │   │   ├── shared_docs.py
│       │       │   │   ├── sorting.py
│       │       │   │   ├── sparse/
│       │       │   │   │   ├── api.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── strings/
│       │       │   │   │   ├── accessor.py
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── object_array.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── tools/
│       │       │   │   │   ├── datetimes.py
│       │       │   │   │   ├── numeric.py
│       │       │   │   │   ├── timedeltas.py
│       │       │   │   │   ├── times.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── util/
│       │       │   │   │   ├── hashing.py
│       │       │   │   │   ├── numba_.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── window/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── doc.py
│       │       │   │   │   ├── ewm.py
│       │       │   │   │   ├── expanding.py
│       │       │   │   │   ├── numba_.py
│       │       │   │   │   ├── online.py
│       │       │   │   │   ├── rolling.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _numba/
│       │       │   │   │   ├── executor.py
│       │       │   │   │   ├── extensions.py
│       │       │   │   │   ├── kernels/
│       │       │   │   │   │   ├── mean_.py
│       │       │   │   │   │   ├── min_max_.py
│       │       │   │   │   │   ├── shared.py
│       │       │   │   │   │   ├── sum_.py
│       │       │   │   │   │   ├── var_.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── errors/
│       │       │   │   └── __init__.py
│       │       │   ├── io/
│       │       │   │   ├── api.py
│       │       │   │   ├── clipboard/
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── clipboards.py
│       │       │   │   ├── common.py
│       │       │   │   ├── excel/
│       │       │   │   │   ├── _base.py
│       │       │   │   │   ├── _calamine.py
│       │       │   │   │   ├── _odfreader.py
│       │       │   │   │   ├── _odswriter.py
│       │       │   │   │   ├── _openpyxl.py
│       │       │   │   │   ├── _pyxlsb.py
│       │       │   │   │   ├── _util.py
│       │       │   │   │   ├── _xlrd.py
│       │       │   │   │   ├── _xlsxwriter.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── feather_format.py
│       │       │   │   ├── formats/
│       │       │   │   │   ├── console.py
│       │       │   │   │   ├── css.py
│       │       │   │   │   ├── csvs.py
│       │       │   │   │   ├── excel.py
│       │       │   │   │   ├── format.py
│       │       │   │   │   ├── html.py
│       │       │   │   │   ├── info.py
│       │       │   │   │   ├── printing.py
│       │       │   │   │   ├── string.py
│       │       │   │   │   ├── style.py
│       │       │   │   │   ├── style_render.py
│       │       │   │   │   ├── templates/
│       │       │   │   │   │   ├── html.tpl
│       │       │   │   │   │   ├── html_style.tpl
│       │       │   │   │   │   ├── html_table.tpl
│       │       │   │   │   │   ├── latex.tpl
│       │       │   │   │   │   ├── latex_longtable.tpl
│       │       │   │   │   │   ├── latex_table.tpl
│       │       │   │   │   │   └── string.tpl
│       │       │   │   │   ├── xml.py
│       │       │   │   │   ├── _color_data.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── gbq.py
│       │       │   │   ├── html.py
│       │       │   │   ├── json/
│       │       │   │   │   ├── _json.py
│       │       │   │   │   ├── _normalize.py
│       │       │   │   │   ├── _table_schema.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── orc.py
│       │       │   │   ├── parquet.py
│       │       │   │   ├── parsers/
│       │       │   │   │   ├── arrow_parser_wrapper.py
│       │       │   │   │   ├── base_parser.py
│       │       │   │   │   ├── c_parser_wrapper.py
│       │       │   │   │   ├── python_parser.py
│       │       │   │   │   ├── readers.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── pickle.py
│       │       │   │   ├── pytables.py
│       │       │   │   ├── sas/
│       │       │   │   │   ├── sas7bdat.py
│       │       │   │   │   ├── sasreader.py
│       │       │   │   │   ├── sas_constants.py
│       │       │   │   │   ├── sas_xport.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── spss.py
│       │       │   │   ├── sql.py
│       │       │   │   ├── stata.py
│       │       │   │   ├── xml.py
│       │       │   │   ├── _util.py
│       │       │   │   └── __init__.py
│       │       │   ├── plotting/
│       │       │   │   ├── _core.py
│       │       │   │   ├── _matplotlib/
│       │       │   │   │   ├── boxplot.py
│       │       │   │   │   ├── converter.py
│       │       │   │   │   ├── core.py
│       │       │   │   │   ├── groupby.py
│       │       │   │   │   ├── hist.py
│       │       │   │   │   ├── misc.py
│       │       │   │   │   ├── style.py
│       │       │   │   │   ├── timeseries.py
│       │       │   │   │   ├── tools.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _misc.py
│       │       │   │   └── __init__.py
│       │       │   ├── pyproject.toml
│       │       │   ├── testing.py
│       │       │   ├── tests/
│       │       │   │   ├── api/
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_types.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── apply/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── test_frame_apply.py
│       │       │   │   │   ├── test_frame_apply_relabeling.py
│       │       │   │   │   ├── test_frame_transform.py
│       │       │   │   │   ├── test_invalid_arg.py
│       │       │   │   │   ├── test_numba.py
│       │       │   │   │   ├── test_series_apply.py
│       │       │   │   │   ├── test_series_apply_relabeling.py
│       │       │   │   │   ├── test_series_transform.py
│       │       │   │   │   ├── test_str.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── arithmetic/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── test_array_ops.py
│       │       │   │   │   ├── test_categorical.py
│       │       │   │   │   ├── test_datetime64.py
│       │       │   │   │   ├── test_interval.py
│       │       │   │   │   ├── test_numeric.py
│       │       │   │   │   ├── test_object.py
│       │       │   │   │   ├── test_period.py
│       │       │   │   │   ├── test_timedelta64.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── arrays/
│       │       │   │   │   ├── boolean/
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_comparison.py
│       │       │   │   │   │   ├── test_construction.py
│       │       │   │   │   │   ├── test_function.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_logical.py
│       │       │   │   │   │   ├── test_ops.py
│       │       │   │   │   │   ├── test_reduction.py
│       │       │   │   │   │   ├── test_repr.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── categorical/
│       │       │   │   │   │   ├── test_algos.py
│       │       │   │   │   │   ├── test_analytics.py
│       │       │   │   │   │   ├── test_api.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_dtypes.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_map.py
│       │       │   │   │   │   ├── test_missing.py
│       │       │   │   │   │   ├── test_operators.py
│       │       │   │   │   │   ├── test_replace.py
│       │       │   │   │   │   ├── test_repr.py
│       │       │   │   │   │   ├── test_sorting.py
│       │       │   │   │   │   ├── test_subclass.py
│       │       │   │   │   │   ├── test_take.py
│       │       │   │   │   │   ├── test_warnings.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── datetimes/
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_cumulative.py
│       │       │   │   │   │   ├── test_reductions.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── floating/
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_comparison.py
│       │       │   │   │   │   ├── test_concat.py
│       │       │   │   │   │   ├── test_construction.py
│       │       │   │   │   │   ├── test_contains.py
│       │       │   │   │   │   ├── test_function.py
│       │       │   │   │   │   ├── test_repr.py
│       │       │   │   │   │   ├── test_to_numpy.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── integer/
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_comparison.py
│       │       │   │   │   │   ├── test_concat.py
│       │       │   │   │   │   ├── test_construction.py
│       │       │   │   │   │   ├── test_dtypes.py
│       │       │   │   │   │   ├── test_function.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_reduction.py
│       │       │   │   │   │   ├── test_repr.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── interval/
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_interval.py
│       │       │   │   │   │   ├── test_interval_pyarrow.py
│       │       │   │   │   │   ├── test_overlaps.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── masked/
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_arrow_compat.py
│       │       │   │   │   │   ├── test_function.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── masked_shared.py
│       │       │   │   │   ├── numpy_/
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_numpy.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── period/
│       │       │   │   │   │   ├── test_arrow_compat.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_reductions.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── sparse/
│       │       │   │   │   │   ├── test_accessor.py
│       │       │   │   │   │   ├── test_arithmetics.py
│       │       │   │   │   │   ├── test_array.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_combine_concat.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_dtype.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_libsparse.py
│       │       │   │   │   │   ├── test_reductions.py
│       │       │   │   │   │   ├── test_unary.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── string_/
│       │       │   │   │   │   ├── test_concat.py
│       │       │   │   │   │   ├── test_string.py
│       │       │   │   │   │   ├── test_string_arrow.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_array.py
│       │       │   │   │   ├── test_datetimelike.py
│       │       │   │   │   ├── test_datetimes.py
│       │       │   │   │   ├── test_ndarray_backed.py
│       │       │   │   │   ├── test_period.py
│       │       │   │   │   ├── test_timedeltas.py
│       │       │   │   │   ├── timedeltas/
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_cumulative.py
│       │       │   │   │   │   ├── test_reductions.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── base/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── test_constructors.py
│       │       │   │   │   ├── test_conversion.py
│       │       │   │   │   ├── test_fillna.py
│       │       │   │   │   ├── test_misc.py
│       │       │   │   │   ├── test_transpose.py
│       │       │   │   │   ├── test_unique.py
│       │       │   │   │   ├── test_value_counts.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── computation/
│       │       │   │   │   ├── test_compat.py
│       │       │   │   │   ├── test_eval.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── config/
│       │       │   │   │   ├── test_config.py
│       │       │   │   │   ├── test_localization.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── construction/
│       │       │   │   │   ├── test_extract_array.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── copy_view/
│       │       │   │   │   ├── index/
│       │       │   │   │   │   ├── test_datetimeindex.py
│       │       │   │   │   │   ├── test_index.py
│       │       │   │   │   │   ├── test_periodindex.py
│       │       │   │   │   │   ├── test_timedeltaindex.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_array.py
│       │       │   │   │   ├── test_astype.py
│       │       │   │   │   ├── test_chained_assignment_deprecation.py
│       │       │   │   │   ├── test_clip.py
│       │       │   │   │   ├── test_constructors.py
│       │       │   │   │   ├── test_core_functionalities.py
│       │       │   │   │   ├── test_functions.py
│       │       │   │   │   ├── test_indexing.py
│       │       │   │   │   ├── test_internals.py
│       │       │   │   │   ├── test_interp_fillna.py
│       │       │   │   │   ├── test_methods.py
│       │       │   │   │   ├── test_replace.py
│       │       │   │   │   ├── test_setitem.py
│       │       │   │   │   ├── test_util.py
│       │       │   │   │   ├── util.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── dtypes/
│       │       │   │   │   ├── cast/
│       │       │   │   │   │   ├── test_can_hold_element.py
│       │       │   │   │   │   ├── test_construct_from_scalar.py
│       │       │   │   │   │   ├── test_construct_ndarray.py
│       │       │   │   │   │   ├── test_construct_object_arr.py
│       │       │   │   │   │   ├── test_dict_compat.py
│       │       │   │   │   │   ├── test_downcast.py
│       │       │   │   │   │   ├── test_find_common_type.py
│       │       │   │   │   │   ├── test_infer_datetimelike.py
│       │       │   │   │   │   ├── test_infer_dtype.py
│       │       │   │   │   │   ├── test_maybe_box_native.py
│       │       │   │   │   │   ├── test_promote.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_concat.py
│       │       │   │   │   ├── test_dtypes.py
│       │       │   │   │   ├── test_generic.py
│       │       │   │   │   ├── test_inference.py
│       │       │   │   │   ├── test_missing.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── extension/
│       │       │   │   │   ├── array_with_attr/
│       │       │   │   │   │   ├── array.py
│       │       │   │   │   │   ├── test_array_with_attr.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── base/
│       │       │   │   │   │   ├── accumulate.py
│       │       │   │   │   │   ├── base.py
│       │       │   │   │   │   ├── casting.py
│       │       │   │   │   │   ├── constructors.py
│       │       │   │   │   │   ├── dim2.py
│       │       │   │   │   │   ├── dtype.py
│       │       │   │   │   │   ├── getitem.py
│       │       │   │   │   │   ├── groupby.py
│       │       │   │   │   │   ├── index.py
│       │       │   │   │   │   ├── interface.py
│       │       │   │   │   │   ├── io.py
│       │       │   │   │   │   ├── methods.py
│       │       │   │   │   │   ├── missing.py
│       │       │   │   │   │   ├── ops.py
│       │       │   │   │   │   ├── printing.py
│       │       │   │   │   │   ├── reduce.py
│       │       │   │   │   │   ├── reshaping.py
│       │       │   │   │   │   ├── setitem.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── date/
│       │       │   │   │   │   ├── array.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── decimal/
│       │       │   │   │   │   ├── array.py
│       │       │   │   │   │   ├── test_decimal.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── json/
│       │       │   │   │   │   ├── array.py
│       │       │   │   │   │   ├── test_json.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── list/
│       │       │   │   │   │   ├── array.py
│       │       │   │   │   │   ├── test_list.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_arrow.py
│       │       │   │   │   ├── test_categorical.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_datetime.py
│       │       │   │   │   ├── test_extension.py
│       │       │   │   │   ├── test_interval.py
│       │       │   │   │   ├── test_masked.py
│       │       │   │   │   ├── test_numpy.py
│       │       │   │   │   ├── test_period.py
│       │       │   │   │   ├── test_sparse.py
│       │       │   │   │   ├── test_string.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── frame/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── constructors/
│       │       │   │   │   │   ├── test_from_dict.py
│       │       │   │   │   │   ├── test_from_records.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── indexing/
│       │       │   │   │   │   ├── test_coercion.py
│       │       │   │   │   │   ├── test_delitem.py
│       │       │   │   │   │   ├── test_get.py
│       │       │   │   │   │   ├── test_getitem.py
│       │       │   │   │   │   ├── test_get_value.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_insert.py
│       │       │   │   │   │   ├── test_mask.py
│       │       │   │   │   │   ├── test_setitem.py
│       │       │   │   │   │   ├── test_set_value.py
│       │       │   │   │   │   ├── test_take.py
│       │       │   │   │   │   ├── test_where.py
│       │       │   │   │   │   ├── test_xs.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── methods/
│       │       │   │   │   │   ├── test_add_prefix_suffix.py
│       │       │   │   │   │   ├── test_align.py
│       │       │   │   │   │   ├── test_asfreq.py
│       │       │   │   │   │   ├── test_asof.py
│       │       │   │   │   │   ├── test_assign.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_at_time.py
│       │       │   │   │   │   ├── test_between_time.py
│       │       │   │   │   │   ├── test_clip.py
│       │       │   │   │   │   ├── test_combine.py
│       │       │   │   │   │   ├── test_combine_first.py
│       │       │   │   │   │   ├── test_compare.py
│       │       │   │   │   │   ├── test_convert_dtypes.py
│       │       │   │   │   │   ├── test_copy.py
│       │       │   │   │   │   ├── test_count.py
│       │       │   │   │   │   ├── test_cov_corr.py
│       │       │   │   │   │   ├── test_describe.py
│       │       │   │   │   │   ├── test_diff.py
│       │       │   │   │   │   ├── test_dot.py
│       │       │   │   │   │   ├── test_drop.py
│       │       │   │   │   │   ├── test_droplevel.py
│       │       │   │   │   │   ├── test_dropna.py
│       │       │   │   │   │   ├── test_drop_duplicates.py
│       │       │   │   │   │   ├── test_dtypes.py
│       │       │   │   │   │   ├── test_duplicated.py
│       │       │   │   │   │   ├── test_equals.py
│       │       │   │   │   │   ├── test_explode.py
│       │       │   │   │   │   ├── test_fillna.py
│       │       │   │   │   │   ├── test_filter.py
│       │       │   │   │   │   ├── test_first_and_last.py
│       │       │   │   │   │   ├── test_first_valid_index.py
│       │       │   │   │   │   ├── test_get_numeric_data.py
│       │       │   │   │   │   ├── test_head_tail.py
│       │       │   │   │   │   ├── test_infer_objects.py
│       │       │   │   │   │   ├── test_info.py
│       │       │   │   │   │   ├── test_interpolate.py
│       │       │   │   │   │   ├── test_isetitem.py
│       │       │   │   │   │   ├── test_isin.py
│       │       │   │   │   │   ├── test_is_homogeneous_dtype.py
│       │       │   │   │   │   ├── test_iterrows.py
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_map.py
│       │       │   │   │   │   ├── test_matmul.py
│       │       │   │   │   │   ├── test_nlargest.py
│       │       │   │   │   │   ├── test_pct_change.py
│       │       │   │   │   │   ├── test_pipe.py
│       │       │   │   │   │   ├── test_pop.py
│       │       │   │   │   │   ├── test_quantile.py
│       │       │   │   │   │   ├── test_rank.py
│       │       │   │   │   │   ├── test_reindex.py
│       │       │   │   │   │   ├── test_reindex_like.py
│       │       │   │   │   │   ├── test_rename.py
│       │       │   │   │   │   ├── test_rename_axis.py
│       │       │   │   │   │   ├── test_reorder_levels.py
│       │       │   │   │   │   ├── test_replace.py
│       │       │   │   │   │   ├── test_reset_index.py
│       │       │   │   │   │   ├── test_round.py
│       │       │   │   │   │   ├── test_sample.py
│       │       │   │   │   │   ├── test_select_dtypes.py
│       │       │   │   │   │   ├── test_set_axis.py
│       │       │   │   │   │   ├── test_set_index.py
│       │       │   │   │   │   ├── test_shift.py
│       │       │   │   │   │   ├── test_size.py
│       │       │   │   │   │   ├── test_sort_index.py
│       │       │   │   │   │   ├── test_sort_values.py
│       │       │   │   │   │   ├── test_swapaxes.py
│       │       │   │   │   │   ├── test_swaplevel.py
│       │       │   │   │   │   ├── test_to_csv.py
│       │       │   │   │   │   ├── test_to_dict.py
│       │       │   │   │   │   ├── test_to_dict_of_blocks.py
│       │       │   │   │   │   ├── test_to_numpy.py
│       │       │   │   │   │   ├── test_to_period.py
│       │       │   │   │   │   ├── test_to_records.py
│       │       │   │   │   │   ├── test_to_timestamp.py
│       │       │   │   │   │   ├── test_transpose.py
│       │       │   │   │   │   ├── test_truncate.py
│       │       │   │   │   │   ├── test_tz_convert.py
│       │       │   │   │   │   ├── test_tz_localize.py
│       │       │   │   │   │   ├── test_update.py
│       │       │   │   │   │   ├── test_values.py
│       │       │   │   │   │   ├── test_value_counts.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_alter_axes.py
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_arithmetic.py
│       │       │   │   │   ├── test_arrow_interface.py
│       │       │   │   │   ├── test_block_internals.py
│       │       │   │   │   ├── test_constructors.py
│       │       │   │   │   ├── test_cumulative.py
│       │       │   │   │   ├── test_iteration.py
│       │       │   │   │   ├── test_logical_ops.py
│       │       │   │   │   ├── test_nonunique_indexes.py
│       │       │   │   │   ├── test_npfuncs.py
│       │       │   │   │   ├── test_query_eval.py
│       │       │   │   │   ├── test_reductions.py
│       │       │   │   │   ├── test_repr.py
│       │       │   │   │   ├── test_stack_unstack.py
│       │       │   │   │   ├── test_subclass.py
│       │       │   │   │   ├── test_ufunc.py
│       │       │   │   │   ├── test_unary.py
│       │       │   │   │   ├── test_validate.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── generic/
│       │       │   │   │   ├── test_duplicate_labels.py
│       │       │   │   │   ├── test_finalize.py
│       │       │   │   │   ├── test_frame.py
│       │       │   │   │   ├── test_generic.py
│       │       │   │   │   ├── test_label_or_level_utils.py
│       │       │   │   │   ├── test_series.py
│       │       │   │   │   ├── test_to_xarray.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── groupby/
│       │       │   │   │   ├── aggregate/
│       │       │   │   │   │   ├── test_aggregate.py
│       │       │   │   │   │   ├── test_cython.py
│       │       │   │   │   │   ├── test_numba.py
│       │       │   │   │   │   ├── test_other.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── methods/
│       │       │   │   │   │   ├── test_corrwith.py
│       │       │   │   │   │   ├── test_describe.py
│       │       │   │   │   │   ├── test_groupby_shift_diff.py
│       │       │   │   │   │   ├── test_is_monotonic.py
│       │       │   │   │   │   ├── test_nlargest_nsmallest.py
│       │       │   │   │   │   ├── test_nth.py
│       │       │   │   │   │   ├── test_quantile.py
│       │       │   │   │   │   ├── test_rank.py
│       │       │   │   │   │   ├── test_sample.py
│       │       │   │   │   │   ├── test_size.py
│       │       │   │   │   │   ├── test_skew.py
│       │       │   │   │   │   ├── test_value_counts.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_all_methods.py
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_apply.py
│       │       │   │   │   ├── test_apply_mutate.py
│       │       │   │   │   ├── test_bin_groupby.py
│       │       │   │   │   ├── test_categorical.py
│       │       │   │   │   ├── test_counting.py
│       │       │   │   │   ├── test_cumulative.py
│       │       │   │   │   ├── test_filters.py
│       │       │   │   │   ├── test_groupby.py
│       │       │   │   │   ├── test_groupby_dropna.py
│       │       │   │   │   ├── test_groupby_subclass.py
│       │       │   │   │   ├── test_grouping.py
│       │       │   │   │   ├── test_indexing.py
│       │       │   │   │   ├── test_index_as_string.py
│       │       │   │   │   ├── test_libgroupby.py
│       │       │   │   │   ├── test_missing.py
│       │       │   │   │   ├── test_numba.py
│       │       │   │   │   ├── test_numeric_only.py
│       │       │   │   │   ├── test_pipe.py
│       │       │   │   │   ├── test_raises.py
│       │       │   │   │   ├── test_reductions.py
│       │       │   │   │   ├── test_timegrouper.py
│       │       │   │   │   ├── transform/
│       │       │   │   │   │   ├── test_numba.py
│       │       │   │   │   │   ├── test_transform.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── indexes/
│       │       │   │   │   ├── base_class/
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_pickle.py
│       │       │   │   │   │   ├── test_reshape.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   ├── test_where.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── categorical/
│       │       │   │   │   │   ├── test_append.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_category.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_equals.py
│       │       │   │   │   │   ├── test_fillna.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_map.py
│       │       │   │   │   │   ├── test_reindex.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── datetimelike_/
│       │       │   │   │   │   ├── test_drop_duplicates.py
│       │       │   │   │   │   ├── test_equals.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_is_monotonic.py
│       │       │   │   │   │   ├── test_nat.py
│       │       │   │   │   │   ├── test_sort_values.py
│       │       │   │   │   │   ├── test_value_counts.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── datetimes/
│       │       │   │   │   │   ├── methods/
│       │       │   │   │   │   │   ├── test_asof.py
│       │       │   │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   │   ├── test_delete.py
│       │       │   │   │   │   │   ├── test_factorize.py
│       │       │   │   │   │   │   ├── test_fillna.py
│       │       │   │   │   │   │   ├── test_insert.py
│       │       │   │   │   │   │   ├── test_isocalendar.py
│       │       │   │   │   │   │   ├── test_map.py
│       │       │   │   │   │   │   ├── test_normalize.py
│       │       │   │   │   │   │   ├── test_repeat.py
│       │       │   │   │   │   │   ├── test_resolution.py
│       │       │   │   │   │   │   ├── test_round.py
│       │       │   │   │   │   │   ├── test_shift.py
│       │       │   │   │   │   │   ├── test_snap.py
│       │       │   │   │   │   │   ├── test_to_frame.py
│       │       │   │   │   │   │   ├── test_to_julian_date.py
│       │       │   │   │   │   │   ├── test_to_period.py
│       │       │   │   │   │   │   ├── test_to_pydatetime.py
│       │       │   │   │   │   │   ├── test_to_series.py
│       │       │   │   │   │   │   ├── test_tz_convert.py
│       │       │   │   │   │   │   ├── test_tz_localize.py
│       │       │   │   │   │   │   ├── test_unique.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_datetime.py
│       │       │   │   │   │   ├── test_date_range.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_freq_attr.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_iter.py
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_npfuncs.py
│       │       │   │   │   │   ├── test_ops.py
│       │       │   │   │   │   ├── test_partial_slicing.py
│       │       │   │   │   │   ├── test_pickle.py
│       │       │   │   │   │   ├── test_reindex.py
│       │       │   │   │   │   ├── test_scalar_compat.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   ├── test_timezones.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── interval/
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_equals.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_interval.py
│       │       │   │   │   │   ├── test_interval_range.py
│       │       │   │   │   │   ├── test_interval_tree.py
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_pickle.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── multi/
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── test_analytics.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_compat.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_conversion.py
│       │       │   │   │   │   ├── test_copy.py
│       │       │   │   │   │   ├── test_drop.py
│       │       │   │   │   │   ├── test_duplicates.py
│       │       │   │   │   │   ├── test_equivalence.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_get_level_values.py
│       │       │   │   │   │   ├── test_get_set.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_integrity.py
│       │       │   │   │   │   ├── test_isin.py
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_lexsort.py
│       │       │   │   │   │   ├── test_missing.py
│       │       │   │   │   │   ├── test_monotonic.py
│       │       │   │   │   │   ├── test_names.py
│       │       │   │   │   │   ├── test_partial_indexing.py
│       │       │   │   │   │   ├── test_pickle.py
│       │       │   │   │   │   ├── test_reindex.py
│       │       │   │   │   │   ├── test_reshape.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   ├── test_sorting.py
│       │       │   │   │   │   ├── test_take.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── numeric/
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_numeric.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── object/
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── period/
│       │       │   │   │   │   ├── methods/
│       │       │   │   │   │   │   ├── test_asfreq.py
│       │       │   │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   │   ├── test_factorize.py
│       │       │   │   │   │   │   ├── test_fillna.py
│       │       │   │   │   │   │   ├── test_insert.py
│       │       │   │   │   │   │   ├── test_is_full.py
│       │       │   │   │   │   │   ├── test_repeat.py
│       │       │   │   │   │   │   ├── test_shift.py
│       │       │   │   │   │   │   ├── test_to_timestamp.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_freq_attr.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_monotonic.py
│       │       │   │   │   │   ├── test_partial_slicing.py
│       │       │   │   │   │   ├── test_period.py
│       │       │   │   │   │   ├── test_period_range.py
│       │       │   │   │   │   ├── test_pickle.py
│       │       │   │   │   │   ├── test_resolution.py
│       │       │   │   │   │   ├── test_scalar_compat.py
│       │       │   │   │   │   ├── test_searchsorted.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   ├── test_tools.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── ranges/
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_range.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── string/
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_any_index.py
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_datetimelike.py
│       │       │   │   │   ├── test_engines.py
│       │       │   │   │   ├── test_frozen.py
│       │       │   │   │   ├── test_indexing.py
│       │       │   │   │   ├── test_index_new.py
│       │       │   │   │   ├── test_numpy_compat.py
│       │       │   │   │   ├── test_old_base.py
│       │       │   │   │   ├── test_setops.py
│       │       │   │   │   ├── test_subclass.py
│       │       │   │   │   ├── timedeltas/
│       │       │   │   │   │   ├── methods/
│       │       │   │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   │   ├── test_factorize.py
│       │       │   │   │   │   │   ├── test_fillna.py
│       │       │   │   │   │   │   ├── test_insert.py
│       │       │   │   │   │   │   ├── test_repeat.py
│       │       │   │   │   │   │   ├── test_shift.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_delete.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_freq_attr.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_ops.py
│       │       │   │   │   │   ├── test_pickle.py
│       │       │   │   │   │   ├── test_scalar_compat.py
│       │       │   │   │   │   ├── test_searchsorted.py
│       │       │   │   │   │   ├── test_setops.py
│       │       │   │   │   │   ├── test_timedelta.py
│       │       │   │   │   │   ├── test_timedelta_range.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── indexing/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── interval/
│       │       │   │   │   │   ├── test_interval.py
│       │       │   │   │   │   ├── test_interval_new.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── multiindex/
│       │       │   │   │   │   ├── test_chaining_and_caching.py
│       │       │   │   │   │   ├── test_datetime.py
│       │       │   │   │   │   ├── test_getitem.py
│       │       │   │   │   │   ├── test_iloc.py
│       │       │   │   │   │   ├── test_indexing_slow.py
│       │       │   │   │   │   ├── test_loc.py
│       │       │   │   │   │   ├── test_multiindex.py
│       │       │   │   │   │   ├── test_partial.py
│       │       │   │   │   │   ├── test_setitem.py
│       │       │   │   │   │   ├── test_slice.py
│       │       │   │   │   │   ├── test_sorted.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_at.py
│       │       │   │   │   ├── test_categorical.py
│       │       │   │   │   ├── test_chaining_and_caching.py
│       │       │   │   │   ├── test_check_indexer.py
│       │       │   │   │   ├── test_coercion.py
│       │       │   │   │   ├── test_datetime.py
│       │       │   │   │   ├── test_floats.py
│       │       │   │   │   ├── test_iat.py
│       │       │   │   │   ├── test_iloc.py
│       │       │   │   │   ├── test_indexers.py
│       │       │   │   │   ├── test_indexing.py
│       │       │   │   │   ├── test_loc.py
│       │       │   │   │   ├── test_na_indexing.py
│       │       │   │   │   ├── test_partial.py
│       │       │   │   │   ├── test_scalar.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── interchange/
│       │       │   │   │   ├── test_impl.py
│       │       │   │   │   ├── test_spec_conformance.py
│       │       │   │   │   ├── test_utils.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── internals/
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_internals.py
│       │       │   │   │   ├── test_managers.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── io/
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── excel/
│       │       │   │   │   │   ├── test_odf.py
│       │       │   │   │   │   ├── test_odswriter.py
│       │       │   │   │   │   ├── test_openpyxl.py
│       │       │   │   │   │   ├── test_readers.py
│       │       │   │   │   │   ├── test_style.py
│       │       │   │   │   │   ├── test_writers.py
│       │       │   │   │   │   ├── test_xlrd.py
│       │       │   │   │   │   ├── test_xlsxwriter.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── formats/
│       │       │   │   │   │   ├── style/
│       │       │   │   │   │   │   ├── test_bar.py
│       │       │   │   │   │   │   ├── test_exceptions.py
│       │       │   │   │   │   │   ├── test_format.py
│       │       │   │   │   │   │   ├── test_highlight.py
│       │       │   │   │   │   │   ├── test_html.py
│       │       │   │   │   │   │   ├── test_matplotlib.py
│       │       │   │   │   │   │   ├── test_non_unique.py
│       │       │   │   │   │   │   ├── test_style.py
│       │       │   │   │   │   │   ├── test_tooltip.py
│       │       │   │   │   │   │   ├── test_to_latex.py
│       │       │   │   │   │   │   ├── test_to_string.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── test_console.py
│       │       │   │   │   │   ├── test_css.py
│       │       │   │   │   │   ├── test_eng_formatting.py
│       │       │   │   │   │   ├── test_format.py
│       │       │   │   │   │   ├── test_ipython_compat.py
│       │       │   │   │   │   ├── test_printing.py
│       │       │   │   │   │   ├── test_to_csv.py
│       │       │   │   │   │   ├── test_to_excel.py
│       │       │   │   │   │   ├── test_to_html.py
│       │       │   │   │   │   ├── test_to_latex.py
│       │       │   │   │   │   ├── test_to_markdown.py
│       │       │   │   │   │   ├── test_to_string.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── generate_legacy_storage_files.py
│       │       │   │   │   ├── json/
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── test_compression.py
│       │       │   │   │   │   ├── test_deprecated_kwargs.py
│       │       │   │   │   │   ├── test_json_table_schema.py
│       │       │   │   │   │   ├── test_json_table_schema_ext_dtype.py
│       │       │   │   │   │   ├── test_normalize.py
│       │       │   │   │   │   ├── test_pandas.py
│       │       │   │   │   │   ├── test_readlines.py
│       │       │   │   │   │   ├── test_ujson.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── parser/
│       │       │   │   │   │   ├── common/
│       │       │   │   │   │   │   ├── test_chunksize.py
│       │       │   │   │   │   │   ├── test_common_basic.py
│       │       │   │   │   │   │   ├── test_data_list.py
│       │       │   │   │   │   │   ├── test_decimal.py
│       │       │   │   │   │   │   ├── test_file_buffer_url.py
│       │       │   │   │   │   │   ├── test_float.py
│       │       │   │   │   │   │   ├── test_index.py
│       │       │   │   │   │   │   ├── test_inf.py
│       │       │   │   │   │   │   ├── test_ints.py
│       │       │   │   │   │   │   ├── test_iterator.py
│       │       │   │   │   │   │   ├── test_read_errors.py
│       │       │   │   │   │   │   ├── test_verbose.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── dtypes/
│       │       │   │   │   │   │   ├── test_categorical.py
│       │       │   │   │   │   │   ├── test_dtypes_basic.py
│       │       │   │   │   │   │   ├── test_empty.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── test_comment.py
│       │       │   │   │   │   ├── test_compression.py
│       │       │   │   │   │   ├── test_concatenate_chunks.py
│       │       │   │   │   │   ├── test_converters.py
│       │       │   │   │   │   ├── test_c_parser_only.py
│       │       │   │   │   │   ├── test_dialect.py
│       │       │   │   │   │   ├── test_encoding.py
│       │       │   │   │   │   ├── test_header.py
│       │       │   │   │   │   ├── test_index_col.py
│       │       │   │   │   │   ├── test_mangle_dupes.py
│       │       │   │   │   │   ├── test_multi_thread.py
│       │       │   │   │   │   ├── test_na_values.py
│       │       │   │   │   │   ├── test_network.py
│       │       │   │   │   │   ├── test_parse_dates.py
│       │       │   │   │   │   ├── test_python_parser_only.py
│       │       │   │   │   │   ├── test_quoting.py
│       │       │   │   │   │   ├── test_read_fwf.py
│       │       │   │   │   │   ├── test_skiprows.py
│       │       │   │   │   │   ├── test_textreader.py
│       │       │   │   │   │   ├── test_unsupported.py
│       │       │   │   │   │   ├── test_upcast.py
│       │       │   │   │   │   ├── usecols/
│       │       │   │   │   │   │   ├── test_parse_dates.py
│       │       │   │   │   │   │   ├── test_strings.py
│       │       │   │   │   │   │   ├── test_usecols_basic.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── pytables/
│       │       │   │   │   │   ├── common.py
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── test_append.py
│       │       │   │   │   │   ├── test_categorical.py
│       │       │   │   │   │   ├── test_compat.py
│       │       │   │   │   │   ├── test_complex.py
│       │       │   │   │   │   ├── test_errors.py
│       │       │   │   │   │   ├── test_file_handling.py
│       │       │   │   │   │   ├── test_keys.py
│       │       │   │   │   │   ├── test_put.py
│       │       │   │   │   │   ├── test_pytables_missing.py
│       │       │   │   │   │   ├── test_read.py
│       │       │   │   │   │   ├── test_retain_attributes.py
│       │       │   │   │   │   ├── test_round_trip.py
│       │       │   │   │   │   ├── test_select.py
│       │       │   │   │   │   ├── test_store.py
│       │       │   │   │   │   ├── test_subclass.py
│       │       │   │   │   │   ├── test_timezones.py
│       │       │   │   │   │   ├── test_time_series.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── sas/
│       │       │   │   │   │   ├── test_byteswap.py
│       │       │   │   │   │   ├── test_sas.py
│       │       │   │   │   │   ├── test_sas7bdat.py
│       │       │   │   │   │   ├── test_xport.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_clipboard.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_compression.py
│       │       │   │   │   ├── test_feather.py
│       │       │   │   │   ├── test_fsspec.py
│       │       │   │   │   ├── test_gbq.py
│       │       │   │   │   ├── test_gcs.py
│       │       │   │   │   ├── test_html.py
│       │       │   │   │   ├── test_http_headers.py
│       │       │   │   │   ├── test_orc.py
│       │       │   │   │   ├── test_parquet.py
│       │       │   │   │   ├── test_pickle.py
│       │       │   │   │   ├── test_s3.py
│       │       │   │   │   ├── test_spss.py
│       │       │   │   │   ├── test_sql.py
│       │       │   │   │   ├── test_stata.py
│       │       │   │   │   ├── xml/
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── test_to_xml.py
│       │       │   │   │   │   ├── test_xml.py
│       │       │   │   │   │   ├── test_xml_dtypes.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── libs/
│       │       │   │   │   ├── test_hashtable.py
│       │       │   │   │   ├── test_join.py
│       │       │   │   │   ├── test_lib.py
│       │       │   │   │   ├── test_libalgos.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── plotting/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── frame/
│       │       │   │   │   │   ├── test_frame.py
│       │       │   │   │   │   ├── test_frame_color.py
│       │       │   │   │   │   ├── test_frame_groupby.py
│       │       │   │   │   │   ├── test_frame_legend.py
│       │       │   │   │   │   ├── test_frame_subplots.py
│       │       │   │   │   │   ├── test_hist_box_by.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_backend.py
│       │       │   │   │   ├── test_boxplot_method.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_converter.py
│       │       │   │   │   ├── test_datetimelike.py
│       │       │   │   │   ├── test_groupby.py
│       │       │   │   │   ├── test_hist_method.py
│       │       │   │   │   ├── test_misc.py
│       │       │   │   │   ├── test_series.py
│       │       │   │   │   ├── test_style.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── reductions/
│       │       │   │   │   ├── test_reductions.py
│       │       │   │   │   ├── test_stat_reductions.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── resample/
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_datetime_index.py
│       │       │   │   │   ├── test_period_index.py
│       │       │   │   │   ├── test_resampler_grouper.py
│       │       │   │   │   ├── test_resample_api.py
│       │       │   │   │   ├── test_timedelta.py
│       │       │   │   │   ├── test_time_grouper.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── reshape/
│       │       │   │   │   ├── concat/
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── test_append.py
│       │       │   │   │   │   ├── test_append_common.py
│       │       │   │   │   │   ├── test_categorical.py
│       │       │   │   │   │   ├── test_concat.py
│       │       │   │   │   │   ├── test_dataframe.py
│       │       │   │   │   │   ├── test_datetimes.py
│       │       │   │   │   │   ├── test_empty.py
│       │       │   │   │   │   ├── test_index.py
│       │       │   │   │   │   ├── test_invalid.py
│       │       │   │   │   │   ├── test_series.py
│       │       │   │   │   │   ├── test_sort.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── merge/
│       │       │   │   │   │   ├── test_join.py
│       │       │   │   │   │   ├── test_merge.py
│       │       │   │   │   │   ├── test_merge_asof.py
│       │       │   │   │   │   ├── test_merge_cross.py
│       │       │   │   │   │   ├── test_merge_index_as_string.py
│       │       │   │   │   │   ├── test_merge_ordered.py
│       │       │   │   │   │   ├── test_multi.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_crosstab.py
│       │       │   │   │   ├── test_cut.py
│       │       │   │   │   ├── test_from_dummies.py
│       │       │   │   │   ├── test_get_dummies.py
│       │       │   │   │   ├── test_melt.py
│       │       │   │   │   ├── test_pivot.py
│       │       │   │   │   ├── test_pivot_multilevel.py
│       │       │   │   │   ├── test_qcut.py
│       │       │   │   │   ├── test_union_categoricals.py
│       │       │   │   │   ├── test_util.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── scalar/
│       │       │   │   │   ├── interval/
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_contains.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_interval.py
│       │       │   │   │   │   ├── test_overlaps.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── period/
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_asfreq.py
│       │       │   │   │   │   ├── test_period.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_nat.py
│       │       │   │   │   ├── test_na_scalar.py
│       │       │   │   │   ├── timedelta/
│       │       │   │   │   │   ├── methods/
│       │       │   │   │   │   │   ├── test_as_unit.py
│       │       │   │   │   │   │   ├── test_round.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_timedelta.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── timestamp/
│       │       │   │   │   │   ├── methods/
│       │       │   │   │   │   │   ├── test_as_unit.py
│       │       │   │   │   │   │   ├── test_normalize.py
│       │       │   │   │   │   │   ├── test_replace.py
│       │       │   │   │   │   │   ├── test_round.py
│       │       │   │   │   │   │   ├── test_timestamp_method.py
│       │       │   │   │   │   │   ├── test_to_julian_date.py
│       │       │   │   │   │   │   ├── test_to_pydatetime.py
│       │       │   │   │   │   │   ├── test_tz_convert.py
│       │       │   │   │   │   │   ├── test_tz_localize.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── test_arithmetic.py
│       │       │   │   │   │   ├── test_comparisons.py
│       │       │   │   │   │   ├── test_constructors.py
│       │       │   │   │   │   ├── test_formats.py
│       │       │   │   │   │   ├── test_timestamp.py
│       │       │   │   │   │   ├── test_timezones.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── series/
│       │       │   │   │   ├── accessors/
│       │       │   │   │   │   ├── test_cat_accessor.py
│       │       │   │   │   │   ├── test_dt_accessor.py
│       │       │   │   │   │   ├── test_list_accessor.py
│       │       │   │   │   │   ├── test_sparse_accessor.py
│       │       │   │   │   │   ├── test_struct_accessor.py
│       │       │   │   │   │   ├── test_str_accessor.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── indexing/
│       │       │   │   │   │   ├── test_datetime.py
│       │       │   │   │   │   ├── test_delitem.py
│       │       │   │   │   │   ├── test_get.py
│       │       │   │   │   │   ├── test_getitem.py
│       │       │   │   │   │   ├── test_indexing.py
│       │       │   │   │   │   ├── test_mask.py
│       │       │   │   │   │   ├── test_setitem.py
│       │       │   │   │   │   ├── test_set_value.py
│       │       │   │   │   │   ├── test_take.py
│       │       │   │   │   │   ├── test_where.py
│       │       │   │   │   │   ├── test_xs.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── methods/
│       │       │   │   │   │   ├── test_add_prefix_suffix.py
│       │       │   │   │   │   ├── test_align.py
│       │       │   │   │   │   ├── test_argsort.py
│       │       │   │   │   │   ├── test_asof.py
│       │       │   │   │   │   ├── test_astype.py
│       │       │   │   │   │   ├── test_autocorr.py
│       │       │   │   │   │   ├── test_between.py
│       │       │   │   │   │   ├── test_case_when.py
│       │       │   │   │   │   ├── test_clip.py
│       │       │   │   │   │   ├── test_combine.py
│       │       │   │   │   │   ├── test_combine_first.py
│       │       │   │   │   │   ├── test_compare.py
│       │       │   │   │   │   ├── test_convert_dtypes.py
│       │       │   │   │   │   ├── test_copy.py
│       │       │   │   │   │   ├── test_count.py
│       │       │   │   │   │   ├── test_cov_corr.py
│       │       │   │   │   │   ├── test_describe.py
│       │       │   │   │   │   ├── test_diff.py
│       │       │   │   │   │   ├── test_drop.py
│       │       │   │   │   │   ├── test_dropna.py
│       │       │   │   │   │   ├── test_drop_duplicates.py
│       │       │   │   │   │   ├── test_dtypes.py
│       │       │   │   │   │   ├── test_duplicated.py
│       │       │   │   │   │   ├── test_equals.py
│       │       │   │   │   │   ├── test_explode.py
│       │       │   │   │   │   ├── test_fillna.py
│       │       │   │   │   │   ├── test_get_numeric_data.py
│       │       │   │   │   │   ├── test_head_tail.py
│       │       │   │   │   │   ├── test_infer_objects.py
│       │       │   │   │   │   ├── test_info.py
│       │       │   │   │   │   ├── test_interpolate.py
│       │       │   │   │   │   ├── test_isin.py
│       │       │   │   │   │   ├── test_isna.py
│       │       │   │   │   │   ├── test_is_monotonic.py
│       │       │   │   │   │   ├── test_is_unique.py
│       │       │   │   │   │   ├── test_item.py
│       │       │   │   │   │   ├── test_map.py
│       │       │   │   │   │   ├── test_matmul.py
│       │       │   │   │   │   ├── test_nlargest.py
│       │       │   │   │   │   ├── test_nunique.py
│       │       │   │   │   │   ├── test_pct_change.py
│       │       │   │   │   │   ├── test_pop.py
│       │       │   │   │   │   ├── test_quantile.py
│       │       │   │   │   │   ├── test_rank.py
│       │       │   │   │   │   ├── test_reindex.py
│       │       │   │   │   │   ├── test_reindex_like.py
│       │       │   │   │   │   ├── test_rename.py
│       │       │   │   │   │   ├── test_rename_axis.py
│       │       │   │   │   │   ├── test_repeat.py
│       │       │   │   │   │   ├── test_replace.py
│       │       │   │   │   │   ├── test_reset_index.py
│       │       │   │   │   │   ├── test_round.py
│       │       │   │   │   │   ├── test_searchsorted.py
│       │       │   │   │   │   ├── test_set_name.py
│       │       │   │   │   │   ├── test_size.py
│       │       │   │   │   │   ├── test_sort_index.py
│       │       │   │   │   │   ├── test_sort_values.py
│       │       │   │   │   │   ├── test_tolist.py
│       │       │   │   │   │   ├── test_to_csv.py
│       │       │   │   │   │   ├── test_to_dict.py
│       │       │   │   │   │   ├── test_to_frame.py
│       │       │   │   │   │   ├── test_to_numpy.py
│       │       │   │   │   │   ├── test_truncate.py
│       │       │   │   │   │   ├── test_tz_localize.py
│       │       │   │   │   │   ├── test_unique.py
│       │       │   │   │   │   ├── test_unstack.py
│       │       │   │   │   │   ├── test_update.py
│       │       │   │   │   │   ├── test_values.py
│       │       │   │   │   │   ├── test_value_counts.py
│       │       │   │   │   │   ├── test_view.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_arithmetic.py
│       │       │   │   │   ├── test_constructors.py
│       │       │   │   │   ├── test_cumulative.py
│       │       │   │   │   ├── test_formats.py
│       │       │   │   │   ├── test_iteration.py
│       │       │   │   │   ├── test_logical_ops.py
│       │       │   │   │   ├── test_missing.py
│       │       │   │   │   ├── test_npfuncs.py
│       │       │   │   │   ├── test_reductions.py
│       │       │   │   │   ├── test_subclass.py
│       │       │   │   │   ├── test_ufunc.py
│       │       │   │   │   ├── test_unary.py
│       │       │   │   │   ├── test_validate.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── strings/
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_case_justify.py
│       │       │   │   │   ├── test_cat.py
│       │       │   │   │   ├── test_extract.py
│       │       │   │   │   ├── test_find_replace.py
│       │       │   │   │   ├── test_get_dummies.py
│       │       │   │   │   ├── test_split_partition.py
│       │       │   │   │   ├── test_strings.py
│       │       │   │   │   ├── test_string_array.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── test_aggregation.py
│       │       │   │   ├── test_algos.py
│       │       │   │   ├── test_common.py
│       │       │   │   ├── test_downstream.py
│       │       │   │   ├── test_errors.py
│       │       │   │   ├── test_expressions.py
│       │       │   │   ├── test_flags.py
│       │       │   │   ├── test_multilevel.py
│       │       │   │   ├── test_nanops.py
│       │       │   │   ├── test_optional_dependency.py
│       │       │   │   ├── test_register_accessor.py
│       │       │   │   ├── test_sorting.py
│       │       │   │   ├── test_take.py
│       │       │   │   ├── tools/
│       │       │   │   │   ├── test_to_datetime.py
│       │       │   │   │   ├── test_to_numeric.py
│       │       │   │   │   ├── test_to_time.py
│       │       │   │   │   ├── test_to_timedelta.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── tseries/
│       │       │   │   │   ├── frequencies/
│       │       │   │   │   │   ├── test_frequencies.py
│       │       │   │   │   │   ├── test_freq_code.py
│       │       │   │   │   │   ├── test_inference.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── holiday/
│       │       │   │   │   │   ├── test_calendar.py
│       │       │   │   │   │   ├── test_federal.py
│       │       │   │   │   │   ├── test_holiday.py
│       │       │   │   │   │   ├── test_observance.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── offsets/
│       │       │   │   │   │   ├── common.py
│       │       │   │   │   │   ├── test_business_day.py
│       │       │   │   │   │   ├── test_business_hour.py
│       │       │   │   │   │   ├── test_business_month.py
│       │       │   │   │   │   ├── test_business_quarter.py
│       │       │   │   │   │   ├── test_business_year.py
│       │       │   │   │   │   ├── test_common.py
│       │       │   │   │   │   ├── test_custom_business_day.py
│       │       │   │   │   │   ├── test_custom_business_hour.py
│       │       │   │   │   │   ├── test_custom_business_month.py
│       │       │   │   │   │   ├── test_dst.py
│       │       │   │   │   │   ├── test_easter.py
│       │       │   │   │   │   ├── test_fiscal.py
│       │       │   │   │   │   ├── test_index.py
│       │       │   │   │   │   ├── test_month.py
│       │       │   │   │   │   ├── test_offsets.py
│       │       │   │   │   │   ├── test_offsets_properties.py
│       │       │   │   │   │   ├── test_quarter.py
│       │       │   │   │   │   ├── test_ticks.py
│       │       │   │   │   │   ├── test_week.py
│       │       │   │   │   │   ├── test_year.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── tslibs/
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_array_to_datetime.py
│       │       │   │   │   ├── test_ccalendar.py
│       │       │   │   │   ├── test_conversion.py
│       │       │   │   │   ├── test_fields.py
│       │       │   │   │   ├── test_libfrequencies.py
│       │       │   │   │   ├── test_liboffsets.py
│       │       │   │   │   ├── test_npy_units.py
│       │       │   │   │   ├── test_np_datetime.py
│       │       │   │   │   ├── test_parse_iso8601.py
│       │       │   │   │   ├── test_parsing.py
│       │       │   │   │   ├── test_period.py
│       │       │   │   │   ├── test_resolution.py
│       │       │   │   │   ├── test_strptime.py
│       │       │   │   │   ├── test_timedeltas.py
│       │       │   │   │   ├── test_timezones.py
│       │       │   │   │   ├── test_to_offset.py
│       │       │   │   │   ├── test_tzconversion.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── util/
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── test_assert_almost_equal.py
│       │       │   │   │   ├── test_assert_attr_equal.py
│       │       │   │   │   ├── test_assert_categorical_equal.py
│       │       │   │   │   ├── test_assert_extension_array_equal.py
│       │       │   │   │   ├── test_assert_frame_equal.py
│       │       │   │   │   ├── test_assert_index_equal.py
│       │       │   │   │   ├── test_assert_interval_array_equal.py
│       │       │   │   │   ├── test_assert_numpy_array_equal.py
│       │       │   │   │   ├── test_assert_produces_warning.py
│       │       │   │   │   ├── test_assert_series_equal.py
│       │       │   │   │   ├── test_deprecate.py
│       │       │   │   │   ├── test_deprecate_kwarg.py
│       │       │   │   │   ├── test_deprecate_nonkeyword_arguments.py
│       │       │   │   │   ├── test_doc.py
│       │       │   │   │   ├── test_hashing.py
│       │       │   │   │   ├── test_numba.py
│       │       │   │   │   ├── test_rewrite_warning.py
│       │       │   │   │   ├── test_shares_memory.py
│       │       │   │   │   ├── test_show_versions.py
│       │       │   │   │   ├── test_util.py
│       │       │   │   │   ├── test_validate_args.py
│       │       │   │   │   ├── test_validate_args_and_kwargs.py
│       │       │   │   │   ├── test_validate_inclusive.py
│       │       │   │   │   ├── test_validate_kwargs.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── window/
│       │       │   │   │   ├── conftest.py
│       │       │   │   │   ├── moments/
│       │       │   │   │   │   ├── conftest.py
│       │       │   │   │   │   ├── test_moments_consistency_ewm.py
│       │       │   │   │   │   ├── test_moments_consistency_expanding.py
│       │       │   │   │   │   ├── test_moments_consistency_rolling.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_api.py
│       │       │   │   │   ├── test_apply.py
│       │       │   │   │   ├── test_base_indexer.py
│       │       │   │   │   ├── test_cython_aggregations.py
│       │       │   │   │   ├── test_dtypes.py
│       │       │   │   │   ├── test_ewm.py
│       │       │   │   │   ├── test_expanding.py
│       │       │   │   │   ├── test_groupby.py
│       │       │   │   │   ├── test_numba.py
│       │       │   │   │   ├── test_online.py
│       │       │   │   │   ├── test_pairwise.py
│       │       │   │   │   ├── test_rolling.py
│       │       │   │   │   ├── test_rolling_functions.py
│       │       │   │   │   ├── test_rolling_quantile.py
│       │       │   │   │   ├── test_rolling_skew_kurt.py
│       │       │   │   │   ├── test_timeseries_window.py
│       │       │   │   │   ├── test_win_type.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── tseries/
│       │       │   │   ├── api.py
│       │       │   │   ├── frequencies.py
│       │       │   │   ├── holiday.py
│       │       │   │   ├── offsets.py
│       │       │   │   └── __init__.py
│       │       │   ├── util/
│       │       │   │   ├── version/
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _decorators.py
│       │       │   │   ├── _doctools.py
│       │       │   │   ├── _exceptions.py
│       │       │   │   ├── _print_versions.py
│       │       │   │   ├── _tester.py
│       │       │   │   ├── _test_decorators.py
│       │       │   │   ├── _validators.py
│       │       │   │   └── __init__.py
│       │       │   ├── _config/
│       │       │   │   ├── config.py
│       │       │   │   ├── dates.py
│       │       │   │   ├── display.py
│       │       │   │   ├── localization.py
│       │       │   │   └── __init__.py
│       │       │   ├── _libs/
│       │       │   │   ├── algos.cp312-win_amd64.lib
│       │       │   │   ├── algos.cp312-win_amd64.pyd
│       │       │   │   ├── algos.pyi
│       │       │   │   ├── arrays.cp312-win_amd64.lib
│       │       │   │   ├── arrays.cp312-win_amd64.pyd
│       │       │   │   ├── arrays.pyi
│       │       │   │   ├── byteswap.cp312-win_amd64.lib
│       │       │   │   ├── byteswap.cp312-win_amd64.pyd
│       │       │   │   ├── byteswap.pyi
│       │       │   │   ├── groupby.cp312-win_amd64.lib
│       │       │   │   ├── groupby.cp312-win_amd64.pyd
│       │       │   │   ├── groupby.pyi
│       │       │   │   ├── hashing.cp312-win_amd64.lib
│       │       │   │   ├── hashing.cp312-win_amd64.pyd
│       │       │   │   ├── hashing.pyi
│       │       │   │   ├── hashtable.cp312-win_amd64.lib
│       │       │   │   ├── hashtable.cp312-win_amd64.pyd
│       │       │   │   ├── hashtable.pyi
│       │       │   │   ├── index.cp312-win_amd64.lib
│       │       │   │   ├── index.cp312-win_amd64.pyd
│       │       │   │   ├── index.pyi
│       │       │   │   ├── indexing.cp312-win_amd64.lib
│       │       │   │   ├── indexing.cp312-win_amd64.pyd
│       │       │   │   ├── indexing.pyi
│       │       │   │   ├── internals.cp312-win_amd64.lib
│       │       │   │   ├── internals.cp312-win_amd64.pyd
│       │       │   │   ├── internals.pyi
│       │       │   │   ├── interval.cp312-win_amd64.lib
│       │       │   │   ├── interval.cp312-win_amd64.pyd
│       │       │   │   ├── interval.pyi
│       │       │   │   ├── join.cp312-win_amd64.lib
│       │       │   │   ├── join.cp312-win_amd64.pyd
│       │       │   │   ├── join.pyi
│       │       │   │   ├── json.cp312-win_amd64.lib
│       │       │   │   ├── json.cp312-win_amd64.pyd
│       │       │   │   ├── json.pyi
│       │       │   │   ├── lib.cp312-win_amd64.lib
│       │       │   │   ├── lib.cp312-win_amd64.pyd
│       │       │   │   ├── lib.pyi
│       │       │   │   ├── missing.cp312-win_amd64.lib
│       │       │   │   ├── missing.cp312-win_amd64.pyd
│       │       │   │   ├── missing.pyi
│       │       │   │   ├── ops.cp312-win_amd64.lib
│       │       │   │   ├── ops.cp312-win_amd64.pyd
│       │       │   │   ├── ops.pyi
│       │       │   │   ├── ops_dispatch.cp312-win_amd64.lib
│       │       │   │   ├── ops_dispatch.cp312-win_amd64.pyd
│       │       │   │   ├── ops_dispatch.pyi
│       │       │   │   ├── pandas_datetime.cp312-win_amd64.lib
│       │       │   │   ├── pandas_datetime.cp312-win_amd64.pyd
│       │       │   │   ├── pandas_parser.cp312-win_amd64.lib
│       │       │   │   ├── pandas_parser.cp312-win_amd64.pyd
│       │       │   │   ├── parsers.cp312-win_amd64.lib
│       │       │   │   ├── parsers.cp312-win_amd64.pyd
│       │       │   │   ├── parsers.pyi
│       │       │   │   ├── properties.cp312-win_amd64.lib
│       │       │   │   ├── properties.cp312-win_amd64.pyd
│       │       │   │   ├── properties.pyi
│       │       │   │   ├── reshape.cp312-win_amd64.lib
│       │       │   │   ├── reshape.cp312-win_amd64.pyd
│       │       │   │   ├── reshape.pyi
│       │       │   │   ├── sas.cp312-win_amd64.lib
│       │       │   │   ├── sas.cp312-win_amd64.pyd
│       │       │   │   ├── sas.pyi
│       │       │   │   ├── sparse.cp312-win_amd64.lib
│       │       │   │   ├── sparse.cp312-win_amd64.pyd
│       │       │   │   ├── sparse.pyi
│       │       │   │   ├── testing.cp312-win_amd64.lib
│       │       │   │   ├── testing.cp312-win_amd64.pyd
│       │       │   │   ├── testing.pyi
│       │       │   │   ├── tslib.cp312-win_amd64.lib
│       │       │   │   ├── tslib.cp312-win_amd64.pyd
│       │       │   │   ├── tslib.pyi
│       │       │   │   ├── tslibs/
│       │       │   │   │   ├── base.cp312-win_amd64.lib
│       │       │   │   │   ├── base.cp312-win_amd64.pyd
│       │       │   │   │   ├── ccalendar.cp312-win_amd64.lib
│       │       │   │   │   ├── ccalendar.cp312-win_amd64.pyd
│       │       │   │   │   ├── ccalendar.pyi
│       │       │   │   │   ├── conversion.cp312-win_amd64.lib
│       │       │   │   │   ├── conversion.cp312-win_amd64.pyd
│       │       │   │   │   ├── conversion.pyi
│       │       │   │   │   ├── dtypes.cp312-win_amd64.lib
│       │       │   │   │   ├── dtypes.cp312-win_amd64.pyd
│       │       │   │   │   ├── dtypes.pyi
│       │       │   │   │   ├── fields.cp312-win_amd64.lib
│       │       │   │   │   ├── fields.cp312-win_amd64.pyd
│       │       │   │   │   ├── fields.pyi
│       │       │   │   │   ├── nattype.cp312-win_amd64.lib
│       │       │   │   │   ├── nattype.cp312-win_amd64.pyd
│       │       │   │   │   ├── nattype.pyi
│       │       │   │   │   ├── np_datetime.cp312-win_amd64.lib
│       │       │   │   │   ├── np_datetime.cp312-win_amd64.pyd
│       │       │   │   │   ├── np_datetime.pyi
│       │       │   │   │   ├── offsets.cp312-win_amd64.lib
│       │       │   │   │   ├── offsets.cp312-win_amd64.pyd
│       │       │   │   │   ├── offsets.pyi
│       │       │   │   │   ├── parsing.cp312-win_amd64.lib
│       │       │   │   │   ├── parsing.cp312-win_amd64.pyd
│       │       │   │   │   ├── parsing.pyi
│       │       │   │   │   ├── period.cp312-win_amd64.lib
│       │       │   │   │   ├── period.cp312-win_amd64.pyd
│       │       │   │   │   ├── period.pyi
│       │       │   │   │   ├── strptime.cp312-win_amd64.lib
│       │       │   │   │   ├── strptime.cp312-win_amd64.pyd
│       │       │   │   │   ├── strptime.pyi
│       │       │   │   │   ├── timedeltas.cp312-win_amd64.lib
│       │       │   │   │   ├── timedeltas.cp312-win_amd64.pyd
│       │       │   │   │   ├── timedeltas.pyi
│       │       │   │   │   ├── timestamps.cp312-win_amd64.lib
│       │       │   │   │   ├── timestamps.cp312-win_amd64.pyd
│       │       │   │   │   ├── timestamps.pyi
│       │       │   │   │   ├── timezones.cp312-win_amd64.lib
│       │       │   │   │   ├── timezones.cp312-win_amd64.pyd
│       │       │   │   │   ├── timezones.pyi
│       │       │   │   │   ├── tzconversion.cp312-win_amd64.lib
│       │       │   │   │   ├── tzconversion.cp312-win_amd64.pyd
│       │       │   │   │   ├── tzconversion.pyi
│       │       │   │   │   ├── vectorized.cp312-win_amd64.lib
│       │       │   │   │   ├── vectorized.cp312-win_amd64.pyd
│       │       │   │   │   ├── vectorized.pyi
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── window/
│       │       │   │   │   ├── aggregations.cp312-win_amd64.lib
│       │       │   │   │   ├── aggregations.cp312-win_amd64.pyd
│       │       │   │   │   ├── aggregations.pyi
│       │       │   │   │   ├── indexers.cp312-win_amd64.lib
│       │       │   │   │   ├── indexers.cp312-win_amd64.pyd
│       │       │   │   │   ├── indexers.pyi
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── writers.cp312-win_amd64.lib
│       │       │   │   ├── writers.cp312-win_amd64.pyd
│       │       │   │   ├── writers.pyi
│       │       │   │   └── __init__.py
│       │       │   ├── _testing/
│       │       │   │   ├── asserters.py
│       │       │   │   ├── compat.py
│       │       │   │   ├── contexts.py
│       │       │   │   ├── _hypothesis.py
│       │       │   │   ├── _io.py
│       │       │   │   ├── _warnings.py
│       │       │   │   └── __init__.py
│       │       │   ├── _typing.py
│       │       │   ├── _version.py
│       │       │   ├── _version_meson.py
│       │       │   └── __init__.py
│       │       ├── pandas-2.3.0.dist-info/
│       │       │   ├── DELVEWHEEL
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   └── WHEEL
│       │       ├── pandas.libs/
│       │       │   └── msvcp140-1a0962f2a91a74c6d7136a768987a591.dll
│       │       ├── pip/
│       │       │   ├── py.typed
│       │       │   ├── _internal/
│       │       │   │   ├── build_env.py
│       │       │   │   ├── cache.py
│       │       │   │   ├── cli/
│       │       │   │   │   ├── autocompletion.py
│       │       │   │   │   ├── base_command.py
│       │       │   │   │   ├── cmdoptions.py
│       │       │   │   │   ├── command_context.py
│       │       │   │   │   ├── main.py
│       │       │   │   │   ├── main_parser.py
│       │       │   │   │   ├── parser.py
│       │       │   │   │   ├── progress_bars.py
│       │       │   │   │   ├── req_command.py
│       │       │   │   │   ├── spinners.py
│       │       │   │   │   ├── status_codes.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── commands/
│       │       │   │   │   ├── cache.py
│       │       │   │   │   ├── check.py
│       │       │   │   │   ├── completion.py
│       │       │   │   │   ├── configuration.py
│       │       │   │   │   ├── debug.py
│       │       │   │   │   ├── download.py
│       │       │   │   │   ├── freeze.py
│       │       │   │   │   ├── hash.py
│       │       │   │   │   ├── help.py
│       │       │   │   │   ├── index.py
│       │       │   │   │   ├── inspect.py
│       │       │   │   │   ├── install.py
│       │       │   │   │   ├── list.py
│       │       │   │   │   ├── search.py
│       │       │   │   │   ├── show.py
│       │       │   │   │   ├── uninstall.py
│       │       │   │   │   ├── wheel.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── configuration.py
│       │       │   │   ├── distributions/
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── installed.py
│       │       │   │   │   ├── sdist.py
│       │       │   │   │   ├── wheel.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── exceptions.py
│       │       │   │   ├── index/
│       │       │   │   │   ├── collector.py
│       │       │   │   │   ├── package_finder.py
│       │       │   │   │   ├── sources.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── locations/
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── _distutils.py
│       │       │   │   │   ├── _sysconfig.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── main.py
│       │       │   │   ├── metadata/
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── importlib/
│       │       │   │   │   │   ├── _compat.py
│       │       │   │   │   │   ├── _dists.py
│       │       │   │   │   │   ├── _envs.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── pkg_resources.py
│       │       │   │   │   ├── _json.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── models/
│       │       │   │   │   ├── candidate.py
│       │       │   │   │   ├── direct_url.py
│       │       │   │   │   ├── format_control.py
│       │       │   │   │   ├── index.py
│       │       │   │   │   ├── installation_report.py
│       │       │   │   │   ├── link.py
│       │       │   │   │   ├── scheme.py
│       │       │   │   │   ├── search_scope.py
│       │       │   │   │   ├── selection_prefs.py
│       │       │   │   │   ├── target_python.py
│       │       │   │   │   ├── wheel.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── network/
│       │       │   │   │   ├── auth.py
│       │       │   │   │   ├── cache.py
│       │       │   │   │   ├── download.py
│       │       │   │   │   ├── lazy_wheel.py
│       │       │   │   │   ├── session.py
│       │       │   │   │   ├── utils.py
│       │       │   │   │   ├── xmlrpc.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── operations/
│       │       │   │   │   ├── check.py
│       │       │   │   │   ├── freeze.py
│       │       │   │   │   ├── install/
│       │       │   │   │   │   ├── editable_legacy.py
│       │       │   │   │   │   ├── wheel.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── prepare.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── pyproject.py
│       │       │   │   ├── req/
│       │       │   │   │   ├── constructors.py
│       │       │   │   │   ├── req_file.py
│       │       │   │   │   ├── req_install.py
│       │       │   │   │   ├── req_set.py
│       │       │   │   │   ├── req_uninstall.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── resolution/
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── legacy/
│       │       │   │   │   │   ├── resolver.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── resolvelib/
│       │       │   │   │   │   ├── base.py
│       │       │   │   │   │   ├── candidates.py
│       │       │   │   │   │   ├── factory.py
│       │       │   │   │   │   ├── found_candidates.py
│       │       │   │   │   │   ├── provider.py
│       │       │   │   │   │   ├── reporter.py
│       │       │   │   │   │   ├── requirements.py
│       │       │   │   │   │   ├── resolver.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── self_outdated_check.py
│       │       │   │   ├── utils/
│       │       │   │   │   ├── appdirs.py
│       │       │   │   │   ├── compat.py
│       │       │   │   │   ├── compatibility_tags.py
│       │       │   │   │   ├── datetime.py
│       │       │   │   │   ├── deprecation.py
│       │       │   │   │   ├── direct_url_helpers.py
│       │       │   │   │   ├── egg_link.py
│       │       │   │   │   ├── encoding.py
│       │       │   │   │   ├── entrypoints.py
│       │       │   │   │   ├── filesystem.py
│       │       │   │   │   ├── filetypes.py
│       │       │   │   │   ├── glibc.py
│       │       │   │   │   ├── hashes.py
│       │       │   │   │   ├── logging.py
│       │       │   │   │   ├── misc.py
│       │       │   │   │   ├── models.py
│       │       │   │   │   ├── packaging.py
│       │       │   │   │   ├── setuptools_build.py
│       │       │   │   │   ├── subprocess.py
│       │       │   │   │   ├── temp_dir.py
│       │       │   │   │   ├── unpacking.py
│       │       │   │   │   ├── urls.py
│       │       │   │   │   ├── virtualenv.py
│       │       │   │   │   ├── wheel.py
│       │       │   │   │   ├── _jaraco_text.py
│       │       │   │   │   ├── _log.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── vcs/
│       │       │   │   │   ├── bazaar.py
│       │       │   │   │   ├── git.py
│       │       │   │   │   ├── mercurial.py
│       │       │   │   │   ├── subversion.py
│       │       │   │   │   ├── versioncontrol.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── wheel_builder.py
│       │       │   │   └── __init__.py
│       │       │   ├── _vendor/
│       │       │   │   ├── cachecontrol/
│       │       │   │   │   ├── adapter.py
│       │       │   │   │   ├── cache.py
│       │       │   │   │   ├── caches/
│       │       │   │   │   │   ├── file_cache.py
│       │       │   │   │   │   ├── redis_cache.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── controller.py
│       │       │   │   │   ├── filewrapper.py
│       │       │   │   │   ├── heuristics.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── serialize.py
│       │       │   │   │   ├── wrapper.py
│       │       │   │   │   ├── _cmd.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── certifi/
│       │       │   │   │   ├── cacert.pem
│       │       │   │   │   ├── core.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── __init__.py
│       │       │   │   │   └── __main__.py
│       │       │   │   ├── chardet/
│       │       │   │   │   ├── big5freq.py
│       │       │   │   │   ├── big5prober.py
│       │       │   │   │   ├── chardistribution.py
│       │       │   │   │   ├── charsetgroupprober.py
│       │       │   │   │   ├── charsetprober.py
│       │       │   │   │   ├── cli/
│       │       │   │   │   │   ├── chardetect.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── codingstatemachine.py
│       │       │   │   │   ├── codingstatemachinedict.py
│       │       │   │   │   ├── cp949prober.py
│       │       │   │   │   ├── enums.py
│       │       │   │   │   ├── escprober.py
│       │       │   │   │   ├── escsm.py
│       │       │   │   │   ├── eucjpprober.py
│       │       │   │   │   ├── euckrfreq.py
│       │       │   │   │   ├── euckrprober.py
│       │       │   │   │   ├── euctwfreq.py
│       │       │   │   │   ├── euctwprober.py
│       │       │   │   │   ├── gb2312freq.py
│       │       │   │   │   ├── gb2312prober.py
│       │       │   │   │   ├── hebrewprober.py
│       │       │   │   │   ├── jisfreq.py
│       │       │   │   │   ├── johabfreq.py
│       │       │   │   │   ├── johabprober.py
│       │       │   │   │   ├── jpcntx.py
│       │       │   │   │   ├── langbulgarianmodel.py
│       │       │   │   │   ├── langgreekmodel.py
│       │       │   │   │   ├── langhebrewmodel.py
│       │       │   │   │   ├── langhungarianmodel.py
│       │       │   │   │   ├── langrussianmodel.py
│       │       │   │   │   ├── langthaimodel.py
│       │       │   │   │   ├── langturkishmodel.py
│       │       │   │   │   ├── latin1prober.py
│       │       │   │   │   ├── macromanprober.py
│       │       │   │   │   ├── mbcharsetprober.py
│       │       │   │   │   ├── mbcsgroupprober.py
│       │       │   │   │   ├── mbcssm.py
│       │       │   │   │   ├── metadata/
│       │       │   │   │   │   ├── languages.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── resultdict.py
│       │       │   │   │   ├── sbcharsetprober.py
│       │       │   │   │   ├── sbcsgroupprober.py
│       │       │   │   │   ├── sjisprober.py
│       │       │   │   │   ├── universaldetector.py
│       │       │   │   │   ├── utf1632prober.py
│       │       │   │   │   ├── utf8prober.py
│       │       │   │   │   ├── version.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── colorama/
│       │       │   │   │   ├── ansi.py
│       │       │   │   │   ├── ansitowin32.py
│       │       │   │   │   ├── initialise.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── ansitowin32_test.py
│       │       │   │   │   │   ├── ansi_test.py
│       │       │   │   │   │   ├── initialise_test.py
│       │       │   │   │   │   ├── isatty_test.py
│       │       │   │   │   │   ├── utils.py
│       │       │   │   │   │   ├── winterm_test.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── win32.py
│       │       │   │   │   ├── winterm.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── distlib/
│       │       │   │   │   ├── compat.py
│       │       │   │   │   ├── database.py
│       │       │   │   │   ├── index.py
│       │       │   │   │   ├── locators.py
│       │       │   │   │   ├── manifest.py
│       │       │   │   │   ├── markers.py
│       │       │   │   │   ├── metadata.py
│       │       │   │   │   ├── resources.py
│       │       │   │   │   ├── scripts.py
│       │       │   │   │   ├── t32.exe
│       │       │   │   │   ├── t64-arm.exe
│       │       │   │   │   ├── t64.exe
│       │       │   │   │   ├── util.py
│       │       │   │   │   ├── version.py
│       │       │   │   │   ├── w32.exe
│       │       │   │   │   ├── w64-arm.exe
│       │       │   │   │   ├── w64.exe
│       │       │   │   │   ├── wheel.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── distro/
│       │       │   │   │   ├── distro.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── __init__.py
│       │       │   │   │   └── __main__.py
│       │       │   │   ├── idna/
│       │       │   │   │   ├── codec.py
│       │       │   │   │   ├── compat.py
│       │       │   │   │   ├── core.py
│       │       │   │   │   ├── idnadata.py
│       │       │   │   │   ├── intranges.py
│       │       │   │   │   ├── package_data.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── uts46data.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── msgpack/
│       │       │   │   │   ├── exceptions.py
│       │       │   │   │   ├── ext.py
│       │       │   │   │   ├── fallback.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── packaging/
│       │       │   │   │   ├── markers.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── requirements.py
│       │       │   │   │   ├── specifiers.py
│       │       │   │   │   ├── tags.py
│       │       │   │   │   ├── utils.py
│       │       │   │   │   ├── version.py
│       │       │   │   │   ├── _manylinux.py
│       │       │   │   │   ├── _musllinux.py
│       │       │   │   │   ├── _structures.py
│       │       │   │   │   ├── __about__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── pkg_resources/
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── platformdirs/
│       │       │   │   │   ├── android.py
│       │       │   │   │   ├── api.py
│       │       │   │   │   ├── macos.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── unix.py
│       │       │   │   │   ├── version.py
│       │       │   │   │   ├── windows.py
│       │       │   │   │   ├── __init__.py
│       │       │   │   │   └── __main__.py
│       │       │   │   ├── pygments/
│       │       │   │   │   ├── cmdline.py
│       │       │   │   │   ├── console.py
│       │       │   │   │   ├── filter.py
│       │       │   │   │   ├── filters/
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── formatter.py
│       │       │   │   │   ├── formatters/
│       │       │   │   │   │   ├── bbcode.py
│       │       │   │   │   │   ├── groff.py
│       │       │   │   │   │   ├── html.py
│       │       │   │   │   │   ├── img.py
│       │       │   │   │   │   ├── irc.py
│       │       │   │   │   │   ├── latex.py
│       │       │   │   │   │   ├── other.py
│       │       │   │   │   │   ├── pangomarkup.py
│       │       │   │   │   │   ├── rtf.py
│       │       │   │   │   │   ├── svg.py
│       │       │   │   │   │   ├── terminal.py
│       │       │   │   │   │   ├── terminal256.py
│       │       │   │   │   │   ├── _mapping.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── lexer.py
│       │       │   │   │   ├── lexers/
│       │       │   │   │   │   ├── python.py
│       │       │   │   │   │   ├── _mapping.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── modeline.py
│       │       │   │   │   ├── plugin.py
│       │       │   │   │   ├── regexopt.py
│       │       │   │   │   ├── scanner.py
│       │       │   │   │   ├── sphinxext.py
│       │       │   │   │   ├── style.py
│       │       │   │   │   ├── styles/
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── token.py
│       │       │   │   │   ├── unistring.py
│       │       │   │   │   ├── util.py
│       │       │   │   │   ├── __init__.py
│       │       │   │   │   └── __main__.py
│       │       │   │   ├── pyparsing/
│       │       │   │   │   ├── actions.py
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── core.py
│       │       │   │   │   ├── diagram/
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── exceptions.py
│       │       │   │   │   ├── helpers.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── results.py
│       │       │   │   │   ├── testing.py
│       │       │   │   │   ├── unicode.py
│       │       │   │   │   ├── util.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── pyproject_hooks/
│       │       │   │   │   ├── _compat.py
│       │       │   │   │   ├── _impl.py
│       │       │   │   │   ├── _in_process/
│       │       │   │   │   │   ├── _in_process.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── requests/
│       │       │   │   │   ├── adapters.py
│       │       │   │   │   ├── api.py
│       │       │   │   │   ├── auth.py
│       │       │   │   │   ├── certs.py
│       │       │   │   │   ├── compat.py
│       │       │   │   │   ├── cookies.py
│       │       │   │   │   ├── exceptions.py
│       │       │   │   │   ├── help.py
│       │       │   │   │   ├── hooks.py
│       │       │   │   │   ├── models.py
│       │       │   │   │   ├── packages.py
│       │       │   │   │   ├── sessions.py
│       │       │   │   │   ├── status_codes.py
│       │       │   │   │   ├── structures.py
│       │       │   │   │   ├── utils.py
│       │       │   │   │   ├── _internal_utils.py
│       │       │   │   │   ├── __init__.py
│       │       │   │   │   └── __version__.py
│       │       │   │   ├── resolvelib/
│       │       │   │   │   ├── compat/
│       │       │   │   │   │   ├── collections_abc.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── providers.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── reporters.py
│       │       │   │   │   ├── resolvers.py
│       │       │   │   │   ├── structs.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── rich/
│       │       │   │   │   ├── abc.py
│       │       │   │   │   ├── align.py
│       │       │   │   │   ├── ansi.py
│       │       │   │   │   ├── bar.py
│       │       │   │   │   ├── box.py
│       │       │   │   │   ├── cells.py
│       │       │   │   │   ├── color.py
│       │       │   │   │   ├── color_triplet.py
│       │       │   │   │   ├── columns.py
│       │       │   │   │   ├── console.py
│       │       │   │   │   ├── constrain.py
│       │       │   │   │   ├── containers.py
│       │       │   │   │   ├── control.py
│       │       │   │   │   ├── default_styles.py
│       │       │   │   │   ├── diagnose.py
│       │       │   │   │   ├── emoji.py
│       │       │   │   │   ├── errors.py
│       │       │   │   │   ├── filesize.py
│       │       │   │   │   ├── file_proxy.py
│       │       │   │   │   ├── highlighter.py
│       │       │   │   │   ├── json.py
│       │       │   │   │   ├── jupyter.py
│       │       │   │   │   ├── layout.py
│       │       │   │   │   ├── live.py
│       │       │   │   │   ├── live_render.py
│       │       │   │   │   ├── logging.py
│       │       │   │   │   ├── markup.py
│       │       │   │   │   ├── measure.py
│       │       │   │   │   ├── padding.py
│       │       │   │   │   ├── pager.py
│       │       │   │   │   ├── palette.py
│       │       │   │   │   ├── panel.py
│       │       │   │   │   ├── pretty.py
│       │       │   │   │   ├── progress.py
│       │       │   │   │   ├── progress_bar.py
│       │       │   │   │   ├── prompt.py
│       │       │   │   │   ├── protocol.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── region.py
│       │       │   │   │   ├── repr.py
│       │       │   │   │   ├── rule.py
│       │       │   │   │   ├── scope.py
│       │       │   │   │   ├── screen.py
│       │       │   │   │   ├── segment.py
│       │       │   │   │   ├── spinner.py
│       │       │   │   │   ├── status.py
│       │       │   │   │   ├── style.py
│       │       │   │   │   ├── styled.py
│       │       │   │   │   ├── syntax.py
│       │       │   │   │   ├── table.py
│       │       │   │   │   ├── terminal_theme.py
│       │       │   │   │   ├── text.py
│       │       │   │   │   ├── theme.py
│       │       │   │   │   ├── themes.py
│       │       │   │   │   ├── traceback.py
│       │       │   │   │   ├── tree.py
│       │       │   │   │   ├── _cell_widths.py
│       │       │   │   │   ├── _emoji_codes.py
│       │       │   │   │   ├── _emoji_replace.py
│       │       │   │   │   ├── _export_format.py
│       │       │   │   │   ├── _extension.py
│       │       │   │   │   ├── _fileno.py
│       │       │   │   │   ├── _inspect.py
│       │       │   │   │   ├── _log_render.py
│       │       │   │   │   ├── _loop.py
│       │       │   │   │   ├── _null_file.py
│       │       │   │   │   ├── _palettes.py
│       │       │   │   │   ├── _pick.py
│       │       │   │   │   ├── _ratio.py
│       │       │   │   │   ├── _spinners.py
│       │       │   │   │   ├── _stack.py
│       │       │   │   │   ├── _timer.py
│       │       │   │   │   ├── _win32_console.py
│       │       │   │   │   ├── _windows.py
│       │       │   │   │   ├── _windows_renderer.py
│       │       │   │   │   ├── _wrap.py
│       │       │   │   │   ├── __init__.py
│       │       │   │   │   └── __main__.py
│       │       │   │   ├── six.py
│       │       │   │   ├── tenacity/
│       │       │   │   │   ├── after.py
│       │       │   │   │   ├── before.py
│       │       │   │   │   ├── before_sleep.py
│       │       │   │   │   ├── nap.py
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── retry.py
│       │       │   │   │   ├── stop.py
│       │       │   │   │   ├── tornadoweb.py
│       │       │   │   │   ├── wait.py
│       │       │   │   │   ├── _asyncio.py
│       │       │   │   │   ├── _utils.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── tomli/
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── _parser.py
│       │       │   │   │   ├── _re.py
│       │       │   │   │   ├── _types.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── truststore/
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── _api.py
│       │       │   │   │   ├── _macos.py
│       │       │   │   │   ├── _openssl.py
│       │       │   │   │   ├── _ssl_constants.py
│       │       │   │   │   ├── _windows.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── typing_extensions.py
│       │       │   │   ├── urllib3/
│       │       │   │   │   ├── connection.py
│       │       │   │   │   ├── connectionpool.py
│       │       │   │   │   ├── contrib/
│       │       │   │   │   │   ├── appengine.py
│       │       │   │   │   │   ├── ntlmpool.py
│       │       │   │   │   │   ├── pyopenssl.py
│       │       │   │   │   │   ├── securetransport.py
│       │       │   │   │   │   ├── socks.py
│       │       │   │   │   │   ├── _appengine_environ.py
│       │       │   │   │   │   ├── _securetransport/
│       │       │   │   │   │   │   ├── bindings.py
│       │       │   │   │   │   │   ├── low_level.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── exceptions.py
│       │       │   │   │   ├── fields.py
│       │       │   │   │   ├── filepost.py
│       │       │   │   │   ├── packages/
│       │       │   │   │   │   ├── backports/
│       │       │   │   │   │   │   ├── makefile.py
│       │       │   │   │   │   │   ├── weakref_finalize.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── six.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── poolmanager.py
│       │       │   │   │   ├── request.py
│       │       │   │   │   ├── response.py
│       │       │   │   │   ├── util/
│       │       │   │   │   │   ├── connection.py
│       │       │   │   │   │   ├── proxy.py
│       │       │   │   │   │   ├── queue.py
│       │       │   │   │   │   ├── request.py
│       │       │   │   │   │   ├── response.py
│       │       │   │   │   │   ├── retry.py
│       │       │   │   │   │   ├── ssltransport.py
│       │       │   │   │   │   ├── ssl_.py
│       │       │   │   │   │   ├── ssl_match_hostname.py
│       │       │   │   │   │   ├── timeout.py
│       │       │   │   │   │   ├── url.py
│       │       │   │   │   │   ├── wait.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _collections.py
│       │       │   │   │   ├── _version.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── vendor.txt
│       │       │   │   ├── webencodings/
│       │       │   │   │   ├── labels.py
│       │       │   │   │   ├── mklabels.py
│       │       │   │   │   ├── tests.py
│       │       │   │   │   ├── x_user_defined.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── __init__.py
│       │       │   ├── __main__.py
│       │       │   └── __pip-runner__.py
│       │       ├── pip-24.0.dist-info/
│       │       │   ├── AUTHORS.txt
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── pydantic/
│       │       │   ├── aliases.py
│       │       │   ├── alias_generators.py
│       │       │   ├── annotated_handlers.py
│       │       │   ├── class_validators.py
│       │       │   ├── color.py
│       │       │   ├── config.py
│       │       │   ├── dataclasses.py
│       │       │   ├── datetime_parse.py
│       │       │   ├── decorator.py
│       │       │   ├── deprecated/
│       │       │   │   ├── class_validators.py
│       │       │   │   ├── config.py
│       │       │   │   ├── copy_internals.py
│       │       │   │   ├── decorator.py
│       │       │   │   ├── json.py
│       │       │   │   ├── parse.py
│       │       │   │   ├── tools.py
│       │       │   │   └── __init__.py
│       │       │   ├── env_settings.py
│       │       │   ├── errors.py
│       │       │   ├── error_wrappers.py
│       │       │   ├── experimental/
│       │       │   │   ├── arguments_schema.py
│       │       │   │   ├── pipeline.py
│       │       │   │   └── __init__.py
│       │       │   ├── fields.py
│       │       │   ├── functional_serializers.py
│       │       │   ├── functional_validators.py
│       │       │   ├── generics.py
│       │       │   ├── json.py
│       │       │   ├── json_schema.py
│       │       │   ├── main.py
│       │       │   ├── mypy.py
│       │       │   ├── networks.py
│       │       │   ├── parse.py
│       │       │   ├── plugin/
│       │       │   │   ├── _loader.py
│       │       │   │   ├── _schema_validator.py
│       │       │   │   └── __init__.py
│       │       │   ├── py.typed
│       │       │   ├── root_model.py
│       │       │   ├── schema.py
│       │       │   ├── tools.py
│       │       │   ├── types.py
│       │       │   ├── type_adapter.py
│       │       │   ├── typing.py
│       │       │   ├── utils.py
│       │       │   ├── v1/
│       │       │   │   ├── annotated_types.py
│       │       │   │   ├── class_validators.py
│       │       │   │   ├── color.py
│       │       │   │   ├── config.py
│       │       │   │   ├── dataclasses.py
│       │       │   │   ├── datetime_parse.py
│       │       │   │   ├── decorator.py
│       │       │   │   ├── env_settings.py
│       │       │   │   ├── errors.py
│       │       │   │   ├── error_wrappers.py
│       │       │   │   ├── fields.py
│       │       │   │   ├── generics.py
│       │       │   │   ├── json.py
│       │       │   │   ├── main.py
│       │       │   │   ├── mypy.py
│       │       │   │   ├── networks.py
│       │       │   │   ├── parse.py
│       │       │   │   ├── py.typed
│       │       │   │   ├── schema.py
│       │       │   │   ├── tools.py
│       │       │   │   ├── types.py
│       │       │   │   ├── typing.py
│       │       │   │   ├── utils.py
│       │       │   │   ├── validators.py
│       │       │   │   ├── version.py
│       │       │   │   ├── _hypothesis_plugin.py
│       │       │   │   └── __init__.py
│       │       │   ├── validate_call_decorator.py
│       │       │   ├── validators.py
│       │       │   ├── version.py
│       │       │   ├── warnings.py
│       │       │   ├── _internal/
│       │       │   │   ├── _config.py
│       │       │   │   ├── _core_metadata.py
│       │       │   │   ├── _core_utils.py
│       │       │   │   ├── _dataclasses.py
│       │       │   │   ├── _decorators.py
│       │       │   │   ├── _decorators_v1.py
│       │       │   │   ├── _discriminated_union.py
│       │       │   │   ├── _docs_extraction.py
│       │       │   │   ├── _fields.py
│       │       │   │   ├── _forward_ref.py
│       │       │   │   ├── _generate_schema.py
│       │       │   │   ├── _generics.py
│       │       │   │   ├── _git.py
│       │       │   │   ├── _import_utils.py
│       │       │   │   ├── _internal_dataclass.py
│       │       │   │   ├── _known_annotated_metadata.py
│       │       │   │   ├── _mock_val_ser.py
│       │       │   │   ├── _model_construction.py
│       │       │   │   ├── _namespace_utils.py
│       │       │   │   ├── _repr.py
│       │       │   │   ├── _schema_gather.py
│       │       │   │   ├── _schema_generation_shared.py
│       │       │   │   ├── _serializers.py
│       │       │   │   ├── _signature.py
│       │       │   │   ├── _typing_extra.py
│       │       │   │   ├── _utils.py
│       │       │   │   ├── _validate_call.py
│       │       │   │   ├── _validators.py
│       │       │   │   └── __init__.py
│       │       │   ├── _migration.py
│       │       │   └── __init__.py
│       │       ├── pydantic-2.11.7.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── pydantic_core/
│       │       │   ├── core_schema.py
│       │       │   ├── py.typed
│       │       │   ├── _pydantic_core.cp312-win_amd64.pyd
│       │       │   ├── _pydantic_core.pyi
│       │       │   └── __init__.py
│       │       ├── pydantic_core-2.33.2.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── python_dateutil-2.9.0.post0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   ├── WHEEL
│       │       │   └── zip-safe
│       │       ├── python_dotenv-1.1.0.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── pytz/
│       │       │   ├── exceptions.py
│       │       │   ├── lazy.py
│       │       │   ├── reference.py
│       │       │   ├── tzfile.py
│       │       │   ├── tzinfo.py
│       │       │   ├── zoneinfo/
│       │       │   │   ├── Africa/
│       │       │   │   │   ├── Abidjan
│       │       │   │   │   ├── Accra
│       │       │   │   │   ├── Addis_Ababa
│       │       │   │   │   ├── Algiers
│       │       │   │   │   ├── Asmara
│       │       │   │   │   ├── Asmera
│       │       │   │   │   ├── Bamako
│       │       │   │   │   ├── Bangui
│       │       │   │   │   ├── Banjul
│       │       │   │   │   ├── Bissau
│       │       │   │   │   ├── Blantyre
│       │       │   │   │   ├── Brazzaville
│       │       │   │   │   ├── Bujumbura
│       │       │   │   │   ├── Cairo
│       │       │   │   │   ├── Casablanca
│       │       │   │   │   ├── Ceuta
│       │       │   │   │   ├── Conakry
│       │       │   │   │   ├── Dakar
│       │       │   │   │   ├── Dar_es_Salaam
│       │       │   │   │   ├── Djibouti
│       │       │   │   │   ├── Douala
│       │       │   │   │   ├── El_Aaiun
│       │       │   │   │   ├── Freetown
│       │       │   │   │   ├── Gaborone
│       │       │   │   │   ├── Harare
│       │       │   │   │   ├── Johannesburg
│       │       │   │   │   ├── Juba
│       │       │   │   │   ├── Kampala
│       │       │   │   │   ├── Khartoum
│       │       │   │   │   ├── Kigali
│       │       │   │   │   ├── Kinshasa
│       │       │   │   │   ├── Lagos
│       │       │   │   │   ├── Libreville
│       │       │   │   │   ├── Lome
│       │       │   │   │   ├── Luanda
│       │       │   │   │   ├── Lubumbashi
│       │       │   │   │   ├── Lusaka
│       │       │   │   │   ├── Malabo
│       │       │   │   │   ├── Maputo
│       │       │   │   │   ├── Maseru
│       │       │   │   │   ├── Mbabane
│       │       │   │   │   ├── Mogadishu
│       │       │   │   │   ├── Monrovia
│       │       │   │   │   ├── Nairobi
│       │       │   │   │   ├── Ndjamena
│       │       │   │   │   ├── Niamey
│       │       │   │   │   ├── Nouakchott
│       │       │   │   │   ├── Ouagadougou
│       │       │   │   │   ├── Porto-Novo
│       │       │   │   │   ├── Sao_Tome
│       │       │   │   │   ├── Timbuktu
│       │       │   │   │   ├── Tripoli
│       │       │   │   │   ├── Tunis
│       │       │   │   │   └── Windhoek
│       │       │   │   ├── America/
│       │       │   │   │   ├── Adak
│       │       │   │   │   ├── Anchorage
│       │       │   │   │   ├── Anguilla
│       │       │   │   │   ├── Antigua
│       │       │   │   │   ├── Araguaina
│       │       │   │   │   ├── Argentina/
│       │       │   │   │   │   ├── Buenos_Aires
│       │       │   │   │   │   ├── Catamarca
│       │       │   │   │   │   ├── ComodRivadavia
│       │       │   │   │   │   ├── Cordoba
│       │       │   │   │   │   ├── Jujuy
│       │       │   │   │   │   ├── La_Rioja
│       │       │   │   │   │   ├── Mendoza
│       │       │   │   │   │   ├── Rio_Gallegos
│       │       │   │   │   │   ├── Salta
│       │       │   │   │   │   ├── San_Juan
│       │       │   │   │   │   ├── San_Luis
│       │       │   │   │   │   ├── Tucuman
│       │       │   │   │   │   └── Ushuaia
│       │       │   │   │   ├── Aruba
│       │       │   │   │   ├── Asuncion
│       │       │   │   │   ├── Atikokan
│       │       │   │   │   ├── Atka
│       │       │   │   │   ├── Bahia
│       │       │   │   │   ├── Bahia_Banderas
│       │       │   │   │   ├── Barbados
│       │       │   │   │   ├── Belem
│       │       │   │   │   ├── Belize
│       │       │   │   │   ├── Blanc-Sablon
│       │       │   │   │   ├── Boa_Vista
│       │       │   │   │   ├── Bogota
│       │       │   │   │   ├── Boise
│       │       │   │   │   ├── Buenos_Aires
│       │       │   │   │   ├── Cambridge_Bay
│       │       │   │   │   ├── Campo_Grande
│       │       │   │   │   ├── Cancun
│       │       │   │   │   ├── Caracas
│       │       │   │   │   ├── Catamarca
│       │       │   │   │   ├── Cayenne
│       │       │   │   │   ├── Cayman
│       │       │   │   │   ├── Chicago
│       │       │   │   │   ├── Chihuahua
│       │       │   │   │   ├── Ciudad_Juarez
│       │       │   │   │   ├── Coral_Harbour
│       │       │   │   │   ├── Cordoba
│       │       │   │   │   ├── Costa_Rica
│       │       │   │   │   ├── Coyhaique
│       │       │   │   │   ├── Creston
│       │       │   │   │   ├── Cuiaba
│       │       │   │   │   ├── Curacao
│       │       │   │   │   ├── Danmarkshavn
│       │       │   │   │   ├── Dawson
│       │       │   │   │   ├── Dawson_Creek
│       │       │   │   │   ├── Denver
│       │       │   │   │   ├── Detroit
│       │       │   │   │   ├── Dominica
│       │       │   │   │   ├── Edmonton
│       │       │   │   │   ├── Eirunepe
│       │       │   │   │   ├── El_Salvador
│       │       │   │   │   ├── Ensenada
│       │       │   │   │   ├── Fortaleza
│       │       │   │   │   ├── Fort_Nelson
│       │       │   │   │   ├── Fort_Wayne
│       │       │   │   │   ├── Glace_Bay
│       │       │   │   │   ├── Godthab
│       │       │   │   │   ├── Goose_Bay
│       │       │   │   │   ├── Grand_Turk
│       │       │   │   │   ├── Grenada
│       │       │   │   │   ├── Guadeloupe
│       │       │   │   │   ├── Guatemala
│       │       │   │   │   ├── Guayaquil
│       │       │   │   │   ├── Guyana
│       │       │   │   │   ├── Halifax
│       │       │   │   │   ├── Havana
│       │       │   │   │   ├── Hermosillo
│       │       │   │   │   ├── Indiana/
│       │       │   │   │   │   ├── Indianapolis
│       │       │   │   │   │   ├── Knox
│       │       │   │   │   │   ├── Marengo
│       │       │   │   │   │   ├── Petersburg
│       │       │   │   │   │   ├── Tell_City
│       │       │   │   │   │   ├── Vevay
│       │       │   │   │   │   ├── Vincennes
│       │       │   │   │   │   └── Winamac
│       │       │   │   │   ├── Indianapolis
│       │       │   │   │   ├── Inuvik
│       │       │   │   │   ├── Iqaluit
│       │       │   │   │   ├── Jamaica
│       │       │   │   │   ├── Jujuy
│       │       │   │   │   ├── Juneau
│       │       │   │   │   ├── Kentucky/
│       │       │   │   │   │   ├── Louisville
│       │       │   │   │   │   └── Monticello
│       │       │   │   │   ├── Knox_IN
│       │       │   │   │   ├── Kralendijk
│       │       │   │   │   ├── La_Paz
│       │       │   │   │   ├── Lima
│       │       │   │   │   ├── Los_Angeles
│       │       │   │   │   ├── Louisville
│       │       │   │   │   ├── Lower_Princes
│       │       │   │   │   ├── Maceio
│       │       │   │   │   ├── Managua
│       │       │   │   │   ├── Manaus
│       │       │   │   │   ├── Marigot
│       │       │   │   │   ├── Martinique
│       │       │   │   │   ├── Matamoros
│       │       │   │   │   ├── Mazatlan
│       │       │   │   │   ├── Mendoza
│       │       │   │   │   ├── Menominee
│       │       │   │   │   ├── Merida
│       │       │   │   │   ├── Metlakatla
│       │       │   │   │   ├── Mexico_City
│       │       │   │   │   ├── Miquelon
│       │       │   │   │   ├── Moncton
│       │       │   │   │   ├── Monterrey
│       │       │   │   │   ├── Montevideo
│       │       │   │   │   ├── Montreal
│       │       │   │   │   ├── Montserrat
│       │       │   │   │   ├── Nassau
│       │       │   │   │   ├── New_York
│       │       │   │   │   ├── Nipigon
│       │       │   │   │   ├── Nome
│       │       │   │   │   ├── Noronha
│       │       │   │   │   ├── North_Dakota/
│       │       │   │   │   │   ├── Beulah
│       │       │   │   │   │   ├── Center
│       │       │   │   │   │   └── New_Salem
│       │       │   │   │   ├── Nuuk
│       │       │   │   │   ├── Ojinaga
│       │       │   │   │   ├── Panama
│       │       │   │   │   ├── Pangnirtung
│       │       │   │   │   ├── Paramaribo
│       │       │   │   │   ├── Phoenix
│       │       │   │   │   ├── Port-au-Prince
│       │       │   │   │   ├── Porto_Acre
│       │       │   │   │   ├── Porto_Velho
│       │       │   │   │   ├── Port_of_Spain
│       │       │   │   │   ├── Puerto_Rico
│       │       │   │   │   ├── Punta_Arenas
│       │       │   │   │   ├── Rainy_River
│       │       │   │   │   ├── Rankin_Inlet
│       │       │   │   │   ├── Recife
│       │       │   │   │   ├── Regina
│       │       │   │   │   ├── Resolute
│       │       │   │   │   ├── Rio_Branco
│       │       │   │   │   ├── Rosario
│       │       │   │   │   ├── Santarem
│       │       │   │   │   ├── Santa_Isabel
│       │       │   │   │   ├── Santiago
│       │       │   │   │   ├── Santo_Domingo
│       │       │   │   │   ├── Sao_Paulo
│       │       │   │   │   ├── Scoresbysund
│       │       │   │   │   ├── Shiprock
│       │       │   │   │   ├── Sitka
│       │       │   │   │   ├── St_Barthelemy
│       │       │   │   │   ├── St_Johns
│       │       │   │   │   ├── St_Kitts
│       │       │   │   │   ├── St_Lucia
│       │       │   │   │   ├── St_Thomas
│       │       │   │   │   ├── St_Vincent
│       │       │   │   │   ├── Swift_Current
│       │       │   │   │   ├── Tegucigalpa
│       │       │   │   │   ├── Thule
│       │       │   │   │   ├── Thunder_Bay
│       │       │   │   │   ├── Tijuana
│       │       │   │   │   ├── Toronto
│       │       │   │   │   ├── Tortola
│       │       │   │   │   ├── Vancouver
│       │       │   │   │   ├── Virgin
│       │       │   │   │   ├── Whitehorse
│       │       │   │   │   ├── Winnipeg
│       │       │   │   │   ├── Yakutat
│       │       │   │   │   └── Yellowknife
│       │       │   │   ├── Antarctica/
│       │       │   │   │   ├── Casey
│       │       │   │   │   ├── Davis
│       │       │   │   │   ├── DumontDUrville
│       │       │   │   │   ├── Macquarie
│       │       │   │   │   ├── Mawson
│       │       │   │   │   ├── McMurdo
│       │       │   │   │   ├── Palmer
│       │       │   │   │   ├── Rothera
│       │       │   │   │   ├── South_Pole
│       │       │   │   │   ├── Syowa
│       │       │   │   │   ├── Troll
│       │       │   │   │   └── Vostok
│       │       │   │   ├── Arctic/
│       │       │   │   │   └── Longyearbyen
│       │       │   │   ├── Asia/
│       │       │   │   │   ├── Aden
│       │       │   │   │   ├── Almaty
│       │       │   │   │   ├── Amman
│       │       │   │   │   ├── Anadyr
│       │       │   │   │   ├── Aqtau
│       │       │   │   │   ├── Aqtobe
│       │       │   │   │   ├── Ashgabat
│       │       │   │   │   ├── Ashkhabad
│       │       │   │   │   ├── Atyrau
│       │       │   │   │   ├── Baghdad
│       │       │   │   │   ├── Bahrain
│       │       │   │   │   ├── Baku
│       │       │   │   │   ├── Bangkok
│       │       │   │   │   ├── Barnaul
│       │       │   │   │   ├── Beirut
│       │       │   │   │   ├── Bishkek
│       │       │   │   │   ├── Brunei
│       │       │   │   │   ├── Calcutta
│       │       │   │   │   ├── Chita
│       │       │   │   │   ├── Choibalsan
│       │       │   │   │   ├── Chongqing
│       │       │   │   │   ├── Chungking
│       │       │   │   │   ├── Colombo
│       │       │   │   │   ├── Dacca
│       │       │   │   │   ├── Damascus
│       │       │   │   │   ├── Dhaka
│       │       │   │   │   ├── Dili
│       │       │   │   │   ├── Dubai
│       │       │   │   │   ├── Dushanbe
│       │       │   │   │   ├── Famagusta
│       │       │   │   │   ├── Gaza
│       │       │   │   │   ├── Harbin
│       │       │   │   │   ├── Hebron
│       │       │   │   │   ├── Hong_Kong
│       │       │   │   │   ├── Hovd
│       │       │   │   │   ├── Ho_Chi_Minh
│       │       │   │   │   ├── Irkutsk
│       │       │   │   │   ├── Istanbul
│       │       │   │   │   ├── Jakarta
│       │       │   │   │   ├── Jayapura
│       │       │   │   │   ├── Jerusalem
│       │       │   │   │   ├── Kabul
│       │       │   │   │   ├── Kamchatka
│       │       │   │   │   ├── Karachi
│       │       │   │   │   ├── Kashgar
│       │       │   │   │   ├── Kathmandu
│       │       │   │   │   ├── Katmandu
│       │       │   │   │   ├── Khandyga
│       │       │   │   │   ├── Kolkata
│       │       │   │   │   ├── Krasnoyarsk
│       │       │   │   │   ├── Kuala_Lumpur
│       │       │   │   │   ├── Kuching
│       │       │   │   │   ├── Kuwait
│       │       │   │   │   ├── Macao
│       │       │   │   │   ├── Macau
│       │       │   │   │   ├── Magadan
│       │       │   │   │   ├── Makassar
│       │       │   │   │   ├── Manila
│       │       │   │   │   ├── Muscat
│       │       │   │   │   ├── Nicosia
│       │       │   │   │   ├── Novokuznetsk
│       │       │   │   │   ├── Novosibirsk
│       │       │   │   │   ├── Omsk
│       │       │   │   │   ├── Oral
│       │       │   │   │   ├── Phnom_Penh
│       │       │   │   │   ├── Pontianak
│       │       │   │   │   ├── Pyongyang
│       │       │   │   │   ├── Qatar
│       │       │   │   │   ├── Qostanay
│       │       │   │   │   ├── Qyzylorda
│       │       │   │   │   ├── Rangoon
│       │       │   │   │   ├── Riyadh
│       │       │   │   │   ├── Saigon
│       │       │   │   │   ├── Sakhalin
│       │       │   │   │   ├── Samarkand
│       │       │   │   │   ├── Seoul
│       │       │   │   │   ├── Shanghai
│       │       │   │   │   ├── Singapore
│       │       │   │   │   ├── Srednekolymsk
│       │       │   │   │   ├── Taipei
│       │       │   │   │   ├── Tashkent
│       │       │   │   │   ├── Tbilisi
│       │       │   │   │   ├── Tehran
│       │       │   │   │   ├── Tel_Aviv
│       │       │   │   │   ├── Thimbu
│       │       │   │   │   ├── Thimphu
│       │       │   │   │   ├── Tokyo
│       │       │   │   │   ├── Tomsk
│       │       │   │   │   ├── Ujung_Pandang
│       │       │   │   │   ├── Ulaanbaatar
│       │       │   │   │   ├── Ulan_Bator
│       │       │   │   │   ├── Urumqi
│       │       │   │   │   ├── Ust-Nera
│       │       │   │   │   ├── Vientiane
│       │       │   │   │   ├── Vladivostok
│       │       │   │   │   ├── Yakutsk
│       │       │   │   │   ├── Yangon
│       │       │   │   │   ├── Yekaterinburg
│       │       │   │   │   └── Yerevan
│       │       │   │   ├── Atlantic/
│       │       │   │   │   ├── Azores
│       │       │   │   │   ├── Bermuda
│       │       │   │   │   ├── Canary
│       │       │   │   │   ├── Cape_Verde
│       │       │   │   │   ├── Faeroe
│       │       │   │   │   ├── Faroe
│       │       │   │   │   ├── Jan_Mayen
│       │       │   │   │   ├── Madeira
│       │       │   │   │   ├── Reykjavik
│       │       │   │   │   ├── South_Georgia
│       │       │   │   │   ├── Stanley
│       │       │   │   │   └── St_Helena
│       │       │   │   ├── Australia/
│       │       │   │   │   ├── ACT
│       │       │   │   │   ├── Adelaide
│       │       │   │   │   ├── Brisbane
│       │       │   │   │   ├── Broken_Hill
│       │       │   │   │   ├── Canberra
│       │       │   │   │   ├── Currie
│       │       │   │   │   ├── Darwin
│       │       │   │   │   ├── Eucla
│       │       │   │   │   ├── Hobart
│       │       │   │   │   ├── LHI
│       │       │   │   │   ├── Lindeman
│       │       │   │   │   ├── Lord_Howe
│       │       │   │   │   ├── Melbourne
│       │       │   │   │   ├── North
│       │       │   │   │   ├── NSW
│       │       │   │   │   ├── Perth
│       │       │   │   │   ├── Queensland
│       │       │   │   │   ├── South
│       │       │   │   │   ├── Sydney
│       │       │   │   │   ├── Tasmania
│       │       │   │   │   ├── Victoria
│       │       │   │   │   ├── West
│       │       │   │   │   └── Yancowinna
│       │       │   │   ├── Brazil/
│       │       │   │   │   ├── Acre
│       │       │   │   │   ├── DeNoronha
│       │       │   │   │   ├── East
│       │       │   │   │   └── West
│       │       │   │   ├── Canada/
│       │       │   │   │   ├── Atlantic
│       │       │   │   │   ├── Central
│       │       │   │   │   ├── Eastern
│       │       │   │   │   ├── Mountain
│       │       │   │   │   ├── Newfoundland
│       │       │   │   │   ├── Pacific
│       │       │   │   │   ├── Saskatchewan
│       │       │   │   │   └── Yukon
│       │       │   │   ├── CET
│       │       │   │   ├── Chile/
│       │       │   │   │   ├── Continental
│       │       │   │   │   └── EasterIsland
│       │       │   │   ├── CST6CDT
│       │       │   │   ├── Cuba
│       │       │   │   ├── EET
│       │       │   │   ├── Egypt
│       │       │   │   ├── Eire
│       │       │   │   ├── EST
│       │       │   │   ├── EST5EDT
│       │       │   │   ├── Etc/
│       │       │   │   │   ├── GMT
│       │       │   │   │   ├── GMT+0
│       │       │   │   │   ├── GMT+1
│       │       │   │   │   ├── GMT+10
│       │       │   │   │   ├── GMT+11
│       │       │   │   │   ├── GMT+12
│       │       │   │   │   ├── GMT+2
│       │       │   │   │   ├── GMT+3
│       │       │   │   │   ├── GMT+4
│       │       │   │   │   ├── GMT+5
│       │       │   │   │   ├── GMT+6
│       │       │   │   │   ├── GMT+7
│       │       │   │   │   ├── GMT+8
│       │       │   │   │   ├── GMT+9
│       │       │   │   │   ├── GMT-0
│       │       │   │   │   ├── GMT-1
│       │       │   │   │   ├── GMT-10
│       │       │   │   │   ├── GMT-11
│       │       │   │   │   ├── GMT-12
│       │       │   │   │   ├── GMT-13
│       │       │   │   │   ├── GMT-14
│       │       │   │   │   ├── GMT-2
│       │       │   │   │   ├── GMT-3
│       │       │   │   │   ├── GMT-4
│       │       │   │   │   ├── GMT-5
│       │       │   │   │   ├── GMT-6
│       │       │   │   │   ├── GMT-7
│       │       │   │   │   ├── GMT-8
│       │       │   │   │   ├── GMT-9
│       │       │   │   │   ├── GMT0
│       │       │   │   │   ├── Greenwich
│       │       │   │   │   ├── UCT
│       │       │   │   │   ├── Universal
│       │       │   │   │   ├── UTC
│       │       │   │   │   └── Zulu
│       │       │   │   ├── Europe/
│       │       │   │   │   ├── Amsterdam
│       │       │   │   │   ├── Andorra
│       │       │   │   │   ├── Astrakhan
│       │       │   │   │   ├── Athens
│       │       │   │   │   ├── Belfast
│       │       │   │   │   ├── Belgrade
│       │       │   │   │   ├── Berlin
│       │       │   │   │   ├── Bratislava
│       │       │   │   │   ├── Brussels
│       │       │   │   │   ├── Bucharest
│       │       │   │   │   ├── Budapest
│       │       │   │   │   ├── Busingen
│       │       │   │   │   ├── Chisinau
│       │       │   │   │   ├── Copenhagen
│       │       │   │   │   ├── Dublin
│       │       │   │   │   ├── Gibraltar
│       │       │   │   │   ├── Guernsey
│       │       │   │   │   ├── Helsinki
│       │       │   │   │   ├── Isle_of_Man
│       │       │   │   │   ├── Istanbul
│       │       │   │   │   ├── Jersey
│       │       │   │   │   ├── Kaliningrad
│       │       │   │   │   ├── Kiev
│       │       │   │   │   ├── Kirov
│       │       │   │   │   ├── Kyiv
│       │       │   │   │   ├── Lisbon
│       │       │   │   │   ├── Ljubljana
│       │       │   │   │   ├── London
│       │       │   │   │   ├── Luxembourg
│       │       │   │   │   ├── Madrid
│       │       │   │   │   ├── Malta
│       │       │   │   │   ├── Mariehamn
│       │       │   │   │   ├── Minsk
│       │       │   │   │   ├── Monaco
│       │       │   │   │   ├── Moscow
│       │       │   │   │   ├── Nicosia
│       │       │   │   │   ├── Oslo
│       │       │   │   │   ├── Paris
│       │       │   │   │   ├── Podgorica
│       │       │   │   │   ├── Prague
│       │       │   │   │   ├── Riga
│       │       │   │   │   ├── Rome
│       │       │   │   │   ├── Samara
│       │       │   │   │   ├── San_Marino
│       │       │   │   │   ├── Sarajevo
│       │       │   │   │   ├── Saratov
│       │       │   │   │   ├── Simferopol
│       │       │   │   │   ├── Skopje
│       │       │   │   │   ├── Sofia
│       │       │   │   │   ├── Stockholm
│       │       │   │   │   ├── Tallinn
│       │       │   │   │   ├── Tirane
│       │       │   │   │   ├── Tiraspol
│       │       │   │   │   ├── Ulyanovsk
│       │       │   │   │   ├── Uzhgorod
│       │       │   │   │   ├── Vaduz
│       │       │   │   │   ├── Vatican
│       │       │   │   │   ├── Vienna
│       │       │   │   │   ├── Vilnius
│       │       │   │   │   ├── Volgograd
│       │       │   │   │   ├── Warsaw
│       │       │   │   │   ├── Zagreb
│       │       │   │   │   ├── Zaporozhye
│       │       │   │   │   └── Zurich
│       │       │   │   ├── Factory
│       │       │   │   ├── GB
│       │       │   │   ├── GB-Eire
│       │       │   │   ├── GMT
│       │       │   │   ├── GMT+0
│       │       │   │   ├── GMT-0
│       │       │   │   ├── GMT0
│       │       │   │   ├── Greenwich
│       │       │   │   ├── Hongkong
│       │       │   │   ├── HST
│       │       │   │   ├── Iceland
│       │       │   │   ├── Indian/
│       │       │   │   │   ├── Antananarivo
│       │       │   │   │   ├── Chagos
│       │       │   │   │   ├── Christmas
│       │       │   │   │   ├── Cocos
│       │       │   │   │   ├── Comoro
│       │       │   │   │   ├── Kerguelen
│       │       │   │   │   ├── Mahe
│       │       │   │   │   ├── Maldives
│       │       │   │   │   ├── Mauritius
│       │       │   │   │   ├── Mayotte
│       │       │   │   │   └── Reunion
│       │       │   │   ├── Iran
│       │       │   │   ├── iso3166.tab
│       │       │   │   ├── Israel
│       │       │   │   ├── Jamaica
│       │       │   │   ├── Japan
│       │       │   │   ├── Kwajalein
│       │       │   │   ├── leapseconds
│       │       │   │   ├── Libya
│       │       │   │   ├── MET
│       │       │   │   ├── Mexico/
│       │       │   │   │   ├── BajaNorte
│       │       │   │   │   ├── BajaSur
│       │       │   │   │   └── General
│       │       │   │   ├── MST
│       │       │   │   ├── MST7MDT
│       │       │   │   ├── Navajo
│       │       │   │   ├── NZ
│       │       │   │   ├── NZ-CHAT
│       │       │   │   ├── Pacific/
│       │       │   │   │   ├── Apia
│       │       │   │   │   ├── Auckland
│       │       │   │   │   ├── Bougainville
│       │       │   │   │   ├── Chatham
│       │       │   │   │   ├── Chuuk
│       │       │   │   │   ├── Easter
│       │       │   │   │   ├── Efate
│       │       │   │   │   ├── Enderbury
│       │       │   │   │   ├── Fakaofo
│       │       │   │   │   ├── Fiji
│       │       │   │   │   ├── Funafuti
│       │       │   │   │   ├── Galapagos
│       │       │   │   │   ├── Gambier
│       │       │   │   │   ├── Guadalcanal
│       │       │   │   │   ├── Guam
│       │       │   │   │   ├── Honolulu
│       │       │   │   │   ├── Johnston
│       │       │   │   │   ├── Kanton
│       │       │   │   │   ├── Kiritimati
│       │       │   │   │   ├── Kosrae
│       │       │   │   │   ├── Kwajalein
│       │       │   │   │   ├── Majuro
│       │       │   │   │   ├── Marquesas
│       │       │   │   │   ├── Midway
│       │       │   │   │   ├── Nauru
│       │       │   │   │   ├── Niue
│       │       │   │   │   ├── Norfolk
│       │       │   │   │   ├── Noumea
│       │       │   │   │   ├── Pago_Pago
│       │       │   │   │   ├── Palau
│       │       │   │   │   ├── Pitcairn
│       │       │   │   │   ├── Pohnpei
│       │       │   │   │   ├── Ponape
│       │       │   │   │   ├── Port_Moresby
│       │       │   │   │   ├── Rarotonga
│       │       │   │   │   ├── Saipan
│       │       │   │   │   ├── Samoa
│       │       │   │   │   ├── Tahiti
│       │       │   │   │   ├── Tarawa
│       │       │   │   │   ├── Tongatapu
│       │       │   │   │   ├── Truk
│       │       │   │   │   ├── Wake
│       │       │   │   │   ├── Wallis
│       │       │   │   │   └── Yap
│       │       │   │   ├── Poland
│       │       │   │   ├── Portugal
│       │       │   │   ├── PRC
│       │       │   │   ├── PST8PDT
│       │       │   │   ├── ROC
│       │       │   │   ├── ROK
│       │       │   │   ├── Singapore
│       │       │   │   ├── Turkey
│       │       │   │   ├── tzdata.zi
│       │       │   │   ├── UCT
│       │       │   │   ├── Universal
│       │       │   │   ├── US/
│       │       │   │   │   ├── Alaska
│       │       │   │   │   ├── Aleutian
│       │       │   │   │   ├── Arizona
│       │       │   │   │   ├── Central
│       │       │   │   │   ├── East-Indiana
│       │       │   │   │   ├── Eastern
│       │       │   │   │   ├── Hawaii
│       │       │   │   │   ├── Indiana-Starke
│       │       │   │   │   ├── Michigan
│       │       │   │   │   ├── Mountain
│       │       │   │   │   ├── Pacific
│       │       │   │   │   └── Samoa
│       │       │   │   ├── UTC
│       │       │   │   ├── W-SU
│       │       │   │   ├── WET
│       │       │   │   ├── zone.tab
│       │       │   │   ├── zone1970.tab
│       │       │   │   ├── zonenow.tab
│       │       │   │   └── Zulu
│       │       │   └── __init__.py
│       │       ├── pytz-2025.2.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   ├── WHEEL
│       │       │   └── zip-safe
│       │       ├── PyYAML-6.0.2.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── requests/
│       │       │   ├── adapters.py
│       │       │   ├── api.py
│       │       │   ├── auth.py
│       │       │   ├── certs.py
│       │       │   ├── compat.py
│       │       │   ├── cookies.py
│       │       │   ├── exceptions.py
│       │       │   ├── help.py
│       │       │   ├── hooks.py
│       │       │   ├── models.py
│       │       │   ├── packages.py
│       │       │   ├── sessions.py
│       │       │   ├── status_codes.py
│       │       │   ├── structures.py
│       │       │   ├── utils.py
│       │       │   ├── _internal_utils.py
│       │       │   ├── __init__.py
│       │       │   └── __version__.py
│       │       ├── requests-2.32.4.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── requests_file-2.1.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── requests_file.py
│       │       ├── scikit_learn-1.7.0.dist-info/
│       │       │   ├── COPYING
│       │       │   ├── INSTALLER
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   └── WHEEL
│       │       ├── scipy/
│       │       │   ├── cluster/
│       │       │   │   ├── hierarchy.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── hierarchy_test_data.py
│       │       │   │   │   ├── test_disjoint_set.py
│       │       │   │   │   ├── test_hierarchy.py
│       │       │   │   │   ├── test_vq.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── vq.py
│       │       │   │   ├── _hierarchy.cp312-win_amd64.dll.a
│       │       │   │   ├── _hierarchy.cp312-win_amd64.pyd
│       │       │   │   ├── _optimal_leaf_ordering.cp312-win_amd64.dll.a
│       │       │   │   ├── _optimal_leaf_ordering.cp312-win_amd64.pyd
│       │       │   │   ├── _vq.cp312-win_amd64.dll.a
│       │       │   │   ├── _vq.cp312-win_amd64.pyd
│       │       │   │   └── __init__.py
│       │       │   ├── conftest.py
│       │       │   ├── constants/
│       │       │   │   ├── codata.py
│       │       │   │   ├── constants.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_codata.py
│       │       │   │   │   ├── test_constants.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _codata.py
│       │       │   │   ├── _constants.py
│       │       │   │   └── __init__.py
│       │       │   ├── datasets/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_data.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _download_all.py
│       │       │   │   ├── _fetchers.py
│       │       │   │   ├── _registry.py
│       │       │   │   ├── _utils.py
│       │       │   │   └── __init__.py
│       │       │   ├── differentiate/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_differentiate.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _differentiate.py
│       │       │   │   └── __init__.py
│       │       │   ├── fft/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── mock_backend.py
│       │       │   │   │   ├── test_backend.py
│       │       │   │   │   ├── test_basic.py
│       │       │   │   │   ├── test_fftlog.py
│       │       │   │   │   ├── test_helper.py
│       │       │   │   │   ├── test_multithreading.py
│       │       │   │   │   ├── test_real_transforms.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _backend.py
│       │       │   │   ├── _basic.py
│       │       │   │   ├── _basic_backend.py
│       │       │   │   ├── _debug_backends.py
│       │       │   │   ├── _fftlog.py
│       │       │   │   ├── _fftlog_backend.py
│       │       │   │   ├── _helper.py
│       │       │   │   ├── _pocketfft/
│       │       │   │   │   ├── basic.py
│       │       │   │   │   ├── helper.py
│       │       │   │   │   ├── LICENSE.md
│       │       │   │   │   ├── pypocketfft.cp312-win_amd64.dll.a
│       │       │   │   │   ├── pypocketfft.cp312-win_amd64.pyd
│       │       │   │   │   ├── realtransforms.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_basic.py
│       │       │   │   │   │   ├── test_real_transforms.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _realtransforms.py
│       │       │   │   ├── _realtransforms_backend.py
│       │       │   │   └── __init__.py
│       │       │   ├── fftpack/
│       │       │   │   ├── basic.py
│       │       │   │   ├── convolve.cp312-win_amd64.dll.a
│       │       │   │   ├── convolve.cp312-win_amd64.pyd
│       │       │   │   ├── helper.py
│       │       │   │   ├── pseudo_diffs.py
│       │       │   │   ├── realtransforms.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── fftw_double_ref.npz
│       │       │   │   │   ├── fftw_longdouble_ref.npz
│       │       │   │   │   ├── fftw_single_ref.npz
│       │       │   │   │   ├── test.npz
│       │       │   │   │   ├── test_basic.py
│       │       │   │   │   ├── test_helper.py
│       │       │   │   │   ├── test_import.py
│       │       │   │   │   ├── test_pseudo_diffs.py
│       │       │   │   │   ├── test_real_transforms.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _basic.py
│       │       │   │   ├── _helper.py
│       │       │   │   ├── _pseudo_diffs.py
│       │       │   │   ├── _realtransforms.py
│       │       │   │   └── __init__.py
│       │       │   ├── integrate/
│       │       │   │   ├── dop.py
│       │       │   │   ├── lsoda.py
│       │       │   │   ├── odepack.py
│       │       │   │   ├── quadpack.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_banded_ode_solvers.py
│       │       │   │   │   ├── test_bvp.py
│       │       │   │   │   ├── test_cubature.py
│       │       │   │   │   ├── test_integrate.py
│       │       │   │   │   ├── test_odeint_jac.py
│       │       │   │   │   ├── test_quadpack.py
│       │       │   │   │   ├── test_quadrature.py
│       │       │   │   │   ├── test_tanhsinh.py
│       │       │   │   │   ├── test__quad_vec.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── vode.py
│       │       │   │   ├── _bvp.py
│       │       │   │   ├── _cubature.py
│       │       │   │   ├── _dop.cp312-win_amd64.dll.a
│       │       │   │   ├── _dop.cp312-win_amd64.pyd
│       │       │   │   ├── _ivp/
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── bdf.py
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── dop853_coefficients.py
│       │       │   │   │   ├── ivp.py
│       │       │   │   │   ├── lsoda.py
│       │       │   │   │   ├── radau.py
│       │       │   │   │   ├── rk.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_ivp.py
│       │       │   │   │   │   ├── test_rk.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _lebedev.py
│       │       │   │   ├── _lsoda.cp312-win_amd64.dll.a
│       │       │   │   ├── _lsoda.cp312-win_amd64.pyd
│       │       │   │   ├── _ode.py
│       │       │   │   ├── _odepack.cp312-win_amd64.dll.a
│       │       │   │   ├── _odepack.cp312-win_amd64.pyd
│       │       │   │   ├── _odepack_py.py
│       │       │   │   ├── _quadpack.cp312-win_amd64.dll.a
│       │       │   │   ├── _quadpack.cp312-win_amd64.pyd
│       │       │   │   ├── _quadpack_py.py
│       │       │   │   ├── _quadrature.py
│       │       │   │   ├── _quad_vec.py
│       │       │   │   ├── _rules/
│       │       │   │   │   ├── _base.py
│       │       │   │   │   ├── _gauss_kronrod.py
│       │       │   │   │   ├── _gauss_legendre.py
│       │       │   │   │   ├── _genz_malik.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _tanhsinh.py
│       │       │   │   ├── _test_multivariate.cp312-win_amd64.dll.a
│       │       │   │   ├── _test_multivariate.cp312-win_amd64.pyd
│       │       │   │   ├── _test_odeint_banded.cp312-win_amd64.dll.a
│       │       │   │   ├── _test_odeint_banded.cp312-win_amd64.pyd
│       │       │   │   ├── _vode.cp312-win_amd64.dll.a
│       │       │   │   ├── _vode.cp312-win_amd64.pyd
│       │       │   │   └── __init__.py
│       │       │   ├── interpolate/
│       │       │   │   ├── dfitpack.py
│       │       │   │   ├── fitpack.py
│       │       │   │   ├── fitpack2.py
│       │       │   │   ├── interpnd.py
│       │       │   │   ├── interpolate.py
│       │       │   │   ├── ndgriddata.py
│       │       │   │   ├── polyint.py
│       │       │   │   ├── rbf.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── bug-1310.npz
│       │       │   │   │   │   ├── estimate_gradients_hang.npy
│       │       │   │   │   │   └── gcvspl.npz
│       │       │   │   │   ├── test_bary_rational.py
│       │       │   │   │   ├── test_bsplines.py
│       │       │   │   │   ├── test_fitpack.py
│       │       │   │   │   ├── test_fitpack2.py
│       │       │   │   │   ├── test_gil.py
│       │       │   │   │   ├── test_interpnd.py
│       │       │   │   │   ├── test_interpolate.py
│       │       │   │   │   ├── test_ndgriddata.py
│       │       │   │   │   ├── test_pade.py
│       │       │   │   │   ├── test_polyint.py
│       │       │   │   │   ├── test_rbf.py
│       │       │   │   │   ├── test_rbfinterp.py
│       │       │   │   │   ├── test_rgi.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _bary_rational.py
│       │       │   │   ├── _bsplines.py
│       │       │   │   ├── _cubic.py
│       │       │   │   ├── _dfitpack.cp312-win_amd64.dll.a
│       │       │   │   ├── _dfitpack.cp312-win_amd64.pyd
│       │       │   │   ├── _dierckx.cp312-win_amd64.dll.a
│       │       │   │   ├── _dierckx.cp312-win_amd64.pyd
│       │       │   │   ├── _fitpack.cp312-win_amd64.dll.a
│       │       │   │   ├── _fitpack.cp312-win_amd64.pyd
│       │       │   │   ├── _fitpack2.py
│       │       │   │   ├── _fitpack_impl.py
│       │       │   │   ├── _fitpack_py.py
│       │       │   │   ├── _fitpack_repro.py
│       │       │   │   ├── _interpnd.cp312-win_amd64.dll.a
│       │       │   │   ├── _interpnd.cp312-win_amd64.pyd
│       │       │   │   ├── _interpolate.py
│       │       │   │   ├── _ndbspline.py
│       │       │   │   ├── _ndgriddata.py
│       │       │   │   ├── _pade.py
│       │       │   │   ├── _polyint.py
│       │       │   │   ├── _ppoly.cp312-win_amd64.dll.a
│       │       │   │   ├── _ppoly.cp312-win_amd64.pyd
│       │       │   │   ├── _rbf.py
│       │       │   │   ├── _rbfinterp.py
│       │       │   │   ├── _rbfinterp_pythran.cp312-win_amd64.dll.a
│       │       │   │   ├── _rbfinterp_pythran.cp312-win_amd64.pyd
│       │       │   │   ├── _rgi.py
│       │       │   │   ├── _rgi_cython.cp312-win_amd64.dll.a
│       │       │   │   ├── _rgi_cython.cp312-win_amd64.pyd
│       │       │   │   └── __init__.py
│       │       │   ├── io/
│       │       │   │   ├── arff/
│       │       │   │   │   ├── arffread.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── data/
│       │       │   │   │   │   │   ├── iris.arff
│       │       │   │   │   │   │   ├── missing.arff
│       │       │   │   │   │   │   ├── nodata.arff
│       │       │   │   │   │   │   ├── quoted_nominal.arff
│       │       │   │   │   │   │   ├── quoted_nominal_spaces.arff
│       │       │   │   │   │   │   ├── test1.arff
│       │       │   │   │   │   │   ├── test10.arff
│       │       │   │   │   │   │   ├── test11.arff
│       │       │   │   │   │   │   ├── test2.arff
│       │       │   │   │   │   │   ├── test3.arff
│       │       │   │   │   │   │   ├── test4.arff
│       │       │   │   │   │   │   ├── test5.arff
│       │       │   │   │   │   │   ├── test6.arff
│       │       │   │   │   │   │   ├── test7.arff
│       │       │   │   │   │   │   ├── test8.arff
│       │       │   │   │   │   │   └── test9.arff
│       │       │   │   │   │   ├── test_arffread.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _arffread.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── harwell_boeing.py
│       │       │   │   ├── idl.py
│       │       │   │   ├── matlab/
│       │       │   │   │   ├── byteordercodes.py
│       │       │   │   │   ├── mio.py
│       │       │   │   │   ├── mio4.py
│       │       │   │   │   ├── mio5.py
│       │       │   │   │   ├── mio5_params.py
│       │       │   │   │   ├── mio5_utils.py
│       │       │   │   │   ├── miobase.py
│       │       │   │   │   ├── mio_utils.py
│       │       │   │   │   ├── streams.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── data/
│       │       │   │   │   │   │   ├── bad_miuint32.mat
│       │       │   │   │   │   │   ├── bad_miutf8_array_name.mat
│       │       │   │   │   │   │   ├── big_endian.mat
│       │       │   │   │   │   │   ├── broken_utf8.mat
│       │       │   │   │   │   │   ├── corrupted_zlib_checksum.mat
│       │       │   │   │   │   │   ├── corrupted_zlib_data.mat
│       │       │   │   │   │   │   ├── debigged_m4.mat
│       │       │   │   │   │   │   ├── japanese_utf8.txt
│       │       │   │   │   │   │   ├── little_endian.mat
│       │       │   │   │   │   │   ├── logical_sparse.mat
│       │       │   │   │   │   │   ├── malformed1.mat
│       │       │   │   │   │   │   ├── miuint32_for_miint32.mat
│       │       │   │   │   │   │   ├── miutf8_array_name.mat
│       │       │   │   │   │   │   ├── nasty_duplicate_fieldnames.mat
│       │       │   │   │   │   │   ├── one_by_zero_char.mat
│       │       │   │   │   │   │   ├── parabola.mat
│       │       │   │   │   │   │   ├── single_empty_string.mat
│       │       │   │   │   │   │   ├── some_functions.mat
│       │       │   │   │   │   │   ├── sqr.mat
│       │       │   │   │   │   │   ├── test3dmatrix_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── test3dmatrix_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── test3dmatrix_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── test3dmatrix_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testbool_8_WIN64.mat
│       │       │   │   │   │   │   ├── testcellnest_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testcellnest_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testcellnest_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testcellnest_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testcell_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testcell_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testcell_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testcell_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testcomplex_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── testcomplex_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testcomplex_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testcomplex_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testcomplex_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testdouble_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── testdouble_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testdouble_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testdouble_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testdouble_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testemptycell_5.3_SOL2.mat
│       │       │   │   │   │   │   ├── testemptycell_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testemptycell_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testemptycell_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testfunc_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testhdf5_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testmatrix_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── testmatrix_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testmatrix_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testmatrix_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testmatrix_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testminus_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── testminus_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testminus_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testminus_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testminus_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testmulti_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── testmulti_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testmulti_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testobject_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testobject_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testobject_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testobject_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testonechar_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── testonechar_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testonechar_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testonechar_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testonechar_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testscalarcell_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testsimplecell.mat
│       │       │   │   │   │   │   ├── testsparsecomplex_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── testsparsecomplex_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testsparsecomplex_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testsparsecomplex_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testsparsecomplex_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testsparsefloat_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testsparse_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── testsparse_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── testsparse_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testsparse_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testsparse_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── teststringarray_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── teststringarray_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── teststringarray_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststringarray_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststringarray_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── teststring_4.2c_SOL2.mat
│       │       │   │   │   │   │   ├── teststring_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── teststring_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststring_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststring_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── teststructarr_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── teststructarr_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststructarr_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststructarr_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── teststructnest_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── teststructnest_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststructnest_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststructnest_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── teststruct_6.1_SOL2.mat
│       │       │   │   │   │   │   ├── teststruct_6.5.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststruct_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── teststruct_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testunicode_7.1_GLNX86.mat
│       │       │   │   │   │   │   ├── testunicode_7.4_GLNX86.mat
│       │       │   │   │   │   │   ├── testvec_4_GLNX86.mat
│       │       │   │   │   │   │   ├── test_empty_struct.mat
│       │       │   │   │   │   │   ├── test_mat4_le_floats.mat
│       │       │   │   │   │   │   └── test_skip_variable.mat
│       │       │   │   │   │   ├── test_byteordercodes.py
│       │       │   │   │   │   ├── test_mio.py
│       │       │   │   │   │   ├── test_mio5_utils.py
│       │       │   │   │   │   ├── test_miobase.py
│       │       │   │   │   │   ├── test_mio_funcs.py
│       │       │   │   │   │   ├── test_mio_utils.py
│       │       │   │   │   │   ├── test_pathological.py
│       │       │   │   │   │   ├── test_streams.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _byteordercodes.py
│       │       │   │   │   ├── _mio.py
│       │       │   │   │   ├── _mio4.py
│       │       │   │   │   ├── _mio5.py
│       │       │   │   │   ├── _mio5_params.py
│       │       │   │   │   ├── _mio5_utils.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _mio5_utils.cp312-win_amd64.pyd
│       │       │   │   │   ├── _miobase.py
│       │       │   │   │   ├── _mio_utils.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _mio_utils.cp312-win_amd64.pyd
│       │       │   │   │   ├── _streams.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _streams.cp312-win_amd64.pyd
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── mmio.py
│       │       │   │   ├── netcdf.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── array_float32_1d.sav
│       │       │   │   │   │   ├── array_float32_2d.sav
│       │       │   │   │   │   ├── array_float32_3d.sav
│       │       │   │   │   │   ├── array_float32_4d.sav
│       │       │   │   │   │   ├── array_float32_5d.sav
│       │       │   │   │   │   ├── array_float32_6d.sav
│       │       │   │   │   │   ├── array_float32_7d.sav
│       │       │   │   │   │   ├── array_float32_8d.sav
│       │       │   │   │   │   ├── array_float32_pointer_1d.sav
│       │       │   │   │   │   ├── array_float32_pointer_2d.sav
│       │       │   │   │   │   ├── array_float32_pointer_3d.sav
│       │       │   │   │   │   ├── array_float32_pointer_4d.sav
│       │       │   │   │   │   ├── array_float32_pointer_5d.sav
│       │       │   │   │   │   ├── array_float32_pointer_6d.sav
│       │       │   │   │   │   ├── array_float32_pointer_7d.sav
│       │       │   │   │   │   ├── array_float32_pointer_8d.sav
│       │       │   │   │   │   ├── example_1.nc
│       │       │   │   │   │   ├── example_2.nc
│       │       │   │   │   │   ├── example_3_maskedvals.nc
│       │       │   │   │   │   ├── fortran-3x3d-2i.dat
│       │       │   │   │   │   ├── fortran-mixed.dat
│       │       │   │   │   │   ├── fortran-sf8-11x1x10.dat
│       │       │   │   │   │   ├── fortran-sf8-15x10x22.dat
│       │       │   │   │   │   ├── fortran-sf8-1x1x1.dat
│       │       │   │   │   │   ├── fortran-sf8-1x1x5.dat
│       │       │   │   │   │   ├── fortran-sf8-1x1x7.dat
│       │       │   │   │   │   ├── fortran-sf8-1x3x5.dat
│       │       │   │   │   │   ├── fortran-si4-11x1x10.dat
│       │       │   │   │   │   ├── fortran-si4-15x10x22.dat
│       │       │   │   │   │   ├── fortran-si4-1x1x1.dat
│       │       │   │   │   │   ├── fortran-si4-1x1x5.dat
│       │       │   │   │   │   ├── fortran-si4-1x1x7.dat
│       │       │   │   │   │   ├── fortran-si4-1x3x5.dat
│       │       │   │   │   │   ├── invalid_pointer.sav
│       │       │   │   │   │   ├── null_pointer.sav
│       │       │   │   │   │   ├── scalar_byte.sav
│       │       │   │   │   │   ├── scalar_byte_descr.sav
│       │       │   │   │   │   ├── scalar_complex32.sav
│       │       │   │   │   │   ├── scalar_complex64.sav
│       │       │   │   │   │   ├── scalar_float32.sav
│       │       │   │   │   │   ├── scalar_float64.sav
│       │       │   │   │   │   ├── scalar_heap_pointer.sav
│       │       │   │   │   │   ├── scalar_int16.sav
│       │       │   │   │   │   ├── scalar_int32.sav
│       │       │   │   │   │   ├── scalar_int64.sav
│       │       │   │   │   │   ├── scalar_string.sav
│       │       │   │   │   │   ├── scalar_uint16.sav
│       │       │   │   │   │   ├── scalar_uint32.sav
│       │       │   │   │   │   ├── scalar_uint64.sav
│       │       │   │   │   │   ├── struct_arrays.sav
│       │       │   │   │   │   ├── struct_arrays_byte_idl80.sav
│       │       │   │   │   │   ├── struct_arrays_replicated.sav
│       │       │   │   │   │   ├── struct_arrays_replicated_3d.sav
│       │       │   │   │   │   ├── struct_inherit.sav
│       │       │   │   │   │   ├── struct_pointers.sav
│       │       │   │   │   │   ├── struct_pointers_replicated.sav
│       │       │   │   │   │   ├── struct_pointers_replicated_3d.sav
│       │       │   │   │   │   ├── struct_pointer_arrays.sav
│       │       │   │   │   │   ├── struct_pointer_arrays_replicated.sav
│       │       │   │   │   │   ├── struct_pointer_arrays_replicated_3d.sav
│       │       │   │   │   │   ├── struct_scalars.sav
│       │       │   │   │   │   ├── struct_scalars_replicated.sav
│       │       │   │   │   │   ├── struct_scalars_replicated_3d.sav
│       │       │   │   │   │   ├── test-1234Hz-le-1ch-10S-20bit-extra.wav
│       │       │   │   │   │   ├── test-44100Hz-2ch-32bit-float-be.wav
│       │       │   │   │   │   ├── test-44100Hz-2ch-32bit-float-le.wav
│       │       │   │   │   │   ├── test-44100Hz-be-1ch-4bytes.wav
│       │       │   │   │   │   ├── test-44100Hz-le-1ch-4bytes-early-eof-no-data.wav
│       │       │   │   │   │   ├── test-44100Hz-le-1ch-4bytes-early-eof.wav
│       │       │   │   │   │   ├── test-44100Hz-le-1ch-4bytes-incomplete-chunk.wav
│       │       │   │   │   │   ├── test-44100Hz-le-1ch-4bytes-rf64.wav
│       │       │   │   │   │   ├── test-44100Hz-le-1ch-4bytes.wav
│       │       │   │   │   │   ├── test-48000Hz-2ch-64bit-float-le-wavex.wav
│       │       │   │   │   │   ├── test-8000Hz-be-3ch-5S-24bit.wav
│       │       │   │   │   │   ├── test-8000Hz-le-1ch-1byte-ulaw.wav
│       │       │   │   │   │   ├── test-8000Hz-le-2ch-1byteu.wav
│       │       │   │   │   │   ├── test-8000Hz-le-3ch-5S-24bit-inconsistent.wav
│       │       │   │   │   │   ├── test-8000Hz-le-3ch-5S-24bit-rf64.wav
│       │       │   │   │   │   ├── test-8000Hz-le-3ch-5S-24bit.wav
│       │       │   │   │   │   ├── test-8000Hz-le-3ch-5S-36bit.wav
│       │       │   │   │   │   ├── test-8000Hz-le-3ch-5S-45bit.wav
│       │       │   │   │   │   ├── test-8000Hz-le-3ch-5S-53bit.wav
│       │       │   │   │   │   ├── test-8000Hz-le-3ch-5S-64bit.wav
│       │       │   │   │   │   ├── test-8000Hz-le-4ch-9S-12bit.wav
│       │       │   │   │   │   ├── test-8000Hz-le-5ch-9S-5bit.wav
│       │       │   │   │   │   ├── Transparent Busy.ani
│       │       │   │   │   │   └── various_compressed.sav
│       │       │   │   │   ├── test_fortran.py
│       │       │   │   │   ├── test_idl.py
│       │       │   │   │   ├── test_mmio.py
│       │       │   │   │   ├── test_netcdf.py
│       │       │   │   │   ├── test_paths.py
│       │       │   │   │   ├── test_wavfile.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── wavfile.py
│       │       │   │   ├── _fast_matrix_market/
│       │       │   │   │   ├── _fmm_core.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _fmm_core.cp312-win_amd64.pyd
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _fortran.py
│       │       │   │   ├── _harwell_boeing/
│       │       │   │   │   ├── hb.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_fortran_format.py
│       │       │   │   │   │   ├── test_hb.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _fortran_format_parser.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _idl.py
│       │       │   │   ├── _mmio.py
│       │       │   │   ├── _netcdf.py
│       │       │   │   ├── _test_fortran.cp312-win_amd64.dll.a
│       │       │   │   ├── _test_fortran.cp312-win_amd64.pyd
│       │       │   │   └── __init__.py
│       │       │   ├── linalg/
│       │       │   │   ├── basic.py
│       │       │   │   ├── blas.py
│       │       │   │   ├── cython_blas.cp312-win_amd64.dll.a
│       │       │   │   ├── cython_blas.cp312-win_amd64.pyd
│       │       │   │   ├── cython_blas.pxd
│       │       │   │   ├── cython_blas.pyx
│       │       │   │   ├── cython_lapack.cp312-win_amd64.dll.a
│       │       │   │   ├── cython_lapack.cp312-win_amd64.pyd
│       │       │   │   ├── cython_lapack.pxd
│       │       │   │   ├── cython_lapack.pyx
│       │       │   │   ├── decomp.py
│       │       │   │   ├── decomp_cholesky.py
│       │       │   │   ├── decomp_lu.py
│       │       │   │   ├── decomp_qr.py
│       │       │   │   ├── decomp_schur.py
│       │       │   │   ├── decomp_svd.py
│       │       │   │   ├── interpolative.py
│       │       │   │   ├── lapack.py
│       │       │   │   ├── matfuncs.py
│       │       │   │   ├── misc.py
│       │       │   │   ├── special_matrices.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── carex_15_data.npz
│       │       │   │   │   │   ├── carex_18_data.npz
│       │       │   │   │   │   ├── carex_19_data.npz
│       │       │   │   │   │   ├── carex_20_data.npz
│       │       │   │   │   │   ├── carex_6_data.npz
│       │       │   │   │   │   └── gendare_20170120_data.npz
│       │       │   │   │   ├── test_basic.py
│       │       │   │   │   ├── test_batch.py
│       │       │   │   │   ├── test_blas.py
│       │       │   │   │   ├── test_cythonized_array_utils.py
│       │       │   │   │   ├── test_cython_blas.py
│       │       │   │   │   ├── test_cython_lapack.py
│       │       │   │   │   ├── test_decomp.py
│       │       │   │   │   ├── test_decomp_cholesky.py
│       │       │   │   │   ├── test_decomp_cossin.py
│       │       │   │   │   ├── test_decomp_ldl.py
│       │       │   │   │   ├── test_decomp_lu.py
│       │       │   │   │   ├── test_decomp_polar.py
│       │       │   │   │   ├── test_decomp_update.py
│       │       │   │   │   ├── test_extending.py
│       │       │   │   │   ├── test_fblas.py
│       │       │   │   │   ├── test_interpolative.py
│       │       │   │   │   ├── test_lapack.py
│       │       │   │   │   ├── test_matfuncs.py
│       │       │   │   │   ├── test_matmul_toeplitz.py
│       │       │   │   │   ├── test_procrustes.py
│       │       │   │   │   ├── test_sketches.py
│       │       │   │   │   ├── test_solvers.py
│       │       │   │   │   ├── test_solve_toeplitz.py
│       │       │   │   │   ├── test_special_matrices.py
│       │       │   │   │   ├── _cython_examples/
│       │       │   │   │   │   ├── extending.pyx
│       │       │   │   │   │   └── meson.build
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _basic.py
│       │       │   │   ├── _blas_subroutines.h
│       │       │   │   ├── _cythonized_array_utils.cp312-win_amd64.dll.a
│       │       │   │   ├── _cythonized_array_utils.cp312-win_amd64.pyd
│       │       │   │   ├── _cythonized_array_utils.pxd
│       │       │   │   ├── _cythonized_array_utils.pyi
│       │       │   │   ├── _decomp.py
│       │       │   │   ├── _decomp_cholesky.py
│       │       │   │   ├── _decomp_cossin.py
│       │       │   │   ├── _decomp_interpolative.cp312-win_amd64.dll.a
│       │       │   │   ├── _decomp_interpolative.cp312-win_amd64.pyd
│       │       │   │   ├── _decomp_ldl.py
│       │       │   │   ├── _decomp_lu.py
│       │       │   │   ├── _decomp_lu_cython.cp312-win_amd64.dll.a
│       │       │   │   ├── _decomp_lu_cython.cp312-win_amd64.pyd
│       │       │   │   ├── _decomp_lu_cython.pyi
│       │       │   │   ├── _decomp_polar.py
│       │       │   │   ├── _decomp_qr.py
│       │       │   │   ├── _decomp_qz.py
│       │       │   │   ├── _decomp_schur.py
│       │       │   │   ├── _decomp_svd.py
│       │       │   │   ├── _decomp_update.cp312-win_amd64.dll.a
│       │       │   │   ├── _decomp_update.cp312-win_amd64.pyd
│       │       │   │   ├── _expm_frechet.py
│       │       │   │   ├── _fblas.cp312-win_amd64.dll.a
│       │       │   │   ├── _fblas.cp312-win_amd64.pyd
│       │       │   │   ├── _flapack.cp312-win_amd64.dll.a
│       │       │   │   ├── _flapack.cp312-win_amd64.pyd
│       │       │   │   ├── _lapack_subroutines.h
│       │       │   │   ├── _linalg_pythran.cp312-win_amd64.dll.a
│       │       │   │   ├── _linalg_pythran.cp312-win_amd64.pyd
│       │       │   │   ├── _matfuncs.py
│       │       │   │   ├── _matfuncs_expm.cp312-win_amd64.dll.a
│       │       │   │   ├── _matfuncs_expm.cp312-win_amd64.pyd
│       │       │   │   ├── _matfuncs_expm.pyi
│       │       │   │   ├── _matfuncs_inv_ssq.py
│       │       │   │   ├── _matfuncs_schur_sqrtm.cp312-win_amd64.dll.a
│       │       │   │   ├── _matfuncs_schur_sqrtm.cp312-win_amd64.pyd
│       │       │   │   ├── _matfuncs_sqrtm.py
│       │       │   │   ├── _matfuncs_sqrtm_triu.cp312-win_amd64.dll.a
│       │       │   │   ├── _matfuncs_sqrtm_triu.cp312-win_amd64.pyd
│       │       │   │   ├── _misc.py
│       │       │   │   ├── _procrustes.py
│       │       │   │   ├── _sketches.py
│       │       │   │   ├── _solvers.py
│       │       │   │   ├── _solve_toeplitz.cp312-win_amd64.dll.a
│       │       │   │   ├── _solve_toeplitz.cp312-win_amd64.pyd
│       │       │   │   ├── _special_matrices.py
│       │       │   │   ├── _testutils.py
│       │       │   │   ├── __init__.pxd
│       │       │   │   └── __init__.py
│       │       │   ├── misc/
│       │       │   │   ├── common.py
│       │       │   │   ├── doccer.py
│       │       │   │   └── __init__.py
│       │       │   ├── ndimage/
│       │       │   │   ├── filters.py
│       │       │   │   ├── fourier.py
│       │       │   │   ├── interpolation.py
│       │       │   │   ├── measurements.py
│       │       │   │   ├── morphology.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── label_inputs.txt
│       │       │   │   │   │   ├── label_results.txt
│       │       │   │   │   │   └── label_strels.txt
│       │       │   │   │   ├── dots.png
│       │       │   │   │   ├── test_c_api.py
│       │       │   │   │   ├── test_datatypes.py
│       │       │   │   │   ├── test_filters.py
│       │       │   │   │   ├── test_fourier.py
│       │       │   │   │   ├── test_interpolation.py
│       │       │   │   │   ├── test_measurements.py
│       │       │   │   │   ├── test_morphology.py
│       │       │   │   │   ├── test_ni_support.py
│       │       │   │   │   ├── test_splines.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _ctest.cp312-win_amd64.dll.a
│       │       │   │   ├── _ctest.cp312-win_amd64.pyd
│       │       │   │   ├── _cytest.cp312-win_amd64.dll.a
│       │       │   │   ├── _cytest.cp312-win_amd64.pyd
│       │       │   │   ├── _delegators.py
│       │       │   │   ├── _filters.py
│       │       │   │   ├── _fourier.py
│       │       │   │   ├── _interpolation.py
│       │       │   │   ├── _measurements.py
│       │       │   │   ├── _morphology.py
│       │       │   │   ├── _ndimage_api.py
│       │       │   │   ├── _nd_image.cp312-win_amd64.dll.a
│       │       │   │   ├── _nd_image.cp312-win_amd64.pyd
│       │       │   │   ├── _ni_docstrings.py
│       │       │   │   ├── _ni_label.cp312-win_amd64.dll.a
│       │       │   │   ├── _ni_label.cp312-win_amd64.pyd
│       │       │   │   ├── _ni_support.py
│       │       │   │   ├── _rank_filter_1d.cp312-win_amd64.dll.a
│       │       │   │   ├── _rank_filter_1d.cp312-win_amd64.pyd
│       │       │   │   ├── _support_alternative_backends.py
│       │       │   │   └── __init__.py
│       │       │   ├── odr/
│       │       │   │   ├── models.py
│       │       │   │   ├── odrpack.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_odr.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _add_newdocs.py
│       │       │   │   ├── _models.py
│       │       │   │   ├── _odrpack.py
│       │       │   │   ├── __init__.py
│       │       │   │   ├── __odrpack.cp312-win_amd64.dll.a
│       │       │   │   └── __odrpack.cp312-win_amd64.pyd
│       │       │   ├── optimize/
│       │       │   │   ├── cobyla.py
│       │       │   │   ├── cython_optimize/
│       │       │   │   │   ├── c_zeros.pxd
│       │       │   │   │   ├── _zeros.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _zeros.cp312-win_amd64.pyd
│       │       │   │   │   ├── _zeros.pxd
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── cython_optimize.pxd
│       │       │   │   ├── elementwise.py
│       │       │   │   ├── lbfgsb.py
│       │       │   │   ├── linesearch.py
│       │       │   │   ├── minpack.py
│       │       │   │   ├── minpack2.py
│       │       │   │   ├── moduleTNC.py
│       │       │   │   ├── nonlin.py
│       │       │   │   ├── optimize.py
│       │       │   │   ├── slsqp.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_bracket.py
│       │       │   │   │   ├── test_chandrupatla.py
│       │       │   │   │   ├── test_cobyla.py
│       │       │   │   │   ├── test_cobyqa.py
│       │       │   │   │   ├── test_constraints.py
│       │       │   │   │   ├── test_constraint_conversion.py
│       │       │   │   │   ├── test_cython_optimize.py
│       │       │   │   │   ├── test_differentiable_functions.py
│       │       │   │   │   ├── test_direct.py
│       │       │   │   │   ├── test_extending.py
│       │       │   │   │   ├── test_hessian_update_strategy.py
│       │       │   │   │   ├── test_isotonic_regression.py
│       │       │   │   │   ├── test_lbfgsb_hessinv.py
│       │       │   │   │   ├── test_lbfgsb_setulb.py
│       │       │   │   │   ├── test_least_squares.py
│       │       │   │   │   ├── test_linear_assignment.py
│       │       │   │   │   ├── test_linesearch.py
│       │       │   │   │   ├── test_linprog.py
│       │       │   │   │   ├── test_lsq_common.py
│       │       │   │   │   ├── test_lsq_linear.py
│       │       │   │   │   ├── test_milp.py
│       │       │   │   │   ├── test_minimize_constrained.py
│       │       │   │   │   ├── test_minpack.py
│       │       │   │   │   ├── test_nnls.py
│       │       │   │   │   ├── test_nonlin.py
│       │       │   │   │   ├── test_optimize.py
│       │       │   │   │   ├── test_quadratic_assignment.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   ├── test_slsqp.py
│       │       │   │   │   ├── test_tnc.py
│       │       │   │   │   ├── test_trustregion.py
│       │       │   │   │   ├── test_trustregion_exact.py
│       │       │   │   │   ├── test_trustregion_krylov.py
│       │       │   │   │   ├── test_zeros.py
│       │       │   │   │   ├── test__basinhopping.py
│       │       │   │   │   ├── test__differential_evolution.py
│       │       │   │   │   ├── test__dual_annealing.py
│       │       │   │   │   ├── test__linprog_clean_inputs.py
│       │       │   │   │   ├── test__numdiff.py
│       │       │   │   │   ├── test__remove_redundancy.py
│       │       │   │   │   ├── test__root.py
│       │       │   │   │   ├── test__shgo.py
│       │       │   │   │   ├── test__spectral.py
│       │       │   │   │   ├── _cython_examples/
│       │       │   │   │   │   ├── extending.pyx
│       │       │   │   │   │   └── meson.build
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── tnc.py
│       │       │   │   ├── zeros.py
│       │       │   │   ├── _basinhopping.py
│       │       │   │   ├── _bglu_dense.cp312-win_amd64.dll.a
│       │       │   │   ├── _bglu_dense.cp312-win_amd64.pyd
│       │       │   │   ├── _bracket.py
│       │       │   │   ├── _chandrupatla.py
│       │       │   │   ├── _cobyla_py.py
│       │       │   │   ├── _cobyqa_py.py
│       │       │   │   ├── _constraints.py
│       │       │   │   ├── _dcsrch.py
│       │       │   │   ├── _differentiable_functions.py
│       │       │   │   ├── _differentialevolution.py
│       │       │   │   ├── _direct.cp312-win_amd64.dll.a
│       │       │   │   ├── _direct.cp312-win_amd64.pyd
│       │       │   │   ├── _direct_py.py
│       │       │   │   ├── _dual_annealing.py
│       │       │   │   ├── _elementwise.py
│       │       │   │   ├── _group_columns.cp312-win_amd64.dll.a
│       │       │   │   ├── _group_columns.cp312-win_amd64.pyd
│       │       │   │   ├── _hessian_update_strategy.py
│       │       │   │   ├── _highspy/
│       │       │   │   │   ├── _core.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _core.cp312-win_amd64.pyd
│       │       │   │   │   ├── _highs_options.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _highs_options.cp312-win_amd64.pyd
│       │       │   │   │   ├── _highs_wrapper.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _isotonic.py
│       │       │   │   ├── _lbfgsb.cp312-win_amd64.dll.a
│       │       │   │   ├── _lbfgsb.cp312-win_amd64.pyd
│       │       │   │   ├── _lbfgsb_py.py
│       │       │   │   ├── _linesearch.py
│       │       │   │   ├── _linprog.py
│       │       │   │   ├── _linprog_doc.py
│       │       │   │   ├── _linprog_highs.py
│       │       │   │   ├── _linprog_ip.py
│       │       │   │   ├── _linprog_rs.py
│       │       │   │   ├── _linprog_simplex.py
│       │       │   │   ├── _linprog_util.py
│       │       │   │   ├── _lsap.cp312-win_amd64.dll.a
│       │       │   │   ├── _lsap.cp312-win_amd64.pyd
│       │       │   │   ├── _lsq/
│       │       │   │   │   ├── bvls.py
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── dogbox.py
│       │       │   │   │   ├── givens_elimination.cp312-win_amd64.dll.a
│       │       │   │   │   ├── givens_elimination.cp312-win_amd64.pyd
│       │       │   │   │   ├── least_squares.py
│       │       │   │   │   ├── lsq_linear.py
│       │       │   │   │   ├── trf.py
│       │       │   │   │   ├── trf_linear.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _milp.py
│       │       │   │   ├── _minimize.py
│       │       │   │   ├── _minpack.cp312-win_amd64.dll.a
│       │       │   │   ├── _minpack.cp312-win_amd64.pyd
│       │       │   │   ├── _minpack_py.py
│       │       │   │   ├── _moduleTNC.cp312-win_amd64.dll.a
│       │       │   │   ├── _moduleTNC.cp312-win_amd64.pyd
│       │       │   │   ├── _nnls.py
│       │       │   │   ├── _nonlin.py
│       │       │   │   ├── _numdiff.py
│       │       │   │   ├── _optimize.py
│       │       │   │   ├── _pava_pybind.cp312-win_amd64.dll.a
│       │       │   │   ├── _pava_pybind.cp312-win_amd64.pyd
│       │       │   │   ├── _qap.py
│       │       │   │   ├── _remove_redundancy.py
│       │       │   │   ├── _root.py
│       │       │   │   ├── _root_scalar.py
│       │       │   │   ├── _shgo.py
│       │       │   │   ├── _shgo_lib/
│       │       │   │   │   ├── _complex.py
│       │       │   │   │   ├── _vertex.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _slsqplib.cp312-win_amd64.dll.a
│       │       │   │   ├── _slsqplib.cp312-win_amd64.pyd
│       │       │   │   ├── _slsqp_py.py
│       │       │   │   ├── _spectral.py
│       │       │   │   ├── _tnc.py
│       │       │   │   ├── _trlib/
│       │       │   │   │   ├── _trlib.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _trlib.cp312-win_amd64.pyd
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _trustregion.py
│       │       │   │   ├── _trustregion_constr/
│       │       │   │   │   ├── canonical_constraint.py
│       │       │   │   │   ├── equality_constrained_sqp.py
│       │       │   │   │   ├── minimize_trustregion_constr.py
│       │       │   │   │   ├── projections.py
│       │       │   │   │   ├── qp_subproblem.py
│       │       │   │   │   ├── report.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_canonical_constraint.py
│       │       │   │   │   │   ├── test_nested_minimize.py
│       │       │   │   │   │   ├── test_projections.py
│       │       │   │   │   │   ├── test_qp_subproblem.py
│       │       │   │   │   │   ├── test_report.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── tr_interior_point.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _trustregion_dogleg.py
│       │       │   │   ├── _trustregion_exact.py
│       │       │   │   ├── _trustregion_krylov.py
│       │       │   │   ├── _trustregion_ncg.py
│       │       │   │   ├── _tstutils.py
│       │       │   │   ├── _zeros.cp312-win_amd64.dll.a
│       │       │   │   ├── _zeros.cp312-win_amd64.pyd
│       │       │   │   ├── _zeros_py.py
│       │       │   │   ├── __init__.pxd
│       │       │   │   └── __init__.py
│       │       │   ├── signal/
│       │       │   │   ├── bsplines.py
│       │       │   │   ├── filter_design.py
│       │       │   │   ├── fir_filter_design.py
│       │       │   │   ├── ltisys.py
│       │       │   │   ├── lti_conversion.py
│       │       │   │   ├── signaltools.py
│       │       │   │   ├── spectral.py
│       │       │   │   ├── spline.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── mpsig.py
│       │       │   │   │   ├── test_array_tools.py
│       │       │   │   │   ├── test_bsplines.py
│       │       │   │   │   ├── test_cont2discrete.py
│       │       │   │   │   ├── test_czt.py
│       │       │   │   │   ├── test_dltisys.py
│       │       │   │   │   ├── test_filter_design.py
│       │       │   │   │   ├── test_fir_filter_design.py
│       │       │   │   │   ├── test_ltisys.py
│       │       │   │   │   ├── test_max_len_seq.py
│       │       │   │   │   ├── test_peak_finding.py
│       │       │   │   │   ├── test_result_type.py
│       │       │   │   │   ├── test_savitzky_golay.py
│       │       │   │   │   ├── test_short_time_fft.py
│       │       │   │   │   ├── test_signaltools.py
│       │       │   │   │   ├── test_spectral.py
│       │       │   │   │   ├── test_splines.py
│       │       │   │   │   ├── test_upfirdn.py
│       │       │   │   │   ├── test_waveforms.py
│       │       │   │   │   ├── test_wavelets.py
│       │       │   │   │   ├── test_windows.py
│       │       │   │   │   ├── _scipy_spectral_test_shim.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── waveforms.py
│       │       │   │   ├── wavelets.py
│       │       │   │   ├── windows/
│       │       │   │   │   ├── windows.py
│       │       │   │   │   ├── _windows.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _arraytools.py
│       │       │   │   ├── _czt.py
│       │       │   │   ├── _delegators.py
│       │       │   │   ├── _filter_design.py
│       │       │   │   ├── _fir_filter_design.py
│       │       │   │   ├── _ltisys.py
│       │       │   │   ├── _lti_conversion.py
│       │       │   │   ├── _max_len_seq.py
│       │       │   │   ├── _max_len_seq_inner.cp312-win_amd64.dll.a
│       │       │   │   ├── _max_len_seq_inner.cp312-win_amd64.pyd
│       │       │   │   ├── _peak_finding.py
│       │       │   │   ├── _peak_finding_utils.cp312-win_amd64.dll.a
│       │       │   │   ├── _peak_finding_utils.cp312-win_amd64.pyd
│       │       │   │   ├── _polyutils.py
│       │       │   │   ├── _savitzky_golay.py
│       │       │   │   ├── _short_time_fft.py
│       │       │   │   ├── _signaltools.py
│       │       │   │   ├── _signal_api.py
│       │       │   │   ├── _sigtools.cp312-win_amd64.dll.a
│       │       │   │   ├── _sigtools.cp312-win_amd64.pyd
│       │       │   │   ├── _sosfilt.cp312-win_amd64.dll.a
│       │       │   │   ├── _sosfilt.cp312-win_amd64.pyd
│       │       │   │   ├── _spectral_py.py
│       │       │   │   ├── _spline.cp312-win_amd64.dll.a
│       │       │   │   ├── _spline.cp312-win_amd64.pyd
│       │       │   │   ├── _spline.pyi
│       │       │   │   ├── _spline_filters.py
│       │       │   │   ├── _support_alternative_backends.py
│       │       │   │   ├── _upfirdn.py
│       │       │   │   ├── _upfirdn_apply.cp312-win_amd64.dll.a
│       │       │   │   ├── _upfirdn_apply.cp312-win_amd64.pyd
│       │       │   │   ├── _waveforms.py
│       │       │   │   ├── _wavelets.py
│       │       │   │   └── __init__.py
│       │       │   ├── sparse/
│       │       │   │   ├── base.py
│       │       │   │   ├── bsr.py
│       │       │   │   ├── compressed.py
│       │       │   │   ├── construct.py
│       │       │   │   ├── coo.py
│       │       │   │   ├── csc.py
│       │       │   │   ├── csgraph/
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_connected_components.py
│       │       │   │   │   │   ├── test_conversions.py
│       │       │   │   │   │   ├── test_flow.py
│       │       │   │   │   │   ├── test_graph_laplacian.py
│       │       │   │   │   │   ├── test_matching.py
│       │       │   │   │   │   ├── test_pydata_sparse.py
│       │       │   │   │   │   ├── test_reordering.py
│       │       │   │   │   │   ├── test_shortest_path.py
│       │       │   │   │   │   ├── test_spanning_tree.py
│       │       │   │   │   │   ├── test_traversal.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _flow.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _flow.cp312-win_amd64.pyd
│       │       │   │   │   ├── _laplacian.py
│       │       │   │   │   ├── _matching.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _matching.cp312-win_amd64.pyd
│       │       │   │   │   ├── _min_spanning_tree.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _min_spanning_tree.cp312-win_amd64.pyd
│       │       │   │   │   ├── _reordering.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _reordering.cp312-win_amd64.pyd
│       │       │   │   │   ├── _shortest_path.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _shortest_path.cp312-win_amd64.pyd
│       │       │   │   │   ├── _tools.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _tools.cp312-win_amd64.pyd
│       │       │   │   │   ├── _traversal.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _traversal.cp312-win_amd64.pyd
│       │       │   │   │   ├── _validation.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── csr.py
│       │       │   │   ├── data.py
│       │       │   │   ├── dia.py
│       │       │   │   ├── dok.py
│       │       │   │   ├── extract.py
│       │       │   │   ├── lil.py
│       │       │   │   ├── linalg/
│       │       │   │   │   ├── dsolve.py
│       │       │   │   │   ├── eigen.py
│       │       │   │   │   ├── interface.py
│       │       │   │   │   ├── isolve.py
│       │       │   │   │   ├── matfuncs.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── propack_test_data.npz
│       │       │   │   │   │   ├── test_expm_multiply.py
│       │       │   │   │   │   ├── test_interface.py
│       │       │   │   │   │   ├── test_matfuncs.py
│       │       │   │   │   │   ├── test_norm.py
│       │       │   │   │   │   ├── test_onenormest.py
│       │       │   │   │   │   ├── test_propack.py
│       │       │   │   │   │   ├── test_pydata_sparse.py
│       │       │   │   │   │   ├── test_special_sparse_arrays.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _dsolve/
│       │       │   │   │   │   ├── linsolve.py
│       │       │   │   │   │   ├── tests/
│       │       │   │   │   │   │   ├── test_linsolve.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── _add_newdocs.py
│       │       │   │   │   │   ├── _superlu.cp312-win_amd64.dll.a
│       │       │   │   │   │   ├── _superlu.cp312-win_amd64.pyd
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _eigen/
│       │       │   │   │   │   ├── arpack/
│       │       │   │   │   │   │   ├── arpack.py
│       │       │   │   │   │   │   ├── COPYING
│       │       │   │   │   │   │   ├── tests/
│       │       │   │   │   │   │   │   ├── test_arpack.py
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── _arpack.cp312-win_amd64.dll.a
│       │       │   │   │   │   │   ├── _arpack.cp312-win_amd64.pyd
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── lobpcg/
│       │       │   │   │   │   │   ├── lobpcg.py
│       │       │   │   │   │   │   ├── tests/
│       │       │   │   │   │   │   │   ├── test_lobpcg.py
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── tests/
│       │       │   │   │   │   │   ├── test_svds.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── _svds.py
│       │       │   │   │   │   ├── _svds_doc.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _expm_multiply.py
│       │       │   │   │   ├── _interface.py
│       │       │   │   │   ├── _isolve/
│       │       │   │   │   │   ├── iterative.py
│       │       │   │   │   │   ├── lgmres.py
│       │       │   │   │   │   ├── lsmr.py
│       │       │   │   │   │   ├── lsqr.py
│       │       │   │   │   │   ├── minres.py
│       │       │   │   │   │   ├── tests/
│       │       │   │   │   │   │   ├── test_gcrotmk.py
│       │       │   │   │   │   │   ├── test_iterative.py
│       │       │   │   │   │   │   ├── test_lgmres.py
│       │       │   │   │   │   │   ├── test_lsmr.py
│       │       │   │   │   │   │   ├── test_lsqr.py
│       │       │   │   │   │   │   ├── test_minres.py
│       │       │   │   │   │   │   ├── test_utils.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── tfqmr.py
│       │       │   │   │   │   ├── utils.py
│       │       │   │   │   │   ├── _gcrotmk.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _matfuncs.py
│       │       │   │   │   ├── _norm.py
│       │       │   │   │   ├── _onenormest.py
│       │       │   │   │   ├── _propack/
│       │       │   │   │   │   ├── _cpropack.cp312-win_amd64.dll.a
│       │       │   │   │   │   ├── _cpropack.cp312-win_amd64.pyd
│       │       │   │   │   │   ├── _dpropack.cp312-win_amd64.dll.a
│       │       │   │   │   │   ├── _dpropack.cp312-win_amd64.pyd
│       │       │   │   │   │   ├── _spropack.cp312-win_amd64.dll.a
│       │       │   │   │   │   ├── _spropack.cp312-win_amd64.pyd
│       │       │   │   │   │   ├── _zpropack.cp312-win_amd64.dll.a
│       │       │   │   │   │   └── _zpropack.cp312-win_amd64.pyd
│       │       │   │   │   ├── _special_sparse_arrays.py
│       │       │   │   │   ├── _svdp.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── sparsetools.py
│       │       │   │   ├── spfuncs.py
│       │       │   │   ├── sputils.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── csc_py2.npz
│       │       │   │   │   │   └── csc_py3.npz
│       │       │   │   │   ├── test_arithmetic1d.py
│       │       │   │   │   ├── test_array_api.py
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_common1d.py
│       │       │   │   │   ├── test_construct.py
│       │       │   │   │   ├── test_coo.py
│       │       │   │   │   ├── test_csc.py
│       │       │   │   │   ├── test_csr.py
│       │       │   │   │   ├── test_dok.py
│       │       │   │   │   ├── test_extract.py
│       │       │   │   │   ├── test_indexing1d.py
│       │       │   │   │   ├── test_matrix_io.py
│       │       │   │   │   ├── test_minmax1d.py
│       │       │   │   │   ├── test_sparsetools.py
│       │       │   │   │   ├── test_spfuncs.py
│       │       │   │   │   ├── test_sputils.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _bsr.py
│       │       │   │   ├── _compressed.py
│       │       │   │   ├── _construct.py
│       │       │   │   ├── _coo.py
│       │       │   │   ├── _csc.py
│       │       │   │   ├── _csparsetools.cp312-win_amd64.dll.a
│       │       │   │   ├── _csparsetools.cp312-win_amd64.pyd
│       │       │   │   ├── _csr.py
│       │       │   │   ├── _data.py
│       │       │   │   ├── _dia.py
│       │       │   │   ├── _dok.py
│       │       │   │   ├── _extract.py
│       │       │   │   ├── _index.py
│       │       │   │   ├── _lil.py
│       │       │   │   ├── _matrix.py
│       │       │   │   ├── _matrix_io.py
│       │       │   │   ├── _sparsetools.cp312-win_amd64.dll.a
│       │       │   │   ├── _sparsetools.cp312-win_amd64.pyd
│       │       │   │   ├── _spfuncs.py
│       │       │   │   ├── _sputils.py
│       │       │   │   └── __init__.py
│       │       │   ├── spatial/
│       │       │   │   ├── ckdtree.py
│       │       │   │   ├── distance.py
│       │       │   │   ├── distance.pyi
│       │       │   │   ├── kdtree.py
│       │       │   │   ├── qhull.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── cdist-X1.txt
│       │       │   │   │   │   ├── cdist-X2.txt
│       │       │   │   │   │   ├── degenerate_pointset.npz
│       │       │   │   │   │   ├── iris.txt
│       │       │   │   │   │   ├── pdist-boolean-inp.txt
│       │       │   │   │   │   ├── pdist-chebyshev-ml-iris.txt
│       │       │   │   │   │   ├── pdist-chebyshev-ml.txt
│       │       │   │   │   │   ├── pdist-cityblock-ml-iris.txt
│       │       │   │   │   │   ├── pdist-cityblock-ml.txt
│       │       │   │   │   │   ├── pdist-correlation-ml-iris.txt
│       │       │   │   │   │   ├── pdist-correlation-ml.txt
│       │       │   │   │   │   ├── pdist-cosine-ml-iris.txt
│       │       │   │   │   │   ├── pdist-cosine-ml.txt
│       │       │   │   │   │   ├── pdist-double-inp.txt
│       │       │   │   │   │   ├── pdist-euclidean-ml-iris.txt
│       │       │   │   │   │   ├── pdist-euclidean-ml.txt
│       │       │   │   │   │   ├── pdist-hamming-ml.txt
│       │       │   │   │   │   ├── pdist-jaccard-ml.txt
│       │       │   │   │   │   ├── pdist-jensenshannon-ml-iris.txt
│       │       │   │   │   │   ├── pdist-jensenshannon-ml.txt
│       │       │   │   │   │   ├── pdist-minkowski-3.2-ml-iris.txt
│       │       │   │   │   │   ├── pdist-minkowski-3.2-ml.txt
│       │       │   │   │   │   ├── pdist-minkowski-5.8-ml-iris.txt
│       │       │   │   │   │   ├── pdist-seuclidean-ml-iris.txt
│       │       │   │   │   │   ├── pdist-seuclidean-ml.txt
│       │       │   │   │   │   ├── pdist-spearman-ml.txt
│       │       │   │   │   │   ├── random-bool-data.txt
│       │       │   │   │   │   ├── random-double-data.txt
│       │       │   │   │   │   ├── random-int-data.txt
│       │       │   │   │   │   ├── random-uint-data.txt
│       │       │   │   │   │   └── selfdual-4d-polytope.txt
│       │       │   │   │   ├── test_distance.py
│       │       │   │   │   ├── test_hausdorff.py
│       │       │   │   │   ├── test_kdtree.py
│       │       │   │   │   ├── test_qhull.py
│       │       │   │   │   ├── test_slerp.py
│       │       │   │   │   ├── test_spherical_voronoi.py
│       │       │   │   │   ├── test__plotutils.py
│       │       │   │   │   ├── test__procrustes.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── transform/
│       │       │   │   │   ├── rotation.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_rigid_transform.py
│       │       │   │   │   │   ├── test_rotation.py
│       │       │   │   │   │   ├── test_rotation_groups.py
│       │       │   │   │   │   ├── test_rotation_spline.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _rigid_transform.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _rigid_transform.cp312-win_amd64.pyd
│       │       │   │   │   ├── _rotation.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _rotation.cp312-win_amd64.pyd
│       │       │   │   │   ├── _rotation_groups.py
│       │       │   │   │   ├── _rotation_spline.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _ckdtree.cp312-win_amd64.dll.a
│       │       │   │   ├── _ckdtree.cp312-win_amd64.pyd
│       │       │   │   ├── _distance_pybind.cp312-win_amd64.dll.a
│       │       │   │   ├── _distance_pybind.cp312-win_amd64.pyd
│       │       │   │   ├── _distance_wrap.cp312-win_amd64.dll.a
│       │       │   │   ├── _distance_wrap.cp312-win_amd64.pyd
│       │       │   │   ├── _geometric_slerp.py
│       │       │   │   ├── _hausdorff.cp312-win_amd64.dll.a
│       │       │   │   ├── _hausdorff.cp312-win_amd64.pyd
│       │       │   │   ├── _kdtree.py
│       │       │   │   ├── _plotutils.py
│       │       │   │   ├── _procrustes.py
│       │       │   │   ├── _qhull.cp312-win_amd64.dll.a
│       │       │   │   ├── _qhull.cp312-win_amd64.pyd
│       │       │   │   ├── _qhull.pyi
│       │       │   │   ├── _spherical_voronoi.py
│       │       │   │   ├── _voronoi.cp312-win_amd64.dll.a
│       │       │   │   ├── _voronoi.cp312-win_amd64.pyd
│       │       │   │   ├── _voronoi.pyi
│       │       │   │   └── __init__.py
│       │       │   ├── special/
│       │       │   │   ├── add_newdocs.py
│       │       │   │   ├── basic.py
│       │       │   │   ├── cython_special.cp312-win_amd64.dll.a
│       │       │   │   ├── cython_special.cp312-win_amd64.pyd
│       │       │   │   ├── cython_special.pxd
│       │       │   │   ├── cython_special.pyi
│       │       │   │   ├── orthogonal.py
│       │       │   │   ├── sf_error.py
│       │       │   │   ├── specfun.py
│       │       │   │   ├── spfun_stats.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── boost.npz
│       │       │   │   │   │   ├── gsl.npz
│       │       │   │   │   │   ├── local.npz
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_basic.py
│       │       │   │   │   ├── test_bdtr.py
│       │       │   │   │   ├── test_boost_ufuncs.py
│       │       │   │   │   ├── test_boxcox.py
│       │       │   │   │   ├── test_cdflib.py
│       │       │   │   │   ├── test_cdft_asymptotic.py
│       │       │   │   │   ├── test_cephes_intp_cast.py
│       │       │   │   │   ├── test_cosine_distr.py
│       │       │   │   │   ├── test_cython_special.py
│       │       │   │   │   ├── test_data.py
│       │       │   │   │   ├── test_dd.py
│       │       │   │   │   ├── test_digamma.py
│       │       │   │   │   ├── test_ellip_harm.py
│       │       │   │   │   ├── test_erfinv.py
│       │       │   │   │   ├── test_exponential_integrals.py
│       │       │   │   │   ├── test_extending.py
│       │       │   │   │   ├── test_faddeeva.py
│       │       │   │   │   ├── test_gamma.py
│       │       │   │   │   ├── test_gammainc.py
│       │       │   │   │   ├── test_hyp2f1.py
│       │       │   │   │   ├── test_hypergeometric.py
│       │       │   │   │   ├── test_iv_ratio.py
│       │       │   │   │   ├── test_kolmogorov.py
│       │       │   │   │   ├── test_lambertw.py
│       │       │   │   │   ├── test_legendre.py
│       │       │   │   │   ├── test_log1mexp.py
│       │       │   │   │   ├── test_loggamma.py
│       │       │   │   │   ├── test_logit.py
│       │       │   │   │   ├── test_logsumexp.py
│       │       │   │   │   ├── test_mpmath.py
│       │       │   │   │   ├── test_nan_inputs.py
│       │       │   │   │   ├── test_ndtr.py
│       │       │   │   │   ├── test_ndtri_exp.py
│       │       │   │   │   ├── test_orthogonal.py
│       │       │   │   │   ├── test_orthogonal_eval.py
│       │       │   │   │   ├── test_owens_t.py
│       │       │   │   │   ├── test_pcf.py
│       │       │   │   │   ├── test_pdtr.py
│       │       │   │   │   ├── test_powm1.py
│       │       │   │   │   ├── test_precompute_expn_asy.py
│       │       │   │   │   ├── test_precompute_gammainc.py
│       │       │   │   │   ├── test_precompute_utils.py
│       │       │   │   │   ├── test_round.py
│       │       │   │   │   ├── test_sf_error.py
│       │       │   │   │   ├── test_sici.py
│       │       │   │   │   ├── test_specfun.py
│       │       │   │   │   ├── test_spence.py
│       │       │   │   │   ├── test_spfun_stats.py
│       │       │   │   │   ├── test_spherical_bessel.py
│       │       │   │   │   ├── test_sph_harm.py
│       │       │   │   │   ├── test_support_alternative_backends.py
│       │       │   │   │   ├── test_trig.py
│       │       │   │   │   ├── test_ufunc_signatures.py
│       │       │   │   │   ├── test_wrightomega.py
│       │       │   │   │   ├── test_wright_bessel.py
│       │       │   │   │   ├── test_zeta.py
│       │       │   │   │   ├── _cython_examples/
│       │       │   │   │   │   ├── extending.pyx
│       │       │   │   │   │   └── meson.build
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _add_newdocs.py
│       │       │   │   ├── _basic.py
│       │       │   │   ├── _comb.cp312-win_amd64.dll.a
│       │       │   │   ├── _comb.cp312-win_amd64.pyd
│       │       │   │   ├── _ellip_harm.py
│       │       │   │   ├── _ellip_harm_2.cp312-win_amd64.dll.a
│       │       │   │   ├── _ellip_harm_2.cp312-win_amd64.pyd
│       │       │   │   ├── _gufuncs.cp312-win_amd64.dll.a
│       │       │   │   ├── _gufuncs.cp312-win_amd64.pyd
│       │       │   │   ├── _input_validation.py
│       │       │   │   ├── _lambertw.py
│       │       │   │   ├── _logsumexp.py
│       │       │   │   ├── _mptestutils.py
│       │       │   │   ├── _multiufuncs.py
│       │       │   │   ├── _orthogonal.py
│       │       │   │   ├── _orthogonal.pyi
│       │       │   │   ├── _precompute/
│       │       │   │   │   ├── cosine_cdf.py
│       │       │   │   │   ├── expn_asy.py
│       │       │   │   │   ├── gammainc_asy.py
│       │       │   │   │   ├── gammainc_data.py
│       │       │   │   │   ├── hyp2f1_data.py
│       │       │   │   │   ├── lambertw.py
│       │       │   │   │   ├── loggamma.py
│       │       │   │   │   ├── struve_convergence.py
│       │       │   │   │   ├── utils.py
│       │       │   │   │   ├── wrightomega.py
│       │       │   │   │   ├── wright_bessel.py
│       │       │   │   │   ├── wright_bessel_data.py
│       │       │   │   │   ├── zetac.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _sf_error.py
│       │       │   │   ├── _specfun.cp312-win_amd64.dll.a
│       │       │   │   ├── _specfun.cp312-win_amd64.pyd
│       │       │   │   ├── _special_ufuncs.cp312-win_amd64.dll.a
│       │       │   │   ├── _special_ufuncs.cp312-win_amd64.pyd
│       │       │   │   ├── _spfun_stats.py
│       │       │   │   ├── _spherical_bessel.py
│       │       │   │   ├── _support_alternative_backends.py
│       │       │   │   ├── _testutils.py
│       │       │   │   ├── _test_internal.cp312-win_amd64.dll.a
│       │       │   │   ├── _test_internal.cp312-win_amd64.pyd
│       │       │   │   ├── _test_internal.pyi
│       │       │   │   ├── _ufuncs.cp312-win_amd64.dll.a
│       │       │   │   ├── _ufuncs.cp312-win_amd64.pyd
│       │       │   │   ├── _ufuncs.pyi
│       │       │   │   ├── _ufuncs.pyx
│       │       │   │   ├── _ufuncs_cxx.cp312-win_amd64.dll.a
│       │       │   │   ├── _ufuncs_cxx.cp312-win_amd64.pyd
│       │       │   │   ├── _ufuncs_cxx.pxd
│       │       │   │   ├── _ufuncs_cxx.pyx
│       │       │   │   ├── _ufuncs_cxx_defs.h
│       │       │   │   ├── _ufuncs_defs.h
│       │       │   │   ├── __init__.pxd
│       │       │   │   └── __init__.py
│       │       │   ├── stats/
│       │       │   │   ├── biasedurn.py
│       │       │   │   ├── contingency.py
│       │       │   │   ├── distributions.py
│       │       │   │   ├── kde.py
│       │       │   │   ├── morestats.py
│       │       │   │   ├── mstats.py
│       │       │   │   ├── mstats_basic.py
│       │       │   │   ├── mstats_extras.py
│       │       │   │   ├── mvn.py
│       │       │   │   ├── qmc.py
│       │       │   │   ├── sampling.py
│       │       │   │   ├── stats.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── common_tests.py
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── fisher_exact_results_from_r.py
│       │       │   │   │   │   ├── jf_skew_t_gamlss_pdf_data.npy
│       │       │   │   │   │   ├── levy_stable/
│       │       │   │   │   │   │   ├── stable-loc-scale-sample-data.npy
│       │       │   │   │   │   │   ├── stable-Z1-cdf-sample-data.npy
│       │       │   │   │   │   │   └── stable-Z1-pdf-sample-data.npy
│       │       │   │   │   │   ├── nist_anova/
│       │       │   │   │   │   │   ├── AtmWtAg.dat
│       │       │   │   │   │   │   ├── SiRstv.dat
│       │       │   │   │   │   │   ├── SmLs01.dat
│       │       │   │   │   │   │   ├── SmLs02.dat
│       │       │   │   │   │   │   ├── SmLs03.dat
│       │       │   │   │   │   │   ├── SmLs04.dat
│       │       │   │   │   │   │   ├── SmLs05.dat
│       │       │   │   │   │   │   ├── SmLs06.dat
│       │       │   │   │   │   │   ├── SmLs07.dat
│       │       │   │   │   │   │   ├── SmLs08.dat
│       │       │   │   │   │   │   └── SmLs09.dat
│       │       │   │   │   │   ├── nist_linregress/
│       │       │   │   │   │   │   └── Norris.dat
│       │       │   │   │   │   ├── rel_breitwigner_pdf_sample_data_ROOT.npy
│       │       │   │   │   │   ├── studentized_range_mpmath_ref.json
│       │       │   │   │   │   └── _mvt.py
│       │       │   │   │   ├── test_axis_nan_policy.py
│       │       │   │   │   ├── test_binned_statistic.py
│       │       │   │   │   ├── test_censored_data.py
│       │       │   │   │   ├── test_contingency.py
│       │       │   │   │   ├── test_continued_fraction.py
│       │       │   │   │   ├── test_continuous.py
│       │       │   │   │   ├── test_continuous_basic.py
│       │       │   │   │   ├── test_continuous_fit_censored.py
│       │       │   │   │   ├── test_correlation.py
│       │       │   │   │   ├── test_crosstab.py
│       │       │   │   │   ├── test_discrete_basic.py
│       │       │   │   │   ├── test_discrete_distns.py
│       │       │   │   │   ├── test_distributions.py
│       │       │   │   │   ├── test_entropy.py
│       │       │   │   │   ├── test_fast_gen_inversion.py
│       │       │   │   │   ├── test_fit.py
│       │       │   │   │   ├── test_hypotests.py
│       │       │   │   │   ├── test_kdeoth.py
│       │       │   │   │   ├── test_marray.py
│       │       │   │   │   ├── test_mgc.py
│       │       │   │   │   ├── test_morestats.py
│       │       │   │   │   ├── test_mstats_basic.py
│       │       │   │   │   ├── test_mstats_extras.py
│       │       │   │   │   ├── test_multicomp.py
│       │       │   │   │   ├── test_multivariate.py
│       │       │   │   │   ├── test_odds_ratio.py
│       │       │   │   │   ├── test_qmc.py
│       │       │   │   │   ├── test_quantile.py
│       │       │   │   │   ├── test_rank.py
│       │       │   │   │   ├── test_relative_risk.py
│       │       │   │   │   ├── test_resampling.py
│       │       │   │   │   ├── test_sampling.py
│       │       │   │   │   ├── test_sensitivity_analysis.py
│       │       │   │   │   ├── test_stats.py
│       │       │   │   │   ├── test_survival.py
│       │       │   │   │   ├── test_tukeylambda_stats.py
│       │       │   │   │   ├── test_variation.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _ansari_swilk_statistics.cp312-win_amd64.dll.a
│       │       │   │   ├── _ansari_swilk_statistics.cp312-win_amd64.pyd
│       │       │   │   ├── _axis_nan_policy.py
│       │       │   │   ├── _biasedurn.cp312-win_amd64.dll.a
│       │       │   │   ├── _biasedurn.cp312-win_amd64.pyd
│       │       │   │   ├── _biasedurn.pxd
│       │       │   │   ├── _binned_statistic.py
│       │       │   │   ├── _binomtest.py
│       │       │   │   ├── _bws_test.py
│       │       │   │   ├── _censored_data.py
│       │       │   │   ├── _common.py
│       │       │   │   ├── _constants.py
│       │       │   │   ├── _continued_fraction.py
│       │       │   │   ├── _continuous_distns.py
│       │       │   │   ├── _correlation.py
│       │       │   │   ├── _covariance.py
│       │       │   │   ├── _crosstab.py
│       │       │   │   ├── _discrete_distns.py
│       │       │   │   ├── _distn_infrastructure.py
│       │       │   │   ├── _distribution_infrastructure.py
│       │       │   │   ├── _distr_params.py
│       │       │   │   ├── _entropy.py
│       │       │   │   ├── _finite_differences.py
│       │       │   │   ├── _fit.py
│       │       │   │   ├── _hypotests.py
│       │       │   │   ├── _kde.py
│       │       │   │   ├── _ksstats.py
│       │       │   │   ├── _levy_stable/
│       │       │   │   │   ├── levyst.cp312-win_amd64.dll.a
│       │       │   │   │   ├── levyst.cp312-win_amd64.pyd
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _mannwhitneyu.py
│       │       │   │   ├── _mgc.py
│       │       │   │   ├── _morestats.py
│       │       │   │   ├── _mstats_basic.py
│       │       │   │   ├── _mstats_extras.py
│       │       │   │   ├── _multicomp.py
│       │       │   │   ├── _multivariate.py
│       │       │   │   ├── _new_distributions.py
│       │       │   │   ├── _odds_ratio.py
│       │       │   │   ├── _page_trend_test.py
│       │       │   │   ├── _probability_distribution.py
│       │       │   │   ├── _qmc.py
│       │       │   │   ├── _qmc_cy.cp312-win_amd64.dll.a
│       │       │   │   ├── _qmc_cy.cp312-win_amd64.pyd
│       │       │   │   ├── _qmc_cy.pyi
│       │       │   │   ├── _qmvnt.py
│       │       │   │   ├── _qmvnt_cy.cp312-win_amd64.dll.a
│       │       │   │   ├── _qmvnt_cy.cp312-win_amd64.pyd
│       │       │   │   ├── _quantile.py
│       │       │   │   ├── _rcont/
│       │       │   │   │   ├── rcont.cp312-win_amd64.dll.a
│       │       │   │   │   ├── rcont.cp312-win_amd64.pyd
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _relative_risk.py
│       │       │   │   ├── _resampling.py
│       │       │   │   ├── _result_classes.py
│       │       │   │   ├── _sampling.py
│       │       │   │   ├── _sensitivity_analysis.py
│       │       │   │   ├── _sobol.cp312-win_amd64.dll.a
│       │       │   │   ├── _sobol.cp312-win_amd64.pyd
│       │       │   │   ├── _sobol.pyi
│       │       │   │   ├── _sobol_direction_numbers.npz
│       │       │   │   ├── _stats.cp312-win_amd64.dll.a
│       │       │   │   ├── _stats.cp312-win_amd64.pyd
│       │       │   │   ├── _stats.pxd
│       │       │   │   ├── _stats_mstats_common.py
│       │       │   │   ├── _stats_py.py
│       │       │   │   ├── _stats_pythran.cp312-win_amd64.dll.a
│       │       │   │   ├── _stats_pythran.cp312-win_amd64.pyd
│       │       │   │   ├── _survival.py
│       │       │   │   ├── _tukeylambda_stats.py
│       │       │   │   ├── _unuran/
│       │       │   │   │   ├── unuran_wrapper.cp312-win_amd64.dll.a
│       │       │   │   │   ├── unuran_wrapper.cp312-win_amd64.pyd
│       │       │   │   │   ├── unuran_wrapper.pyi
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _variation.py
│       │       │   │   ├── _warnings_errors.py
│       │       │   │   ├── _wilcoxon.py
│       │       │   │   └── __init__.py
│       │       │   ├── version.py
│       │       │   ├── _cyutility.cp312-win_amd64.dll.a
│       │       │   ├── _cyutility.cp312-win_amd64.pyd
│       │       │   ├── _distributor_init.py
│       │       │   ├── _lib/
│       │       │   │   ├── array_api_compat/
│       │       │   │   │   ├── common/
│       │       │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   ├── _fft.py
│       │       │   │   │   │   ├── _helpers.py
│       │       │   │   │   │   ├── _linalg.py
│       │       │   │   │   │   ├── _typing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── cupy/
│       │       │   │   │   │   ├── fft.py
│       │       │   │   │   │   ├── linalg.py
│       │       │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   ├── _info.py
│       │       │   │   │   │   ├── _typing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── dask/
│       │       │   │   │   │   ├── array/
│       │       │   │   │   │   │   ├── fft.py
│       │       │   │   │   │   │   ├── linalg.py
│       │       │   │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   │   ├── _info.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── numpy/
│       │       │   │   │   │   ├── fft.py
│       │       │   │   │   │   ├── linalg.py
│       │       │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   ├── _info.py
│       │       │   │   │   │   ├── _typing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── torch/
│       │       │   │   │   │   ├── fft.py
│       │       │   │   │   │   ├── linalg.py
│       │       │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   ├── _info.py
│       │       │   │   │   │   ├── _typing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _internal.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── array_api_extra/
│       │       │   │   │   ├── testing.py
│       │       │   │   │   ├── _delegation.py
│       │       │   │   │   ├── _lib/
│       │       │   │   │   │   ├── _at.py
│       │       │   │   │   │   ├── _backends.py
│       │       │   │   │   │   ├── _funcs.py
│       │       │   │   │   │   ├── _lazy.py
│       │       │   │   │   │   ├── _testing.py
│       │       │   │   │   │   ├── _utils/
│       │       │   │   │   │   │   ├── _compat.py
│       │       │   │   │   │   │   ├── _compat.pyi
│       │       │   │   │   │   │   ├── _helpers.py
│       │       │   │   │   │   │   ├── _typing.py
│       │       │   │   │   │   │   ├── _typing.pyi
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── cobyqa/
│       │       │   │   │   ├── framework.py
│       │       │   │   │   ├── main.py
│       │       │   │   │   ├── models.py
│       │       │   │   │   ├── problem.py
│       │       │   │   │   ├── settings.py
│       │       │   │   │   ├── subsolvers/
│       │       │   │   │   │   ├── geometry.py
│       │       │   │   │   │   ├── optim.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── utils/
│       │       │   │   │   │   ├── exceptions.py
│       │       │   │   │   │   ├── math.py
│       │       │   │   │   │   ├── versions.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── decorator.py
│       │       │   │   ├── deprecation.py
│       │       │   │   ├── doccer.py
│       │       │   │   ├── messagestream.cp312-win_amd64.dll.a
│       │       │   │   ├── messagestream.cp312-win_amd64.pyd
│       │       │   │   ├── pyprima/
│       │       │   │   │   ├── cobyla/
│       │       │   │   │   │   ├── cobyla.py
│       │       │   │   │   │   ├── cobylb.py
│       │       │   │   │   │   ├── geometry.py
│       │       │   │   │   │   ├── initialize.py
│       │       │   │   │   │   ├── trustregion.py
│       │       │   │   │   │   ├── update.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── common/
│       │       │   │   │   │   ├── checkbreak.py
│       │       │   │   │   │   ├── consts.py
│       │       │   │   │   │   ├── evaluate.py
│       │       │   │   │   │   ├── history.py
│       │       │   │   │   │   ├── infos.py
│       │       │   │   │   │   ├── linalg.py
│       │       │   │   │   │   ├── message.py
│       │       │   │   │   │   ├── powalg.py
│       │       │   │   │   │   ├── preproc.py
│       │       │   │   │   │   ├── present.py
│       │       │   │   │   │   ├── ratio.py
│       │       │   │   │   │   ├── redrho.py
│       │       │   │   │   │   ├── selectx.py
│       │       │   │   │   │   ├── _bounds.py
│       │       │   │   │   │   ├── _linear_constraints.py
│       │       │   │   │   │   ├── _nonlinear_constraints.py
│       │       │   │   │   │   ├── _project.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_array_api.py
│       │       │   │   │   ├── test_bunch.py
│       │       │   │   │   ├── test_ccallback.py
│       │       │   │   │   ├── test_config.py
│       │       │   │   │   ├── test_deprecation.py
│       │       │   │   │   ├── test_doccer.py
│       │       │   │   │   ├── test_import_cycles.py
│       │       │   │   │   ├── test_public_api.py
│       │       │   │   │   ├── test_scipy_version.py
│       │       │   │   │   ├── test_tmpdirs.py
│       │       │   │   │   ├── test_warnings.py
│       │       │   │   │   ├── test__gcutils.py
│       │       │   │   │   ├── test__pep440.py
│       │       │   │   │   ├── test__testutils.py
│       │       │   │   │   ├── test__threadsafety.py
│       │       │   │   │   ├── test__util.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── uarray.py
│       │       │   │   ├── _array_api.py
│       │       │   │   ├── _array_api_compat_vendor.py
│       │       │   │   ├── _array_api_no_0d.py
│       │       │   │   ├── _bunch.py
│       │       │   │   ├── _ccallback.py
│       │       │   │   ├── _ccallback_c.cp312-win_amd64.dll.a
│       │       │   │   ├── _ccallback_c.cp312-win_amd64.pyd
│       │       │   │   ├── _disjoint_set.py
│       │       │   │   ├── _docscrape.py
│       │       │   │   ├── _elementwise_iterative_method.py
│       │       │   │   ├── _fpumode.cp312-win_amd64.dll.a
│       │       │   │   ├── _fpumode.cp312-win_amd64.pyd
│       │       │   │   ├── _gcutils.py
│       │       │   │   ├── _pep440.py
│       │       │   │   ├── _sparse.py
│       │       │   │   ├── _testutils.py
│       │       │   │   ├── _test_ccallback.cp312-win_amd64.dll.a
│       │       │   │   ├── _test_ccallback.cp312-win_amd64.pyd
│       │       │   │   ├── _test_deprecation_call.cp312-win_amd64.dll.a
│       │       │   │   ├── _test_deprecation_call.cp312-win_amd64.pyd
│       │       │   │   ├── _test_deprecation_def.cp312-win_amd64.dll.a
│       │       │   │   ├── _test_deprecation_def.cp312-win_amd64.pyd
│       │       │   │   ├── _threadsafety.py
│       │       │   │   ├── _tmpdirs.py
│       │       │   │   ├── _uarray/
│       │       │   │   │   ├── LICENSE
│       │       │   │   │   ├── _backend.py
│       │       │   │   │   ├── _uarray.cp312-win_amd64.dll.a
│       │       │   │   │   ├── _uarray.cp312-win_amd64.pyd
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _util.py
│       │       │   │   └── __init__.py
│       │       │   ├── __config__.py
│       │       │   └── __init__.py
│       │       ├── scipy-1.16.0-cp312-cp312-win_amd64.whl
│       │       ├── scipy-1.16.0.dist-info/
│       │       │   ├── DELVEWHEEL
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── scipy.libs/
│       │       │   └── libscipy_openblas-f07f5a5d207a3a47104dca54d6d0c86a.dll
│       │       ├── six-1.17.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── six.py
│       │       ├── sklearn/
│       │       │   ├── base.py
│       │       │   ├── calibration.py
│       │       │   ├── cluster/
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── test_affinity_propagation.py
│       │       │   │   │   ├── test_bicluster.py
│       │       │   │   │   ├── test_birch.py
│       │       │   │   │   ├── test_bisect_k_means.py
│       │       │   │   │   ├── test_dbscan.py
│       │       │   │   │   ├── test_feature_agglomeration.py
│       │       │   │   │   ├── test_hdbscan.py
│       │       │   │   │   ├── test_hierarchical.py
│       │       │   │   │   ├── test_k_means.py
│       │       │   │   │   ├── test_mean_shift.py
│       │       │   │   │   ├── test_optics.py
│       │       │   │   │   ├── test_spectral.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _affinity_propagation.py
│       │       │   │   ├── _agglomerative.py
│       │       │   │   ├── _bicluster.py
│       │       │   │   ├── _birch.py
│       │       │   │   ├── _bisect_k_means.py
│       │       │   │   ├── _dbscan.py
│       │       │   │   ├── _dbscan_inner.cp312-win_amd64.lib
│       │       │   │   ├── _dbscan_inner.cp312-win_amd64.pyd
│       │       │   │   ├── _dbscan_inner.pyx
│       │       │   │   ├── _feature_agglomeration.py
│       │       │   │   ├── _hdbscan/
│       │       │   │   │   ├── hdbscan.py
│       │       │   │   │   ├── meson.build
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_reachibility.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _linkage.cp312-win_amd64.lib
│       │       │   │   │   ├── _linkage.cp312-win_amd64.pyd
│       │       │   │   │   ├── _linkage.pyx
│       │       │   │   │   ├── _reachability.cp312-win_amd64.lib
│       │       │   │   │   ├── _reachability.cp312-win_amd64.pyd
│       │       │   │   │   ├── _reachability.pyx
│       │       │   │   │   ├── _tree.cp312-win_amd64.lib
│       │       │   │   │   ├── _tree.cp312-win_amd64.pyd
│       │       │   │   │   ├── _tree.pxd
│       │       │   │   │   ├── _tree.pyx
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _hierarchical_fast.cp312-win_amd64.lib
│       │       │   │   ├── _hierarchical_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _hierarchical_fast.pxd
│       │       │   │   ├── _hierarchical_fast.pyx
│       │       │   │   ├── _kmeans.py
│       │       │   │   ├── _k_means_common.cp312-win_amd64.lib
│       │       │   │   ├── _k_means_common.cp312-win_amd64.pyd
│       │       │   │   ├── _k_means_common.pxd
│       │       │   │   ├── _k_means_common.pyx
│       │       │   │   ├── _k_means_elkan.cp312-win_amd64.lib
│       │       │   │   ├── _k_means_elkan.cp312-win_amd64.pyd
│       │       │   │   ├── _k_means_elkan.pyx
│       │       │   │   ├── _k_means_lloyd.cp312-win_amd64.lib
│       │       │   │   ├── _k_means_lloyd.cp312-win_amd64.pyd
│       │       │   │   ├── _k_means_lloyd.pyx
│       │       │   │   ├── _k_means_minibatch.cp312-win_amd64.lib
│       │       │   │   ├── _k_means_minibatch.cp312-win_amd64.pyd
│       │       │   │   ├── _k_means_minibatch.pyx
│       │       │   │   ├── _mean_shift.py
│       │       │   │   ├── _optics.py
│       │       │   │   ├── _spectral.py
│       │       │   │   └── __init__.py
│       │       │   ├── compose/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_column_transformer.py
│       │       │   │   │   ├── test_target.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _column_transformer.py
│       │       │   │   ├── _target.py
│       │       │   │   └── __init__.py
│       │       │   ├── conftest.py
│       │       │   ├── covariance/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_covariance.py
│       │       │   │   │   ├── test_elliptic_envelope.py
│       │       │   │   │   ├── test_graphical_lasso.py
│       │       │   │   │   ├── test_robust_covariance.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _elliptic_envelope.py
│       │       │   │   ├── _empirical_covariance.py
│       │       │   │   ├── _graph_lasso.py
│       │       │   │   ├── _robust_covariance.py
│       │       │   │   ├── _shrunk_covariance.py
│       │       │   │   └── __init__.py
│       │       │   ├── cross_decomposition/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_pls.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _pls.py
│       │       │   │   └── __init__.py
│       │       │   ├── datasets/
│       │       │   │   ├── data/
│       │       │   │   │   ├── breast_cancer.csv
│       │       │   │   │   ├── diabetes_data_raw.csv.gz
│       │       │   │   │   ├── diabetes_target.csv.gz
│       │       │   │   │   ├── digits.csv.gz
│       │       │   │   │   ├── iris.csv
│       │       │   │   │   ├── linnerud_exercise.csv
│       │       │   │   │   ├── linnerud_physiological.csv
│       │       │   │   │   ├── wine_data.csv
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── descr/
│       │       │   │   │   ├── breast_cancer.rst
│       │       │   │   │   ├── california_housing.rst
│       │       │   │   │   ├── covtype.rst
│       │       │   │   │   ├── diabetes.rst
│       │       │   │   │   ├── digits.rst
│       │       │   │   │   ├── iris.rst
│       │       │   │   │   ├── kddcup99.rst
│       │       │   │   │   ├── lfw.rst
│       │       │   │   │   ├── linnerud.rst
│       │       │   │   │   ├── olivetti_faces.rst
│       │       │   │   │   ├── rcv1.rst
│       │       │   │   │   ├── species_distributions.rst
│       │       │   │   │   ├── twenty_newsgroups.rst
│       │       │   │   │   ├── wine_data.rst
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── images/
│       │       │   │   │   ├── china.jpg
│       │       │   │   │   ├── flower.jpg
│       │       │   │   │   ├── README.txt
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── data/
│       │       │   │   │   │   ├── openml/
│       │       │   │   │   │   │   ├── id_1/
│       │       │   │   │   │   │   │   ├── api-v1-jd-1.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-1.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-1.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-1.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_1119/
│       │       │   │   │   │   │   │   ├── api-v1-jd-1119.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-1119.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-adult-census-l-2-dv-1.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-adult-census-l-2-s-act-.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-1119.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-54002.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_1590/
│       │       │   │   │   │   │   │   ├── api-v1-jd-1590.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-1590.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-1590.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-1595261.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_2/
│       │       │   │   │   │   │   │   ├── api-v1-jd-2.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-2.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-anneal-l-2-dv-1.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-anneal-l-2-s-act-.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-2.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-1666876.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_292/
│       │       │   │   │   │   │   │   ├── api-v1-jd-292.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jd-40981.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-292.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-40981.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-australian-l-2-dv-1-s-dact.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-australian-l-2-dv-1.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-australian-l-2-s-act-.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-49822.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_3/
│       │       │   │   │   │   │   │   ├── api-v1-jd-3.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-3.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-3.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-3.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_40589/
│       │       │   │   │   │   │   │   ├── api-v1-jd-40589.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-40589.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-emotions-l-2-dv-3.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-emotions-l-2-s-act-.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-40589.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-4644182.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_40675/
│       │       │   │   │   │   │   │   ├── api-v1-jd-40675.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-40675.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-glass2-l-2-dv-1-s-dact.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-glass2-l-2-dv-1.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-glass2-l-2-s-act-.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-40675.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-4965250.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_40945/
│       │       │   │   │   │   │   │   ├── api-v1-jd-40945.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-40945.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-40945.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-16826755.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_40966/
│       │       │   │   │   │   │   │   ├── api-v1-jd-40966.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-40966.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-miceprotein-l-2-dv-4.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-miceprotein-l-2-s-act-.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-40966.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-17928620.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_42074/
│       │       │   │   │   │   │   │   ├── api-v1-jd-42074.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-42074.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-42074.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-21552912.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_42585/
│       │       │   │   │   │   │   │   ├── api-v1-jd-42585.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-42585.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-42585.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-21854866.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_561/
│       │       │   │   │   │   │   │   ├── api-v1-jd-561.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-561.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-cpu-l-2-dv-1.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-cpu-l-2-s-act-.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-561.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-52739.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_61/
│       │       │   │   │   │   │   │   ├── api-v1-jd-61.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-61.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-iris-l-2-dv-1.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdl-dn-iris-l-2-s-act-.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-61.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-61.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   ├── id_62/
│       │       │   │   │   │   │   │   ├── api-v1-jd-62.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdf-62.json.gz
│       │       │   │   │   │   │   │   ├── api-v1-jdq-62.json.gz
│       │       │   │   │   │   │   │   ├── data-v1-dl-52352.arff.gz
│       │       │   │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   ├── svmlight_classification.txt
│       │       │   │   │   │   ├── svmlight_invalid.txt
│       │       │   │   │   │   ├── svmlight_invalid_order.txt
│       │       │   │   │   │   ├── svmlight_multilabel.txt
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── test_20news.py
│       │       │   │   │   ├── test_arff_parser.py
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_california_housing.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_covtype.py
│       │       │   │   │   ├── test_kddcup99.py
│       │       │   │   │   ├── test_lfw.py
│       │       │   │   │   ├── test_olivetti_faces.py
│       │       │   │   │   ├── test_openml.py
│       │       │   │   │   ├── test_rcv1.py
│       │       │   │   │   ├── test_samples_generator.py
│       │       │   │   │   ├── test_svmlight_format.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _arff_parser.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _california_housing.py
│       │       │   │   ├── _covtype.py
│       │       │   │   ├── _kddcup99.py
│       │       │   │   ├── _lfw.py
│       │       │   │   ├── _olivetti_faces.py
│       │       │   │   ├── _openml.py
│       │       │   │   ├── _rcv1.py
│       │       │   │   ├── _samples_generator.py
│       │       │   │   ├── _species_distributions.py
│       │       │   │   ├── _svmlight_format_fast.cp312-win_amd64.lib
│       │       │   │   ├── _svmlight_format_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _svmlight_format_fast.pyx
│       │       │   │   ├── _svmlight_format_io.py
│       │       │   │   ├── _twenty_newsgroups.py
│       │       │   │   └── __init__.py
│       │       │   ├── decomposition/
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_dict_learning.py
│       │       │   │   │   ├── test_factor_analysis.py
│       │       │   │   │   ├── test_fastica.py
│       │       │   │   │   ├── test_incremental_pca.py
│       │       │   │   │   ├── test_kernel_pca.py
│       │       │   │   │   ├── test_nmf.py
│       │       │   │   │   ├── test_online_lda.py
│       │       │   │   │   ├── test_pca.py
│       │       │   │   │   ├── test_sparse_pca.py
│       │       │   │   │   ├── test_truncated_svd.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _cdnmf_fast.cp312-win_amd64.lib
│       │       │   │   ├── _cdnmf_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _cdnmf_fast.pyx
│       │       │   │   ├── _dict_learning.py
│       │       │   │   ├── _factor_analysis.py
│       │       │   │   ├── _fastica.py
│       │       │   │   ├── _incremental_pca.py
│       │       │   │   ├── _kernel_pca.py
│       │       │   │   ├── _lda.py
│       │       │   │   ├── _nmf.py
│       │       │   │   ├── _online_lda_fast.cp312-win_amd64.lib
│       │       │   │   ├── _online_lda_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _online_lda_fast.pyx
│       │       │   │   ├── _pca.py
│       │       │   │   ├── _sparse_pca.py
│       │       │   │   ├── _truncated_svd.py
│       │       │   │   └── __init__.py
│       │       │   ├── discriminant_analysis.py
│       │       │   ├── dummy.py
│       │       │   ├── ensemble/
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_bagging.py
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_forest.py
│       │       │   │   │   ├── test_gradient_boosting.py
│       │       │   │   │   ├── test_iforest.py
│       │       │   │   │   ├── test_stacking.py
│       │       │   │   │   ├── test_voting.py
│       │       │   │   │   ├── test_weight_boosting.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _bagging.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _forest.py
│       │       │   │   ├── _gb.py
│       │       │   │   ├── _gradient_boosting.cp312-win_amd64.lib
│       │       │   │   ├── _gradient_boosting.cp312-win_amd64.pyd
│       │       │   │   ├── _gradient_boosting.pyx
│       │       │   │   ├── _hist_gradient_boosting/
│       │       │   │   │   ├── binning.py
│       │       │   │   │   ├── common.cp312-win_amd64.lib
│       │       │   │   │   ├── common.cp312-win_amd64.pyd
│       │       │   │   │   ├── common.pxd
│       │       │   │   │   ├── common.pyx
│       │       │   │   │   ├── gradient_boosting.py
│       │       │   │   │   ├── grower.py
│       │       │   │   │   ├── histogram.cp312-win_amd64.lib
│       │       │   │   │   ├── histogram.cp312-win_amd64.pyd
│       │       │   │   │   ├── histogram.pyx
│       │       │   │   │   ├── meson.build
│       │       │   │   │   ├── predictor.py
│       │       │   │   │   ├── splitting.cp312-win_amd64.lib
│       │       │   │   │   ├── splitting.cp312-win_amd64.pyd
│       │       │   │   │   ├── splitting.pyx
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_binning.py
│       │       │   │   │   │   ├── test_bitset.py
│       │       │   │   │   │   ├── test_compare_lightgbm.py
│       │       │   │   │   │   ├── test_gradient_boosting.py
│       │       │   │   │   │   ├── test_grower.py
│       │       │   │   │   │   ├── test_histogram.py
│       │       │   │   │   │   ├── test_monotonic_constraints.py
│       │       │   │   │   │   ├── test_predictor.py
│       │       │   │   │   │   ├── test_splitting.py
│       │       │   │   │   │   ├── test_warm_start.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── utils.py
│       │       │   │   │   ├── _binning.cp312-win_amd64.lib
│       │       │   │   │   ├── _binning.cp312-win_amd64.pyd
│       │       │   │   │   ├── _binning.pyx
│       │       │   │   │   ├── _bitset.cp312-win_amd64.lib
│       │       │   │   │   ├── _bitset.cp312-win_amd64.pyd
│       │       │   │   │   ├── _bitset.pxd
│       │       │   │   │   ├── _bitset.pyx
│       │       │   │   │   ├── _gradient_boosting.cp312-win_amd64.lib
│       │       │   │   │   ├── _gradient_boosting.cp312-win_amd64.pyd
│       │       │   │   │   ├── _gradient_boosting.pyx
│       │       │   │   │   ├── _predictor.cp312-win_amd64.lib
│       │       │   │   │   ├── _predictor.cp312-win_amd64.pyd
│       │       │   │   │   ├── _predictor.pyx
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _iforest.py
│       │       │   │   ├── _stacking.py
│       │       │   │   ├── _voting.py
│       │       │   │   ├── _weight_boosting.py
│       │       │   │   └── __init__.py
│       │       │   ├── exceptions.py
│       │       │   ├── experimental/
│       │       │   │   ├── enable_halving_search_cv.py
│       │       │   │   ├── enable_hist_gradient_boosting.py
│       │       │   │   ├── enable_iterative_imputer.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_enable_hist_gradient_boosting.py
│       │       │   │   │   ├── test_enable_iterative_imputer.py
│       │       │   │   │   ├── test_enable_successive_halving.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── externals/
│       │       │   │   ├── array_api_compat/
│       │       │   │   │   ├── common/
│       │       │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   ├── _fft.py
│       │       │   │   │   │   ├── _helpers.py
│       │       │   │   │   │   ├── _linalg.py
│       │       │   │   │   │   ├── _typing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── cupy/
│       │       │   │   │   │   ├── fft.py
│       │       │   │   │   │   ├── linalg.py
│       │       │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   ├── _info.py
│       │       │   │   │   │   ├── _typing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── dask/
│       │       │   │   │   │   ├── array/
│       │       │   │   │   │   │   ├── fft.py
│       │       │   │   │   │   │   ├── linalg.py
│       │       │   │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   │   ├── _info.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── LICENSE
│       │       │   │   │   ├── numpy/
│       │       │   │   │   │   ├── fft.py
│       │       │   │   │   │   ├── linalg.py
│       │       │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   ├── _info.py
│       │       │   │   │   │   ├── _typing.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── README.md
│       │       │   │   │   ├── torch/
│       │       │   │   │   │   ├── fft.py
│       │       │   │   │   │   ├── linalg.py
│       │       │   │   │   │   ├── _aliases.py
│       │       │   │   │   │   ├── _info.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _internal.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── array_api_extra/
│       │       │   │   │   ├── LICENSE
│       │       │   │   │   ├── py.typed
│       │       │   │   │   ├── README.md
│       │       │   │   │   ├── testing.py
│       │       │   │   │   ├── _delegation.py
│       │       │   │   │   ├── _lib/
│       │       │   │   │   │   ├── _at.py
│       │       │   │   │   │   ├── _backends.py
│       │       │   │   │   │   ├── _funcs.py
│       │       │   │   │   │   ├── _lazy.py
│       │       │   │   │   │   ├── _testing.py
│       │       │   │   │   │   ├── _utils/
│       │       │   │   │   │   │   ├── _compat.py
│       │       │   │   │   │   │   ├── _compat.pyi
│       │       │   │   │   │   │   ├── _helpers.py
│       │       │   │   │   │   │   ├── _typing.py
│       │       │   │   │   │   │   ├── _typing.pyi
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── conftest.py
│       │       │   │   ├── README
│       │       │   │   ├── _arff.py
│       │       │   │   ├── _array_api_compat_vendor.py
│       │       │   │   ├── _packaging/
│       │       │   │   │   ├── version.py
│       │       │   │   │   ├── _structures.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _scipy/
│       │       │   │   │   ├── sparse/
│       │       │   │   │   │   ├── csgraph/
│       │       │   │   │   │   │   ├── _laplacian.py
│       │       │   │   │   │   │   └── __init__.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── feature_extraction/
│       │       │   │   ├── image.py
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_dict_vectorizer.py
│       │       │   │   │   ├── test_feature_hasher.py
│       │       │   │   │   ├── test_image.py
│       │       │   │   │   ├── test_text.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── text.py
│       │       │   │   ├── _dict_vectorizer.py
│       │       │   │   ├── _hash.py
│       │       │   │   ├── _hashing_fast.cp312-win_amd64.lib
│       │       │   │   ├── _hashing_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _hashing_fast.pyx
│       │       │   │   ├── _stop_words.py
│       │       │   │   └── __init__.py
│       │       │   ├── feature_selection/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_chi2.py
│       │       │   │   │   ├── test_feature_select.py
│       │       │   │   │   ├── test_from_model.py
│       │       │   │   │   ├── test_mutual_info.py
│       │       │   │   │   ├── test_rfe.py
│       │       │   │   │   ├── test_sequential.py
│       │       │   │   │   ├── test_variance_threshold.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _from_model.py
│       │       │   │   ├── _mutual_info.py
│       │       │   │   ├── _rfe.py
│       │       │   │   ├── _sequential.py
│       │       │   │   ├── _univariate_selection.py
│       │       │   │   ├── _variance_threshold.py
│       │       │   │   └── __init__.py
│       │       │   ├── frozen/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_frozen.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _frozen.py
│       │       │   │   └── __init__.py
│       │       │   ├── gaussian_process/
│       │       │   │   ├── kernels.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_gpc.py
│       │       │   │   │   ├── test_gpr.py
│       │       │   │   │   ├── test_kernels.py
│       │       │   │   │   ├── _mini_sequence_kernel.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _gpc.py
│       │       │   │   ├── _gpr.py
│       │       │   │   └── __init__.py
│       │       │   ├── impute/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_impute.py
│       │       │   │   │   ├── test_knn.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _iterative.py
│       │       │   │   ├── _knn.py
│       │       │   │   └── __init__.py
│       │       │   ├── inspection/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_partial_dependence.py
│       │       │   │   │   ├── test_pd_utils.py
│       │       │   │   │   ├── test_permutation_importance.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _partial_dependence.py
│       │       │   │   ├── _pd_utils.py
│       │       │   │   ├── _permutation_importance.py
│       │       │   │   ├── _plot/
│       │       │   │   │   ├── decision_boundary.py
│       │       │   │   │   ├── partial_dependence.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_boundary_decision_display.py
│       │       │   │   │   │   ├── test_plot_partial_dependence.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── isotonic.py
│       │       │   ├── kernel_approximation.py
│       │       │   ├── kernel_ridge.py
│       │       │   ├── linear_model/
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_bayes.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_coordinate_descent.py
│       │       │   │   │   ├── test_huber.py
│       │       │   │   │   ├── test_least_angle.py
│       │       │   │   │   ├── test_linear_loss.py
│       │       │   │   │   ├── test_logistic.py
│       │       │   │   │   ├── test_omp.py
│       │       │   │   │   ├── test_passive_aggressive.py
│       │       │   │   │   ├── test_perceptron.py
│       │       │   │   │   ├── test_quantile.py
│       │       │   │   │   ├── test_ransac.py
│       │       │   │   │   ├── test_ridge.py
│       │       │   │   │   ├── test_sag.py
│       │       │   │   │   ├── test_sgd.py
│       │       │   │   │   ├── test_sparse_coordinate_descent.py
│       │       │   │   │   ├── test_theil_sen.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _bayes.py
│       │       │   │   ├── _cd_fast.cp312-win_amd64.lib
│       │       │   │   ├── _cd_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _cd_fast.pyx
│       │       │   │   ├── _coordinate_descent.py
│       │       │   │   ├── _glm/
│       │       │   │   │   ├── glm.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_glm.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _newton_solver.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _huber.py
│       │       │   │   ├── _least_angle.py
│       │       │   │   ├── _linear_loss.py
│       │       │   │   ├── _logistic.py
│       │       │   │   ├── _omp.py
│       │       │   │   ├── _passive_aggressive.py
│       │       │   │   ├── _perceptron.py
│       │       │   │   ├── _quantile.py
│       │       │   │   ├── _ransac.py
│       │       │   │   ├── _ridge.py
│       │       │   │   ├── _sag.py
│       │       │   │   ├── _sag_fast.cp312-win_amd64.lib
│       │       │   │   ├── _sag_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _sag_fast.pyx.tp
│       │       │   │   ├── _sgd_fast.cp312-win_amd64.lib
│       │       │   │   ├── _sgd_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _sgd_fast.pyx.tp
│       │       │   │   ├── _stochastic_gradient.py
│       │       │   │   ├── _theil_sen.py
│       │       │   │   └── __init__.py
│       │       │   ├── manifold/
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_isomap.py
│       │       │   │   │   ├── test_locally_linear.py
│       │       │   │   │   ├── test_mds.py
│       │       │   │   │   ├── test_spectral_embedding.py
│       │       │   │   │   ├── test_t_sne.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _barnes_hut_tsne.cp312-win_amd64.lib
│       │       │   │   ├── _barnes_hut_tsne.cp312-win_amd64.pyd
│       │       │   │   ├── _barnes_hut_tsne.pyx
│       │       │   │   ├── _isomap.py
│       │       │   │   ├── _locally_linear.py
│       │       │   │   ├── _mds.py
│       │       │   │   ├── _spectral_embedding.py
│       │       │   │   ├── _t_sne.py
│       │       │   │   ├── _utils.cp312-win_amd64.lib
│       │       │   │   ├── _utils.cp312-win_amd64.pyd
│       │       │   │   ├── _utils.pyx
│       │       │   │   └── __init__.py
│       │       │   ├── meson.build
│       │       │   ├── metrics/
│       │       │   │   ├── cluster/
│       │       │   │   │   ├── meson.build
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_bicluster.py
│       │       │   │   │   │   ├── test_common.py
│       │       │   │   │   │   ├── test_supervised.py
│       │       │   │   │   │   ├── test_unsupervised.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── _bicluster.py
│       │       │   │   │   ├── _expected_mutual_info_fast.cp312-win_amd64.lib
│       │       │   │   │   ├── _expected_mutual_info_fast.cp312-win_amd64.pyd
│       │       │   │   │   ├── _expected_mutual_info_fast.pyx
│       │       │   │   │   ├── _supervised.py
│       │       │   │   │   ├── _unsupervised.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── meson.build
│       │       │   │   ├── pairwise.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_classification.py
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_dist_metrics.py
│       │       │   │   │   ├── test_pairwise.py
│       │       │   │   │   ├── test_pairwise_distances_reduction.py
│       │       │   │   │   ├── test_ranking.py
│       │       │   │   │   ├── test_regression.py
│       │       │   │   │   ├── test_score_objects.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _classification.py
│       │       │   │   ├── _dist_metrics.cp312-win_amd64.lib
│       │       │   │   ├── _dist_metrics.cp312-win_amd64.pyd
│       │       │   │   ├── _dist_metrics.pxd
│       │       │   │   ├── _dist_metrics.pxd.tp
│       │       │   │   ├── _dist_metrics.pyx.tp
│       │       │   │   ├── _pairwise_distances_reduction/
│       │       │   │   │   ├── meson.build
│       │       │   │   │   ├── _argkmin.cp312-win_amd64.lib
│       │       │   │   │   ├── _argkmin.cp312-win_amd64.pyd
│       │       │   │   │   ├── _argkmin.pxd.tp
│       │       │   │   │   ├── _argkmin.pyx.tp
│       │       │   │   │   ├── _argkmin_classmode.cp312-win_amd64.lib
│       │       │   │   │   ├── _argkmin_classmode.cp312-win_amd64.pyd
│       │       │   │   │   ├── _argkmin_classmode.pyx.tp
│       │       │   │   │   ├── _base.cp312-win_amd64.lib
│       │       │   │   │   ├── _base.cp312-win_amd64.pyd
│       │       │   │   │   ├── _base.pxd.tp
│       │       │   │   │   ├── _base.pyx.tp
│       │       │   │   │   ├── _classmode.pxd
│       │       │   │   │   ├── _datasets_pair.cp312-win_amd64.lib
│       │       │   │   │   ├── _datasets_pair.cp312-win_amd64.pyd
│       │       │   │   │   ├── _datasets_pair.pxd.tp
│       │       │   │   │   ├── _datasets_pair.pyx.tp
│       │       │   │   │   ├── _dispatcher.py
│       │       │   │   │   ├── _middle_term_computer.cp312-win_amd64.lib
│       │       │   │   │   ├── _middle_term_computer.cp312-win_amd64.pyd
│       │       │   │   │   ├── _middle_term_computer.pxd.tp
│       │       │   │   │   ├── _middle_term_computer.pyx.tp
│       │       │   │   │   ├── _radius_neighbors.cp312-win_amd64.lib
│       │       │   │   │   ├── _radius_neighbors.cp312-win_amd64.pyd
│       │       │   │   │   ├── _radius_neighbors.pxd.tp
│       │       │   │   │   ├── _radius_neighbors.pyx.tp
│       │       │   │   │   ├── _radius_neighbors_classmode.cp312-win_amd64.lib
│       │       │   │   │   ├── _radius_neighbors_classmode.cp312-win_amd64.pyd
│       │       │   │   │   ├── _radius_neighbors_classmode.pyx.tp
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _pairwise_fast.cp312-win_amd64.lib
│       │       │   │   ├── _pairwise_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _pairwise_fast.pyx
│       │       │   │   ├── _plot/
│       │       │   │   │   ├── confusion_matrix.py
│       │       │   │   │   ├── det_curve.py
│       │       │   │   │   ├── precision_recall_curve.py
│       │       │   │   │   ├── regression.py
│       │       │   │   │   ├── roc_curve.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_common_curve_display.py
│       │       │   │   │   │   ├── test_confusion_matrix_display.py
│       │       │   │   │   │   ├── test_det_curve_display.py
│       │       │   │   │   │   ├── test_precision_recall_display.py
│       │       │   │   │   │   ├── test_predict_error_display.py
│       │       │   │   │   │   ├── test_roc_curve_display.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _ranking.py
│       │       │   │   ├── _regression.py
│       │       │   │   ├── _scorer.py
│       │       │   │   └── __init__.py
│       │       │   ├── mixture/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_bayesian_mixture.py
│       │       │   │   │   ├── test_gaussian_mixture.py
│       │       │   │   │   ├── test_mixture.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _bayesian_mixture.py
│       │       │   │   ├── _gaussian_mixture.py
│       │       │   │   └── __init__.py
│       │       │   ├── model_selection/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── common.py
│       │       │   │   │   ├── test_classification_threshold.py
│       │       │   │   │   ├── test_plot.py
│       │       │   │   │   ├── test_search.py
│       │       │   │   │   ├── test_split.py
│       │       │   │   │   ├── test_successive_halving.py
│       │       │   │   │   ├── test_validation.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _classification_threshold.py
│       │       │   │   ├── _plot.py
│       │       │   │   ├── _search.py
│       │       │   │   ├── _search_successive_halving.py
│       │       │   │   ├── _split.py
│       │       │   │   ├── _validation.py
│       │       │   │   └── __init__.py
│       │       │   ├── multiclass.py
│       │       │   ├── multioutput.py
│       │       │   ├── naive_bayes.py
│       │       │   ├── neighbors/
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_ball_tree.py
│       │       │   │   │   ├── test_graph.py
│       │       │   │   │   ├── test_kde.py
│       │       │   │   │   ├── test_kd_tree.py
│       │       │   │   │   ├── test_lof.py
│       │       │   │   │   ├── test_nca.py
│       │       │   │   │   ├── test_nearest_centroid.py
│       │       │   │   │   ├── test_neighbors.py
│       │       │   │   │   ├── test_neighbors_pipeline.py
│       │       │   │   │   ├── test_neighbors_tree.py
│       │       │   │   │   ├── test_quad_tree.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _ball_tree.cp312-win_amd64.lib
│       │       │   │   ├── _ball_tree.cp312-win_amd64.pyd
│       │       │   │   ├── _ball_tree.pyx.tp
│       │       │   │   ├── _base.py
│       │       │   │   ├── _binary_tree.pxi.tp
│       │       │   │   ├── _classification.py
│       │       │   │   ├── _graph.py
│       │       │   │   ├── _kde.py
│       │       │   │   ├── _kd_tree.cp312-win_amd64.lib
│       │       │   │   ├── _kd_tree.cp312-win_amd64.pyd
│       │       │   │   ├── _kd_tree.pyx.tp
│       │       │   │   ├── _lof.py
│       │       │   │   ├── _nca.py
│       │       │   │   ├── _nearest_centroid.py
│       │       │   │   ├── _partition_nodes.cp312-win_amd64.lib
│       │       │   │   ├── _partition_nodes.cp312-win_amd64.pyd
│       │       │   │   ├── _partition_nodes.pxd
│       │       │   │   ├── _partition_nodes.pyx
│       │       │   │   ├── _quad_tree.cp312-win_amd64.lib
│       │       │   │   ├── _quad_tree.cp312-win_amd64.pyd
│       │       │   │   ├── _quad_tree.pxd
│       │       │   │   ├── _quad_tree.pyx
│       │       │   │   ├── _regression.py
│       │       │   │   ├── _unsupervised.py
│       │       │   │   └── __init__.py
│       │       │   ├── neural_network/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_base.py
│       │       │   │   │   ├── test_mlp.py
│       │       │   │   │   ├── test_rbm.py
│       │       │   │   │   ├── test_stochastic_optimizers.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _multilayer_perceptron.py
│       │       │   │   ├── _rbm.py
│       │       │   │   ├── _stochastic_optimizers.py
│       │       │   │   └── __init__.py
│       │       │   ├── pipeline.py
│       │       │   ├── preprocessing/
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_common.py
│       │       │   │   │   ├── test_data.py
│       │       │   │   │   ├── test_discretization.py
│       │       │   │   │   ├── test_encoders.py
│       │       │   │   │   ├── test_function_transformer.py
│       │       │   │   │   ├── test_label.py
│       │       │   │   │   ├── test_polynomial.py
│       │       │   │   │   ├── test_target_encoder.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _csr_polynomial_expansion.cp312-win_amd64.lib
│       │       │   │   ├── _csr_polynomial_expansion.cp312-win_amd64.pyd
│       │       │   │   ├── _csr_polynomial_expansion.pyx
│       │       │   │   ├── _data.py
│       │       │   │   ├── _discretization.py
│       │       │   │   ├── _encoders.py
│       │       │   │   ├── _function_transformer.py
│       │       │   │   ├── _label.py
│       │       │   │   ├── _polynomial.py
│       │       │   │   ├── _target_encoder.py
│       │       │   │   ├── _target_encoder_fast.cp312-win_amd64.lib
│       │       │   │   ├── _target_encoder_fast.cp312-win_amd64.pyd
│       │       │   │   ├── _target_encoder_fast.pyx
│       │       │   │   └── __init__.py
│       │       │   ├── random_projection.py
│       │       │   ├── semi_supervised/
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_label_propagation.py
│       │       │   │   │   ├── test_self_training.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _label_propagation.py
│       │       │   │   ├── _self_training.py
│       │       │   │   └── __init__.py
│       │       │   ├── svm/
│       │       │   │   ├── meson.build
│       │       │   │   ├── src/
│       │       │   │   │   ├── liblinear/
│       │       │   │   │   │   ├── COPYRIGHT
│       │       │   │   │   │   ├── liblinear_helper.c
│       │       │   │   │   │   ├── linear.cpp
│       │       │   │   │   │   ├── linear.h
│       │       │   │   │   │   ├── tron.cpp
│       │       │   │   │   │   ├── tron.h
│       │       │   │   │   │   └── _cython_blas_helpers.h
│       │       │   │   │   ├── libsvm/
│       │       │   │   │   │   ├── LIBSVM_CHANGES
│       │       │   │   │   │   ├── libsvm_helper.c
│       │       │   │   │   │   ├── libsvm_sparse_helper.c
│       │       │   │   │   │   ├── libsvm_template.cpp
│       │       │   │   │   │   ├── svm.cpp
│       │       │   │   │   │   ├── svm.h
│       │       │   │   │   │   └── _svm_cython_blas_helpers.h
│       │       │   │   │   └── newrand/
│       │       │   │   │       └── newrand.h
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_bounds.py
│       │       │   │   │   ├── test_sparse.py
│       │       │   │   │   ├── test_svm.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _base.py
│       │       │   │   ├── _bounds.py
│       │       │   │   ├── _classes.py
│       │       │   │   ├── _liblinear.cp312-win_amd64.lib
│       │       │   │   ├── _liblinear.cp312-win_amd64.pyd
│       │       │   │   ├── _liblinear.pxi
│       │       │   │   ├── _liblinear.pyx
│       │       │   │   ├── _libsvm.cp312-win_amd64.lib
│       │       │   │   ├── _libsvm.cp312-win_amd64.pyd
│       │       │   │   ├── _libsvm.pxi
│       │       │   │   ├── _libsvm.pyx
│       │       │   │   ├── _libsvm_sparse.cp312-win_amd64.lib
│       │       │   │   ├── _libsvm_sparse.cp312-win_amd64.pyd
│       │       │   │   ├── _libsvm_sparse.pyx
│       │       │   │   ├── _newrand.cp312-win_amd64.lib
│       │       │   │   ├── _newrand.cp312-win_amd64.pyd
│       │       │   │   ├── _newrand.pyx
│       │       │   │   └── __init__.py
│       │       │   ├── tests/
│       │       │   │   ├── metadata_routing_common.py
│       │       │   │   ├── test_base.py
│       │       │   │   ├── test_build.py
│       │       │   │   ├── test_calibration.py
│       │       │   │   ├── test_check_build.py
│       │       │   │   ├── test_common.py
│       │       │   │   ├── test_config.py
│       │       │   │   ├── test_discriminant_analysis.py
│       │       │   │   ├── test_docstrings.py
│       │       │   │   ├── test_docstring_parameters.py
│       │       │   │   ├── test_docstring_parameters_consistency.py
│       │       │   │   ├── test_dummy.py
│       │       │   │   ├── test_init.py
│       │       │   │   ├── test_isotonic.py
│       │       │   │   ├── test_kernel_approximation.py
│       │       │   │   ├── test_kernel_ridge.py
│       │       │   │   ├── test_metadata_routing.py
│       │       │   │   ├── test_metaestimators.py
│       │       │   │   ├── test_metaestimators_metadata_routing.py
│       │       │   │   ├── test_min_dependencies_readme.py
│       │       │   │   ├── test_multiclass.py
│       │       │   │   ├── test_multioutput.py
│       │       │   │   ├── test_naive_bayes.py
│       │       │   │   ├── test_pipeline.py
│       │       │   │   ├── test_public_functions.py
│       │       │   │   ├── test_random_projection.py
│       │       │   │   └── __init__.py
│       │       │   ├── tree/
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_export.py
│       │       │   │   │   ├── test_monotonic_tree.py
│       │       │   │   │   ├── test_reingold_tilford.py
│       │       │   │   │   ├── test_tree.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _classes.py
│       │       │   │   ├── _criterion.cp312-win_amd64.lib
│       │       │   │   ├── _criterion.cp312-win_amd64.pyd
│       │       │   │   ├── _criterion.pxd
│       │       │   │   ├── _criterion.pyx
│       │       │   │   ├── _export.py
│       │       │   │   ├── _partitioner.cp312-win_amd64.lib
│       │       │   │   ├── _partitioner.cp312-win_amd64.pyd
│       │       │   │   ├── _partitioner.pxd
│       │       │   │   ├── _partitioner.pyx
│       │       │   │   ├── _reingold_tilford.py
│       │       │   │   ├── _splitter.cp312-win_amd64.lib
│       │       │   │   ├── _splitter.cp312-win_amd64.pyd
│       │       │   │   ├── _splitter.pxd
│       │       │   │   ├── _splitter.pyx
│       │       │   │   ├── _tree.cp312-win_amd64.lib
│       │       │   │   ├── _tree.cp312-win_amd64.pyd
│       │       │   │   ├── _tree.pxd
│       │       │   │   ├── _tree.pyx
│       │       │   │   ├── _utils.cp312-win_amd64.lib
│       │       │   │   ├── _utils.cp312-win_amd64.pyd
│       │       │   │   ├── _utils.pxd
│       │       │   │   ├── _utils.pyx
│       │       │   │   └── __init__.py
│       │       │   ├── utils/
│       │       │   │   ├── arrayfuncs.cp312-win_amd64.lib
│       │       │   │   ├── arrayfuncs.cp312-win_amd64.pyd
│       │       │   │   ├── arrayfuncs.pyx
│       │       │   │   ├── class_weight.py
│       │       │   │   ├── deprecation.py
│       │       │   │   ├── discovery.py
│       │       │   │   ├── estimator_checks.py
│       │       │   │   ├── extmath.py
│       │       │   │   ├── fixes.py
│       │       │   │   ├── graph.py
│       │       │   │   ├── meson.build
│       │       │   │   ├── metadata_routing.py
│       │       │   │   ├── metaestimators.py
│       │       │   │   ├── multiclass.py
│       │       │   │   ├── murmurhash.cp312-win_amd64.lib
│       │       │   │   ├── murmurhash.cp312-win_amd64.pyd
│       │       │   │   ├── murmurhash.pxd
│       │       │   │   ├── murmurhash.pyx
│       │       │   │   ├── optimize.py
│       │       │   │   ├── parallel.py
│       │       │   │   ├── random.py
│       │       │   │   ├── sparsefuncs.py
│       │       │   │   ├── sparsefuncs_fast.cp312-win_amd64.lib
│       │       │   │   ├── sparsefuncs_fast.cp312-win_amd64.pyd
│       │       │   │   ├── sparsefuncs_fast.pyx
│       │       │   │   ├── src/
│       │       │   │   │   ├── MurmurHash3.cpp
│       │       │   │   │   └── MurmurHash3.h
│       │       │   │   ├── stats.py
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_arpack.py
│       │       │   │   │   ├── test_arrayfuncs.py
│       │       │   │   │   ├── test_array_api.py
│       │       │   │   │   ├── test_bunch.py
│       │       │   │   │   ├── test_chunking.py
│       │       │   │   │   ├── test_class_weight.py
│       │       │   │   │   ├── test_cython_blas.py
│       │       │   │   │   ├── test_deprecation.py
│       │       │   │   │   ├── test_encode.py
│       │       │   │   │   ├── test_estimator_checks.py
│       │       │   │   │   ├── test_extmath.py
│       │       │   │   │   ├── test_fast_dict.py
│       │       │   │   │   ├── test_fixes.py
│       │       │   │   │   ├── test_graph.py
│       │       │   │   │   ├── test_indexing.py
│       │       │   │   │   ├── test_mask.py
│       │       │   │   │   ├── test_metaestimators.py
│       │       │   │   │   ├── test_missing.py
│       │       │   │   │   ├── test_mocking.py
│       │       │   │   │   ├── test_multiclass.py
│       │       │   │   │   ├── test_murmurhash.py
│       │       │   │   │   ├── test_optimize.py
│       │       │   │   │   ├── test_parallel.py
│       │       │   │   │   ├── test_param_validation.py
│       │       │   │   │   ├── test_plotting.py
│       │       │   │   │   ├── test_pprint.py
│       │       │   │   │   ├── test_random.py
│       │       │   │   │   ├── test_response.py
│       │       │   │   │   ├── test_seq_dataset.py
│       │       │   │   │   ├── test_set_output.py
│       │       │   │   │   ├── test_shortest_path.py
│       │       │   │   │   ├── test_show_versions.py
│       │       │   │   │   ├── test_sparsefuncs.py
│       │       │   │   │   ├── test_stats.py
│       │       │   │   │   ├── test_tags.py
│       │       │   │   │   ├── test_testing.py
│       │       │   │   │   ├── test_typedefs.py
│       │       │   │   │   ├── test_unique.py
│       │       │   │   │   ├── test_user_interface.py
│       │       │   │   │   ├── test_validation.py
│       │       │   │   │   ├── test_weight_vector.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── validation.py
│       │       │   │   ├── _arpack.py
│       │       │   │   ├── _array_api.py
│       │       │   │   ├── _available_if.py
│       │       │   │   ├── _bunch.py
│       │       │   │   ├── _chunking.py
│       │       │   │   ├── _cython_blas.cp312-win_amd64.lib
│       │       │   │   ├── _cython_blas.cp312-win_amd64.pyd
│       │       │   │   ├── _cython_blas.pxd
│       │       │   │   ├── _cython_blas.pyx
│       │       │   │   ├── _encode.py
│       │       │   │   ├── _fast_dict.cp312-win_amd64.lib
│       │       │   │   ├── _fast_dict.cp312-win_amd64.pyd
│       │       │   │   ├── _fast_dict.pxd
│       │       │   │   ├── _fast_dict.pyx
│       │       │   │   ├── _heap.cp312-win_amd64.lib
│       │       │   │   ├── _heap.cp312-win_amd64.pyd
│       │       │   │   ├── _heap.pxd
│       │       │   │   ├── _heap.pyx
│       │       │   │   ├── _indexing.py
│       │       │   │   ├── _isfinite.cp312-win_amd64.lib
│       │       │   │   ├── _isfinite.cp312-win_amd64.pyd
│       │       │   │   ├── _isfinite.pyx
│       │       │   │   ├── _mask.py
│       │       │   │   ├── _metadata_requests.py
│       │       │   │   ├── _missing.py
│       │       │   │   ├── _mocking.py
│       │       │   │   ├── _openmp_helpers.cp312-win_amd64.lib
│       │       │   │   ├── _openmp_helpers.cp312-win_amd64.pyd
│       │       │   │   ├── _openmp_helpers.pxd
│       │       │   │   ├── _openmp_helpers.pyx
│       │       │   │   ├── _optional_dependencies.py
│       │       │   │   ├── _param_validation.py
│       │       │   │   ├── _plotting.py
│       │       │   │   ├── _pprint.py
│       │       │   │   ├── _random.cp312-win_amd64.lib
│       │       │   │   ├── _random.cp312-win_amd64.pyd
│       │       │   │   ├── _random.pxd
│       │       │   │   ├── _random.pyx
│       │       │   │   ├── _repr_html/
│       │       │   │   │   ├── base.py
│       │       │   │   │   ├── estimator.css
│       │       │   │   │   ├── estimator.js
│       │       │   │   │   ├── estimator.py
│       │       │   │   │   ├── params.css
│       │       │   │   │   ├── params.py
│       │       │   │   │   ├── tests/
│       │       │   │   │   │   ├── test_estimator.py
│       │       │   │   │   │   ├── test_params.py
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _response.py
│       │       │   │   ├── _seq_dataset.cp312-win_amd64.lib
│       │       │   │   ├── _seq_dataset.cp312-win_amd64.pyd
│       │       │   │   ├── _seq_dataset.pxd.tp
│       │       │   │   ├── _seq_dataset.pyx.tp
│       │       │   │   ├── _set_output.py
│       │       │   │   ├── _show_versions.py
│       │       │   │   ├── _sorting.cp312-win_amd64.lib
│       │       │   │   ├── _sorting.cp312-win_amd64.pyd
│       │       │   │   ├── _sorting.pxd
│       │       │   │   ├── _sorting.pyx
│       │       │   │   ├── _tags.py
│       │       │   │   ├── _testing.py
│       │       │   │   ├── _test_common/
│       │       │   │   │   ├── instance_generator.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _typedefs.cp312-win_amd64.lib
│       │       │   │   ├── _typedefs.cp312-win_amd64.pyd
│       │       │   │   ├── _typedefs.pxd
│       │       │   │   ├── _typedefs.pyx
│       │       │   │   ├── _unique.py
│       │       │   │   ├── _user_interface.py
│       │       │   │   ├── _vector_sentinel.cp312-win_amd64.lib
│       │       │   │   ├── _vector_sentinel.cp312-win_amd64.pyd
│       │       │   │   ├── _vector_sentinel.pxd
│       │       │   │   ├── _vector_sentinel.pyx
│       │       │   │   ├── _weight_vector.cp312-win_amd64.lib
│       │       │   │   ├── _weight_vector.cp312-win_amd64.pyd
│       │       │   │   ├── _weight_vector.pxd.tp
│       │       │   │   ├── _weight_vector.pyx.tp
│       │       │   │   └── __init__.py
│       │       │   ├── _build_utils/
│       │       │   │   ├── tempita.py
│       │       │   │   ├── version.py
│       │       │   │   └── __init__.py
│       │       │   ├── _built_with_meson.py
│       │       │   ├── _config.py
│       │       │   ├── _distributor_init.py
│       │       │   ├── _isotonic.cp312-win_amd64.lib
│       │       │   ├── _isotonic.cp312-win_amd64.pyd
│       │       │   ├── _isotonic.pyx
│       │       │   ├── _loss/
│       │       │   │   ├── link.py
│       │       │   │   ├── loss.py
│       │       │   │   ├── meson.build
│       │       │   │   ├── tests/
│       │       │   │   │   ├── test_link.py
│       │       │   │   │   ├── test_loss.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── _loss.cp312-win_amd64.lib
│       │       │   │   ├── _loss.cp312-win_amd64.pyd
│       │       │   │   ├── _loss.pxd
│       │       │   │   ├── _loss.pyx.tp
│       │       │   │   └── __init__.py
│       │       │   ├── _min_dependencies.py
│       │       │   ├── __check_build/
│       │       │   │   ├── meson.build
│       │       │   │   ├── _check_build.cp312-win_amd64.lib
│       │       │   │   ├── _check_build.cp312-win_amd64.pyd
│       │       │   │   ├── _check_build.pyx
│       │       │   │   └── __init__.py
│       │       │   └── __init__.py
│       │       ├── sniffio/
│       │       │   ├── py.typed
│       │       │   ├── _impl.py
│       │       │   ├── _tests/
│       │       │   │   ├── test_sniffio.py
│       │       │   │   └── __init__.py
│       │       │   ├── _version.py
│       │       │   └── __init__.py
│       │       ├── sniffio-1.3.1.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── LICENSE.APACHE2
│       │       │   ├── LICENSE.MIT
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── starlette/
│       │       │   ├── applications.py
│       │       │   ├── authentication.py
│       │       │   ├── background.py
│       │       │   ├── concurrency.py
│       │       │   ├── config.py
│       │       │   ├── convertors.py
│       │       │   ├── datastructures.py
│       │       │   ├── endpoints.py
│       │       │   ├── exceptions.py
│       │       │   ├── formparsers.py
│       │       │   ├── middleware/
│       │       │   │   ├── authentication.py
│       │       │   │   ├── base.py
│       │       │   │   ├── cors.py
│       │       │   │   ├── errors.py
│       │       │   │   ├── exceptions.py
│       │       │   │   ├── gzip.py
│       │       │   │   ├── httpsredirect.py
│       │       │   │   ├── sessions.py
│       │       │   │   ├── trustedhost.py
│       │       │   │   ├── wsgi.py
│       │       │   │   └── __init__.py
│       │       │   ├── py.typed
│       │       │   ├── requests.py
│       │       │   ├── responses.py
│       │       │   ├── routing.py
│       │       │   ├── schemas.py
│       │       │   ├── staticfiles.py
│       │       │   ├── status.py
│       │       │   ├── templating.py
│       │       │   ├── testclient.py
│       │       │   ├── types.py
│       │       │   ├── websockets.py
│       │       │   ├── _exception_handler.py
│       │       │   ├── _utils.py
│       │       │   └── __init__.py
│       │       ├── starlette-0.46.2.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.md
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── threadpoolctl-3.6.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── threadpoolctl.py
│       │       ├── tldextract/
│       │       │   ├── cache.py
│       │       │   ├── cli.py
│       │       │   ├── py.typed
│       │       │   ├── remote.py
│       │       │   ├── suffix_list.py
│       │       │   ├── tldextract.py
│       │       │   ├── _version.py
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── tldextract-5.3.0.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── typing_extensions-4.14.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── typing_extensions.py
│       │       ├── typing_inspection/
│       │       │   ├── introspection.py
│       │       │   ├── py.typed
│       │       │   ├── typing_objects.py
│       │       │   ├── typing_objects.pyi
│       │       │   └── __init__.py
│       │       ├── typing_inspection-0.4.1.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── tzdata/
│       │       │   ├── zoneinfo/
│       │       │   │   ├── Africa/
│       │       │   │   │   ├── Abidjan
│       │       │   │   │   ├── Accra
│       │       │   │   │   ├── Addis_Ababa
│       │       │   │   │   ├── Algiers
│       │       │   │   │   ├── Asmara
│       │       │   │   │   ├── Asmera
│       │       │   │   │   ├── Bamako
│       │       │   │   │   ├── Bangui
│       │       │   │   │   ├── Banjul
│       │       │   │   │   ├── Bissau
│       │       │   │   │   ├── Blantyre
│       │       │   │   │   ├── Brazzaville
│       │       │   │   │   ├── Bujumbura
│       │       │   │   │   ├── Cairo
│       │       │   │   │   ├── Casablanca
│       │       │   │   │   ├── Ceuta
│       │       │   │   │   ├── Conakry
│       │       │   │   │   ├── Dakar
│       │       │   │   │   ├── Dar_es_Salaam
│       │       │   │   │   ├── Djibouti
│       │       │   │   │   ├── Douala
│       │       │   │   │   ├── El_Aaiun
│       │       │   │   │   ├── Freetown
│       │       │   │   │   ├── Gaborone
│       │       │   │   │   ├── Harare
│       │       │   │   │   ├── Johannesburg
│       │       │   │   │   ├── Juba
│       │       │   │   │   ├── Kampala
│       │       │   │   │   ├── Khartoum
│       │       │   │   │   ├── Kigali
│       │       │   │   │   ├── Kinshasa
│       │       │   │   │   ├── Lagos
│       │       │   │   │   ├── Libreville
│       │       │   │   │   ├── Lome
│       │       │   │   │   ├── Luanda
│       │       │   │   │   ├── Lubumbashi
│       │       │   │   │   ├── Lusaka
│       │       │   │   │   ├── Malabo
│       │       │   │   │   ├── Maputo
│       │       │   │   │   ├── Maseru
│       │       │   │   │   ├── Mbabane
│       │       │   │   │   ├── Mogadishu
│       │       │   │   │   ├── Monrovia
│       │       │   │   │   ├── Nairobi
│       │       │   │   │   ├── Ndjamena
│       │       │   │   │   ├── Niamey
│       │       │   │   │   ├── Nouakchott
│       │       │   │   │   ├── Ouagadougou
│       │       │   │   │   ├── Porto-Novo
│       │       │   │   │   ├── Sao_Tome
│       │       │   │   │   ├── Timbuktu
│       │       │   │   │   ├── Tripoli
│       │       │   │   │   ├── Tunis
│       │       │   │   │   ├── Windhoek
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── America/
│       │       │   │   │   ├── Adak
│       │       │   │   │   ├── Anchorage
│       │       │   │   │   ├── Anguilla
│       │       │   │   │   ├── Antigua
│       │       │   │   │   ├── Araguaina
│       │       │   │   │   ├── Argentina/
│       │       │   │   │   │   ├── Buenos_Aires
│       │       │   │   │   │   ├── Catamarca
│       │       │   │   │   │   ├── ComodRivadavia
│       │       │   │   │   │   ├── Cordoba
│       │       │   │   │   │   ├── Jujuy
│       │       │   │   │   │   ├── La_Rioja
│       │       │   │   │   │   ├── Mendoza
│       │       │   │   │   │   ├── Rio_Gallegos
│       │       │   │   │   │   ├── Salta
│       │       │   │   │   │   ├── San_Juan
│       │       │   │   │   │   ├── San_Luis
│       │       │   │   │   │   ├── Tucuman
│       │       │   │   │   │   ├── Ushuaia
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── Aruba
│       │       │   │   │   ├── Asuncion
│       │       │   │   │   ├── Atikokan
│       │       │   │   │   ├── Atka
│       │       │   │   │   ├── Bahia
│       │       │   │   │   ├── Bahia_Banderas
│       │       │   │   │   ├── Barbados
│       │       │   │   │   ├── Belem
│       │       │   │   │   ├── Belize
│       │       │   │   │   ├── Blanc-Sablon
│       │       │   │   │   ├── Boa_Vista
│       │       │   │   │   ├── Bogota
│       │       │   │   │   ├── Boise
│       │       │   │   │   ├── Buenos_Aires
│       │       │   │   │   ├── Cambridge_Bay
│       │       │   │   │   ├── Campo_Grande
│       │       │   │   │   ├── Cancun
│       │       │   │   │   ├── Caracas
│       │       │   │   │   ├── Catamarca
│       │       │   │   │   ├── Cayenne
│       │       │   │   │   ├── Cayman
│       │       │   │   │   ├── Chicago
│       │       │   │   │   ├── Chihuahua
│       │       │   │   │   ├── Ciudad_Juarez
│       │       │   │   │   ├── Coral_Harbour
│       │       │   │   │   ├── Cordoba
│       │       │   │   │   ├── Costa_Rica
│       │       │   │   │   ├── Coyhaique
│       │       │   │   │   ├── Creston
│       │       │   │   │   ├── Cuiaba
│       │       │   │   │   ├── Curacao
│       │       │   │   │   ├── Danmarkshavn
│       │       │   │   │   ├── Dawson
│       │       │   │   │   ├── Dawson_Creek
│       │       │   │   │   ├── Denver
│       │       │   │   │   ├── Detroit
│       │       │   │   │   ├── Dominica
│       │       │   │   │   ├── Edmonton
│       │       │   │   │   ├── Eirunepe
│       │       │   │   │   ├── El_Salvador
│       │       │   │   │   ├── Ensenada
│       │       │   │   │   ├── Fortaleza
│       │       │   │   │   ├── Fort_Nelson
│       │       │   │   │   ├── Fort_Wayne
│       │       │   │   │   ├── Glace_Bay
│       │       │   │   │   ├── Godthab
│       │       │   │   │   ├── Goose_Bay
│       │       │   │   │   ├── Grand_Turk
│       │       │   │   │   ├── Grenada
│       │       │   │   │   ├── Guadeloupe
│       │       │   │   │   ├── Guatemala
│       │       │   │   │   ├── Guayaquil
│       │       │   │   │   ├── Guyana
│       │       │   │   │   ├── Halifax
│       │       │   │   │   ├── Havana
│       │       │   │   │   ├── Hermosillo
│       │       │   │   │   ├── Indiana/
│       │       │   │   │   │   ├── Indianapolis
│       │       │   │   │   │   ├── Knox
│       │       │   │   │   │   ├── Marengo
│       │       │   │   │   │   ├── Petersburg
│       │       │   │   │   │   ├── Tell_City
│       │       │   │   │   │   ├── Vevay
│       │       │   │   │   │   ├── Vincennes
│       │       │   │   │   │   ├── Winamac
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── Indianapolis
│       │       │   │   │   ├── Inuvik
│       │       │   │   │   ├── Iqaluit
│       │       │   │   │   ├── Jamaica
│       │       │   │   │   ├── Jujuy
│       │       │   │   │   ├── Juneau
│       │       │   │   │   ├── Kentucky/
│       │       │   │   │   │   ├── Louisville
│       │       │   │   │   │   ├── Monticello
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── Knox_IN
│       │       │   │   │   ├── Kralendijk
│       │       │   │   │   ├── La_Paz
│       │       │   │   │   ├── Lima
│       │       │   │   │   ├── Los_Angeles
│       │       │   │   │   ├── Louisville
│       │       │   │   │   ├── Lower_Princes
│       │       │   │   │   ├── Maceio
│       │       │   │   │   ├── Managua
│       │       │   │   │   ├── Manaus
│       │       │   │   │   ├── Marigot
│       │       │   │   │   ├── Martinique
│       │       │   │   │   ├── Matamoros
│       │       │   │   │   ├── Mazatlan
│       │       │   │   │   ├── Mendoza
│       │       │   │   │   ├── Menominee
│       │       │   │   │   ├── Merida
│       │       │   │   │   ├── Metlakatla
│       │       │   │   │   ├── Mexico_City
│       │       │   │   │   ├── Miquelon
│       │       │   │   │   ├── Moncton
│       │       │   │   │   ├── Monterrey
│       │       │   │   │   ├── Montevideo
│       │       │   │   │   ├── Montreal
│       │       │   │   │   ├── Montserrat
│       │       │   │   │   ├── Nassau
│       │       │   │   │   ├── New_York
│       │       │   │   │   ├── Nipigon
│       │       │   │   │   ├── Nome
│       │       │   │   │   ├── Noronha
│       │       │   │   │   ├── North_Dakota/
│       │       │   │   │   │   ├── Beulah
│       │       │   │   │   │   ├── Center
│       │       │   │   │   │   ├── New_Salem
│       │       │   │   │   │   └── __init__.py
│       │       │   │   │   ├── Nuuk
│       │       │   │   │   ├── Ojinaga
│       │       │   │   │   ├── Panama
│       │       │   │   │   ├── Pangnirtung
│       │       │   │   │   ├── Paramaribo
│       │       │   │   │   ├── Phoenix
│       │       │   │   │   ├── Port-au-Prince
│       │       │   │   │   ├── Porto_Acre
│       │       │   │   │   ├── Porto_Velho
│       │       │   │   │   ├── Port_of_Spain
│       │       │   │   │   ├── Puerto_Rico
│       │       │   │   │   ├── Punta_Arenas
│       │       │   │   │   ├── Rainy_River
│       │       │   │   │   ├── Rankin_Inlet
│       │       │   │   │   ├── Recife
│       │       │   │   │   ├── Regina
│       │       │   │   │   ├── Resolute
│       │       │   │   │   ├── Rio_Branco
│       │       │   │   │   ├── Rosario
│       │       │   │   │   ├── Santarem
│       │       │   │   │   ├── Santa_Isabel
│       │       │   │   │   ├── Santiago
│       │       │   │   │   ├── Santo_Domingo
│       │       │   │   │   ├── Sao_Paulo
│       │       │   │   │   ├── Scoresbysund
│       │       │   │   │   ├── Shiprock
│       │       │   │   │   ├── Sitka
│       │       │   │   │   ├── St_Barthelemy
│       │       │   │   │   ├── St_Johns
│       │       │   │   │   ├── St_Kitts
│       │       │   │   │   ├── St_Lucia
│       │       │   │   │   ├── St_Thomas
│       │       │   │   │   ├── St_Vincent
│       │       │   │   │   ├── Swift_Current
│       │       │   │   │   ├── Tegucigalpa
│       │       │   │   │   ├── Thule
│       │       │   │   │   ├── Thunder_Bay
│       │       │   │   │   ├── Tijuana
│       │       │   │   │   ├── Toronto
│       │       │   │   │   ├── Tortola
│       │       │   │   │   ├── Vancouver
│       │       │   │   │   ├── Virgin
│       │       │   │   │   ├── Whitehorse
│       │       │   │   │   ├── Winnipeg
│       │       │   │   │   ├── Yakutat
│       │       │   │   │   ├── Yellowknife
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Antarctica/
│       │       │   │   │   ├── Casey
│       │       │   │   │   ├── Davis
│       │       │   │   │   ├── DumontDUrville
│       │       │   │   │   ├── Macquarie
│       │       │   │   │   ├── Mawson
│       │       │   │   │   ├── McMurdo
│       │       │   │   │   ├── Palmer
│       │       │   │   │   ├── Rothera
│       │       │   │   │   ├── South_Pole
│       │       │   │   │   ├── Syowa
│       │       │   │   │   ├── Troll
│       │       │   │   │   ├── Vostok
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Arctic/
│       │       │   │   │   ├── Longyearbyen
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Asia/
│       │       │   │   │   ├── Aden
│       │       │   │   │   ├── Almaty
│       │       │   │   │   ├── Amman
│       │       │   │   │   ├── Anadyr
│       │       │   │   │   ├── Aqtau
│       │       │   │   │   ├── Aqtobe
│       │       │   │   │   ├── Ashgabat
│       │       │   │   │   ├── Ashkhabad
│       │       │   │   │   ├── Atyrau
│       │       │   │   │   ├── Baghdad
│       │       │   │   │   ├── Bahrain
│       │       │   │   │   ├── Baku
│       │       │   │   │   ├── Bangkok
│       │       │   │   │   ├── Barnaul
│       │       │   │   │   ├── Beirut
│       │       │   │   │   ├── Bishkek
│       │       │   │   │   ├── Brunei
│       │       │   │   │   ├── Calcutta
│       │       │   │   │   ├── Chita
│       │       │   │   │   ├── Choibalsan
│       │       │   │   │   ├── Chongqing
│       │       │   │   │   ├── Chungking
│       │       │   │   │   ├── Colombo
│       │       │   │   │   ├── Dacca
│       │       │   │   │   ├── Damascus
│       │       │   │   │   ├── Dhaka
│       │       │   │   │   ├── Dili
│       │       │   │   │   ├── Dubai
│       │       │   │   │   ├── Dushanbe
│       │       │   │   │   ├── Famagusta
│       │       │   │   │   ├── Gaza
│       │       │   │   │   ├── Harbin
│       │       │   │   │   ├── Hebron
│       │       │   │   │   ├── Hong_Kong
│       │       │   │   │   ├── Hovd
│       │       │   │   │   ├── Ho_Chi_Minh
│       │       │   │   │   ├── Irkutsk
│       │       │   │   │   ├── Istanbul
│       │       │   │   │   ├── Jakarta
│       │       │   │   │   ├── Jayapura
│       │       │   │   │   ├── Jerusalem
│       │       │   │   │   ├── Kabul
│       │       │   │   │   ├── Kamchatka
│       │       │   │   │   ├── Karachi
│       │       │   │   │   ├── Kashgar
│       │       │   │   │   ├── Kathmandu
│       │       │   │   │   ├── Katmandu
│       │       │   │   │   ├── Khandyga
│       │       │   │   │   ├── Kolkata
│       │       │   │   │   ├── Krasnoyarsk
│       │       │   │   │   ├── Kuala_Lumpur
│       │       │   │   │   ├── Kuching
│       │       │   │   │   ├── Kuwait
│       │       │   │   │   ├── Macao
│       │       │   │   │   ├── Macau
│       │       │   │   │   ├── Magadan
│       │       │   │   │   ├── Makassar
│       │       │   │   │   ├── Manila
│       │       │   │   │   ├── Muscat
│       │       │   │   │   ├── Nicosia
│       │       │   │   │   ├── Novokuznetsk
│       │       │   │   │   ├── Novosibirsk
│       │       │   │   │   ├── Omsk
│       │       │   │   │   ├── Oral
│       │       │   │   │   ├── Phnom_Penh
│       │       │   │   │   ├── Pontianak
│       │       │   │   │   ├── Pyongyang
│       │       │   │   │   ├── Qatar
│       │       │   │   │   ├── Qostanay
│       │       │   │   │   ├── Qyzylorda
│       │       │   │   │   ├── Rangoon
│       │       │   │   │   ├── Riyadh
│       │       │   │   │   ├── Saigon
│       │       │   │   │   ├── Sakhalin
│       │       │   │   │   ├── Samarkand
│       │       │   │   │   ├── Seoul
│       │       │   │   │   ├── Shanghai
│       │       │   │   │   ├── Singapore
│       │       │   │   │   ├── Srednekolymsk
│       │       │   │   │   ├── Taipei
│       │       │   │   │   ├── Tashkent
│       │       │   │   │   ├── Tbilisi
│       │       │   │   │   ├── Tehran
│       │       │   │   │   ├── Tel_Aviv
│       │       │   │   │   ├── Thimbu
│       │       │   │   │   ├── Thimphu
│       │       │   │   │   ├── Tokyo
│       │       │   │   │   ├── Tomsk
│       │       │   │   │   ├── Ujung_Pandang
│       │       │   │   │   ├── Ulaanbaatar
│       │       │   │   │   ├── Ulan_Bator
│       │       │   │   │   ├── Urumqi
│       │       │   │   │   ├── Ust-Nera
│       │       │   │   │   ├── Vientiane
│       │       │   │   │   ├── Vladivostok
│       │       │   │   │   ├── Yakutsk
│       │       │   │   │   ├── Yangon
│       │       │   │   │   ├── Yekaterinburg
│       │       │   │   │   ├── Yerevan
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Atlantic/
│       │       │   │   │   ├── Azores
│       │       │   │   │   ├── Bermuda
│       │       │   │   │   ├── Canary
│       │       │   │   │   ├── Cape_Verde
│       │       │   │   │   ├── Faeroe
│       │       │   │   │   ├── Faroe
│       │       │   │   │   ├── Jan_Mayen
│       │       │   │   │   ├── Madeira
│       │       │   │   │   ├── Reykjavik
│       │       │   │   │   ├── South_Georgia
│       │       │   │   │   ├── Stanley
│       │       │   │   │   ├── St_Helena
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Australia/
│       │       │   │   │   ├── ACT
│       │       │   │   │   ├── Adelaide
│       │       │   │   │   ├── Brisbane
│       │       │   │   │   ├── Broken_Hill
│       │       │   │   │   ├── Canberra
│       │       │   │   │   ├── Currie
│       │       │   │   │   ├── Darwin
│       │       │   │   │   ├── Eucla
│       │       │   │   │   ├── Hobart
│       │       │   │   │   ├── LHI
│       │       │   │   │   ├── Lindeman
│       │       │   │   │   ├── Lord_Howe
│       │       │   │   │   ├── Melbourne
│       │       │   │   │   ├── North
│       │       │   │   │   ├── NSW
│       │       │   │   │   ├── Perth
│       │       │   │   │   ├── Queensland
│       │       │   │   │   ├── South
│       │       │   │   │   ├── Sydney
│       │       │   │   │   ├── Tasmania
│       │       │   │   │   ├── Victoria
│       │       │   │   │   ├── West
│       │       │   │   │   ├── Yancowinna
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Brazil/
│       │       │   │   │   ├── Acre
│       │       │   │   │   ├── DeNoronha
│       │       │   │   │   ├── East
│       │       │   │   │   ├── West
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Canada/
│       │       │   │   │   ├── Atlantic
│       │       │   │   │   ├── Central
│       │       │   │   │   ├── Eastern
│       │       │   │   │   ├── Mountain
│       │       │   │   │   ├── Newfoundland
│       │       │   │   │   ├── Pacific
│       │       │   │   │   ├── Saskatchewan
│       │       │   │   │   ├── Yukon
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── CET
│       │       │   │   ├── Chile/
│       │       │   │   │   ├── Continental
│       │       │   │   │   ├── EasterIsland
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── CST6CDT
│       │       │   │   ├── Cuba
│       │       │   │   ├── EET
│       │       │   │   ├── Egypt
│       │       │   │   ├── Eire
│       │       │   │   ├── EST
│       │       │   │   ├── EST5EDT
│       │       │   │   ├── Etc/
│       │       │   │   │   ├── GMT
│       │       │   │   │   ├── GMT+0
│       │       │   │   │   ├── GMT+1
│       │       │   │   │   ├── GMT+10
│       │       │   │   │   ├── GMT+11
│       │       │   │   │   ├── GMT+12
│       │       │   │   │   ├── GMT+2
│       │       │   │   │   ├── GMT+3
│       │       │   │   │   ├── GMT+4
│       │       │   │   │   ├── GMT+5
│       │       │   │   │   ├── GMT+6
│       │       │   │   │   ├── GMT+7
│       │       │   │   │   ├── GMT+8
│       │       │   │   │   ├── GMT+9
│       │       │   │   │   ├── GMT-0
│       │       │   │   │   ├── GMT-1
│       │       │   │   │   ├── GMT-10
│       │       │   │   │   ├── GMT-11
│       │       │   │   │   ├── GMT-12
│       │       │   │   │   ├── GMT-13
│       │       │   │   │   ├── GMT-14
│       │       │   │   │   ├── GMT-2
│       │       │   │   │   ├── GMT-3
│       │       │   │   │   ├── GMT-4
│       │       │   │   │   ├── GMT-5
│       │       │   │   │   ├── GMT-6
│       │       │   │   │   ├── GMT-7
│       │       │   │   │   ├── GMT-8
│       │       │   │   │   ├── GMT-9
│       │       │   │   │   ├── GMT0
│       │       │   │   │   ├── Greenwich
│       │       │   │   │   ├── UCT
│       │       │   │   │   ├── Universal
│       │       │   │   │   ├── UTC
│       │       │   │   │   ├── Zulu
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Europe/
│       │       │   │   │   ├── Amsterdam
│       │       │   │   │   ├── Andorra
│       │       │   │   │   ├── Astrakhan
│       │       │   │   │   ├── Athens
│       │       │   │   │   ├── Belfast
│       │       │   │   │   ├── Belgrade
│       │       │   │   │   ├── Berlin
│       │       │   │   │   ├── Bratislava
│       │       │   │   │   ├── Brussels
│       │       │   │   │   ├── Bucharest
│       │       │   │   │   ├── Budapest
│       │       │   │   │   ├── Busingen
│       │       │   │   │   ├── Chisinau
│       │       │   │   │   ├── Copenhagen
│       │       │   │   │   ├── Dublin
│       │       │   │   │   ├── Gibraltar
│       │       │   │   │   ├── Guernsey
│       │       │   │   │   ├── Helsinki
│       │       │   │   │   ├── Isle_of_Man
│       │       │   │   │   ├── Istanbul
│       │       │   │   │   ├── Jersey
│       │       │   │   │   ├── Kaliningrad
│       │       │   │   │   ├── Kiev
│       │       │   │   │   ├── Kirov
│       │       │   │   │   ├── Kyiv
│       │       │   │   │   ├── Lisbon
│       │       │   │   │   ├── Ljubljana
│       │       │   │   │   ├── London
│       │       │   │   │   ├── Luxembourg
│       │       │   │   │   ├── Madrid
│       │       │   │   │   ├── Malta
│       │       │   │   │   ├── Mariehamn
│       │       │   │   │   ├── Minsk
│       │       │   │   │   ├── Monaco
│       │       │   │   │   ├── Moscow
│       │       │   │   │   ├── Nicosia
│       │       │   │   │   ├── Oslo
│       │       │   │   │   ├── Paris
│       │       │   │   │   ├── Podgorica
│       │       │   │   │   ├── Prague
│       │       │   │   │   ├── Riga
│       │       │   │   │   ├── Rome
│       │       │   │   │   ├── Samara
│       │       │   │   │   ├── San_Marino
│       │       │   │   │   ├── Sarajevo
│       │       │   │   │   ├── Saratov
│       │       │   │   │   ├── Simferopol
│       │       │   │   │   ├── Skopje
│       │       │   │   │   ├── Sofia
│       │       │   │   │   ├── Stockholm
│       │       │   │   │   ├── Tallinn
│       │       │   │   │   ├── Tirane
│       │       │   │   │   ├── Tiraspol
│       │       │   │   │   ├── Ulyanovsk
│       │       │   │   │   ├── Uzhgorod
│       │       │   │   │   ├── Vaduz
│       │       │   │   │   ├── Vatican
│       │       │   │   │   ├── Vienna
│       │       │   │   │   ├── Vilnius
│       │       │   │   │   ├── Volgograd
│       │       │   │   │   ├── Warsaw
│       │       │   │   │   ├── Zagreb
│       │       │   │   │   ├── Zaporozhye
│       │       │   │   │   ├── Zurich
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Factory
│       │       │   │   ├── GB
│       │       │   │   ├── GB-Eire
│       │       │   │   ├── GMT
│       │       │   │   ├── GMT+0
│       │       │   │   ├── GMT-0
│       │       │   │   ├── GMT0
│       │       │   │   ├── Greenwich
│       │       │   │   ├── Hongkong
│       │       │   │   ├── HST
│       │       │   │   ├── Iceland
│       │       │   │   ├── Indian/
│       │       │   │   │   ├── Antananarivo
│       │       │   │   │   ├── Chagos
│       │       │   │   │   ├── Christmas
│       │       │   │   │   ├── Cocos
│       │       │   │   │   ├── Comoro
│       │       │   │   │   ├── Kerguelen
│       │       │   │   │   ├── Mahe
│       │       │   │   │   ├── Maldives
│       │       │   │   │   ├── Mauritius
│       │       │   │   │   ├── Mayotte
│       │       │   │   │   ├── Reunion
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Iran
│       │       │   │   ├── iso3166.tab
│       │       │   │   ├── Israel
│       │       │   │   ├── Jamaica
│       │       │   │   ├── Japan
│       │       │   │   ├── Kwajalein
│       │       │   │   ├── leapseconds
│       │       │   │   ├── Libya
│       │       │   │   ├── MET
│       │       │   │   ├── Mexico/
│       │       │   │   │   ├── BajaNorte
│       │       │   │   │   ├── BajaSur
│       │       │   │   │   ├── General
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── MST
│       │       │   │   ├── MST7MDT
│       │       │   │   ├── Navajo
│       │       │   │   ├── NZ
│       │       │   │   ├── NZ-CHAT
│       │       │   │   ├── Pacific/
│       │       │   │   │   ├── Apia
│       │       │   │   │   ├── Auckland
│       │       │   │   │   ├── Bougainville
│       │       │   │   │   ├── Chatham
│       │       │   │   │   ├── Chuuk
│       │       │   │   │   ├── Easter
│       │       │   │   │   ├── Efate
│       │       │   │   │   ├── Enderbury
│       │       │   │   │   ├── Fakaofo
│       │       │   │   │   ├── Fiji
│       │       │   │   │   ├── Funafuti
│       │       │   │   │   ├── Galapagos
│       │       │   │   │   ├── Gambier
│       │       │   │   │   ├── Guadalcanal
│       │       │   │   │   ├── Guam
│       │       │   │   │   ├── Honolulu
│       │       │   │   │   ├── Johnston
│       │       │   │   │   ├── Kanton
│       │       │   │   │   ├── Kiritimati
│       │       │   │   │   ├── Kosrae
│       │       │   │   │   ├── Kwajalein
│       │       │   │   │   ├── Majuro
│       │       │   │   │   ├── Marquesas
│       │       │   │   │   ├── Midway
│       │       │   │   │   ├── Nauru
│       │       │   │   │   ├── Niue
│       │       │   │   │   ├── Norfolk
│       │       │   │   │   ├── Noumea
│       │       │   │   │   ├── Pago_Pago
│       │       │   │   │   ├── Palau
│       │       │   │   │   ├── Pitcairn
│       │       │   │   │   ├── Pohnpei
│       │       │   │   │   ├── Ponape
│       │       │   │   │   ├── Port_Moresby
│       │       │   │   │   ├── Rarotonga
│       │       │   │   │   ├── Saipan
│       │       │   │   │   ├── Samoa
│       │       │   │   │   ├── Tahiti
│       │       │   │   │   ├── Tarawa
│       │       │   │   │   ├── Tongatapu
│       │       │   │   │   ├── Truk
│       │       │   │   │   ├── Wake
│       │       │   │   │   ├── Wallis
│       │       │   │   │   ├── Yap
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── Poland
│       │       │   │   ├── Portugal
│       │       │   │   ├── PRC
│       │       │   │   ├── PST8PDT
│       │       │   │   ├── ROC
│       │       │   │   ├── ROK
│       │       │   │   ├── Singapore
│       │       │   │   ├── Turkey
│       │       │   │   ├── tzdata.zi
│       │       │   │   ├── UCT
│       │       │   │   ├── Universal
│       │       │   │   ├── US/
│       │       │   │   │   ├── Alaska
│       │       │   │   │   ├── Aleutian
│       │       │   │   │   ├── Arizona
│       │       │   │   │   ├── Central
│       │       │   │   │   ├── East-Indiana
│       │       │   │   │   ├── Eastern
│       │       │   │   │   ├── Hawaii
│       │       │   │   │   ├── Indiana-Starke
│       │       │   │   │   ├── Michigan
│       │       │   │   │   ├── Mountain
│       │       │   │   │   ├── Pacific
│       │       │   │   │   ├── Samoa
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── UTC
│       │       │   │   ├── W-SU
│       │       │   │   ├── WET
│       │       │   │   ├── zone.tab
│       │       │   │   ├── zone1970.tab
│       │       │   │   ├── zonenow.tab
│       │       │   │   ├── Zulu
│       │       │   │   └── __init__.py
│       │       │   ├── zones
│       │       │   └── __init__.py
│       │       ├── tzdata-2025.2.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   ├── LICENSE
│       │       │   │   └── licenses/
│       │       │   │       └── LICENSE_APACHE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── urllib3/
│       │       │   ├── connection.py
│       │       │   ├── connectionpool.py
│       │       │   ├── contrib/
│       │       │   │   ├── emscripten/
│       │       │   │   │   ├── connection.py
│       │       │   │   │   ├── emscripten_fetch_worker.js
│       │       │   │   │   ├── fetch.py
│       │       │   │   │   ├── request.py
│       │       │   │   │   ├── response.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── pyopenssl.py
│       │       │   │   ├── socks.py
│       │       │   │   └── __init__.py
│       │       │   ├── exceptions.py
│       │       │   ├── fields.py
│       │       │   ├── filepost.py
│       │       │   ├── http2/
│       │       │   │   ├── connection.py
│       │       │   │   ├── probe.py
│       │       │   │   └── __init__.py
│       │       │   ├── poolmanager.py
│       │       │   ├── py.typed
│       │       │   ├── response.py
│       │       │   ├── util/
│       │       │   │   ├── connection.py
│       │       │   │   ├── proxy.py
│       │       │   │   ├── request.py
│       │       │   │   ├── response.py
│       │       │   │   ├── retry.py
│       │       │   │   ├── ssltransport.py
│       │       │   │   ├── ssl_.py
│       │       │   │   ├── ssl_match_hostname.py
│       │       │   │   ├── timeout.py
│       │       │   │   ├── url.py
│       │       │   │   ├── util.py
│       │       │   │   ├── wait.py
│       │       │   │   └── __init__.py
│       │       │   ├── _base_connection.py
│       │       │   ├── _collections.py
│       │       │   ├── _request_methods.py
│       │       │   ├── _version.py
│       │       │   └── __init__.py
│       │       ├── urllib3-2.4.0.dist-info/
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.txt
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── uvicorn/
│       │       │   ├── config.py
│       │       │   ├── importer.py
│       │       │   ├── lifespan/
│       │       │   │   ├── off.py
│       │       │   │   ├── on.py
│       │       │   │   └── __init__.py
│       │       │   ├── logging.py
│       │       │   ├── loops/
│       │       │   │   ├── asyncio.py
│       │       │   │   ├── auto.py
│       │       │   │   ├── uvloop.py
│       │       │   │   └── __init__.py
│       │       │   ├── main.py
│       │       │   ├── middleware/
│       │       │   │   ├── asgi2.py
│       │       │   │   ├── message_logger.py
│       │       │   │   ├── proxy_headers.py
│       │       │   │   ├── wsgi.py
│       │       │   │   └── __init__.py
│       │       │   ├── protocols/
│       │       │   │   ├── http/
│       │       │   │   │   ├── auto.py
│       │       │   │   │   ├── flow_control.py
│       │       │   │   │   ├── h11_impl.py
│       │       │   │   │   ├── httptools_impl.py
│       │       │   │   │   └── __init__.py
│       │       │   │   ├── utils.py
│       │       │   │   ├── websockets/
│       │       │   │   │   ├── auto.py
│       │       │   │   │   ├── websockets_impl.py
│       │       │   │   │   ├── wsproto_impl.py
│       │       │   │   │   └── __init__.py
│       │       │   │   └── __init__.py
│       │       │   ├── py.typed
│       │       │   ├── server.py
│       │       │   ├── supervisors/
│       │       │   │   ├── basereload.py
│       │       │   │   ├── multiprocess.py
│       │       │   │   ├── statreload.py
│       │       │   │   ├── watchfilesreload.py
│       │       │   │   └── __init__.py
│       │       │   ├── workers.py
│       │       │   ├── _subprocess.py
│       │       │   ├── _types.py
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── uvicorn-0.34.3.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE.md
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── REQUESTED
│       │       │   └── WHEEL
│       │       ├── watchfiles/
│       │       │   ├── cli.py
│       │       │   ├── filters.py
│       │       │   ├── main.py
│       │       │   ├── py.typed
│       │       │   ├── run.py
│       │       │   ├── version.py
│       │       │   ├── _rust_notify.cp312-win_amd64.pyd
│       │       │   ├── _rust_notify.pyi
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── watchfiles-1.1.0.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── licenses/
│       │       │   │   └── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   └── WHEEL
│       │       ├── websockets/
│       │       │   ├── asyncio/
│       │       │   │   ├── async_timeout.py
│       │       │   │   ├── client.py
│       │       │   │   ├── compatibility.py
│       │       │   │   ├── connection.py
│       │       │   │   ├── messages.py
│       │       │   │   ├── router.py
│       │       │   │   ├── server.py
│       │       │   │   └── __init__.py
│       │       │   ├── auth.py
│       │       │   ├── cli.py
│       │       │   ├── client.py
│       │       │   ├── connection.py
│       │       │   ├── datastructures.py
│       │       │   ├── exceptions.py
│       │       │   ├── extensions/
│       │       │   │   ├── base.py
│       │       │   │   ├── permessage_deflate.py
│       │       │   │   └── __init__.py
│       │       │   ├── frames.py
│       │       │   ├── headers.py
│       │       │   ├── http.py
│       │       │   ├── http11.py
│       │       │   ├── imports.py
│       │       │   ├── legacy/
│       │       │   │   ├── auth.py
│       │       │   │   ├── client.py
│       │       │   │   ├── exceptions.py
│       │       │   │   ├── framing.py
│       │       │   │   ├── handshake.py
│       │       │   │   ├── http.py
│       │       │   │   ├── protocol.py
│       │       │   │   ├── server.py
│       │       │   │   └── __init__.py
│       │       │   ├── protocol.py
│       │       │   ├── py.typed
│       │       │   ├── server.py
│       │       │   ├── speedups.c
│       │       │   ├── speedups.cp312-win_amd64.pyd
│       │       │   ├── speedups.pyi
│       │       │   ├── streams.py
│       │       │   ├── sync/
│       │       │   │   ├── client.py
│       │       │   │   ├── connection.py
│       │       │   │   ├── messages.py
│       │       │   │   ├── router.py
│       │       │   │   ├── server.py
│       │       │   │   ├── utils.py
│       │       │   │   └── __init__.py
│       │       │   ├── typing.py
│       │       │   ├── uri.py
│       │       │   ├── utils.py
│       │       │   ├── version.py
│       │       │   ├── __init__.py
│       │       │   └── __main__.py
│       │       ├── websockets-15.0.1.dist-info/
│       │       │   ├── entry_points.txt
│       │       │   ├── INSTALLER
│       │       │   ├── LICENSE
│       │       │   ├── METADATA
│       │       │   ├── RECORD
│       │       │   ├── top_level.txt
│       │       │   └── WHEEL
│       │       ├── yaml/
│       │       │   ├── composer.py
│       │       │   ├── constructor.py
│       │       │   ├── cyaml.py
│       │       │   ├── dumper.py
│       │       │   ├── emitter.py
│       │       │   ├── error.py
│       │       │   ├── events.py
│       │       │   ├── loader.py
│       │       │   ├── nodes.py
│       │       │   ├── parser.py
│       │       │   ├── reader.py
│       │       │   ├── representer.py
│       │       │   ├── resolver.py
│       │       │   ├── scanner.py
│       │       │   ├── serializer.py
│       │       │   ├── tokens.py
│       │       │   ├── _yaml.cp312-win_amd64.pyd
│       │       │   └── __init__.py
│       │       └── _yaml/
│       │           └── __init__.py
│       ├── pyvenv.cfg
│       └── Scripts/
│           ├── activate
│           ├── activate.bat
│           ├── Activate.ps1
│           ├── deactivate.bat
│           ├── dotenv.exe
│           ├── email_validator.exe
│           ├── f2py.exe
│           ├── fastapi.exe
│           ├── httpx.exe
│           ├── normalizer.exe
│           ├── numpy-config.exe
│           ├── pip.exe
│           ├── pip3.12.exe
│           ├── pip3.exe
│           ├── python.exe
│           ├── pythonw.exe
│           ├── tldextract.exe
│           ├── uvicorn.exe
│           ├── watchfiles.exe
│           └── websockets.exe
├── frontend/
│   ├── package-lock.json
│   ├── package.json
│   ├── public/
│   │   ├── assets/
│   │   │   └── logo.png
│   │   ├── favicon.ico
│   │   ├── index.html
│   │   ├── manifest.json
│   │   └── robots.txt
│   ├── README.md
│   └── src/
│       ├── App.css
│       ├── App.js
│       ├── App.test.js
│       ├── components/
│       │   └── SeverityBadge.js
│       ├── hooks/
│       ├── index.css
│       ├── index.js
│       ├── layout/
│       │   ├── Layout.js
│       │   └── TopNav.js
│       ├── logo.svg
│       ├── pages/
│       │   ├── DarkWebScanner.js
│       │   ├── LinkScanner.js
│       │   ├── PhishingDetector.js
│       │   ├── Remediation.js
│       │   ├── ThreatScanner.js
│       │   └── VulnerabilityScanner.js
│       ├── reportWebVitals.js
│       ├── services/
│       │   ├── darkWebScanner.js
│       │   ├── linkScanner.js
│       │   ├── phishingDetector.js
│       │   ├── threatScanner.js
│       │   └── vulnerabilityScanner.js
│       ├── setupTests.js
│       ├── styles/
│       └── utils/
├── image.png
└── README.md

```


