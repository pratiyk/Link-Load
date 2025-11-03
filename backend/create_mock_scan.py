"""
Create mock scan data for demonstration purposes.
Run this script to populate the database with a sample scan and vulnerabilities.
"""
import sys
import uuid
from datetime import datetime, timedelta
from app.database.supabase_client import supabase

def create_mock_scan():
    """Create a comprehensive mock scan with vulnerabilities."""
    
    # Generate a unique scan ID
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    
    # Mock scan data
    scan_data = {
        "scan_id": scan_id,
        "user_id": "demo_user",
        "target_url": "https://demo.testfire.net",
        "scan_types": ["owasp", "nuclei", "wapiti"],
        "status": "completed",
        "progress": 100,
        "current_stage": "Completed",
        "started_at": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
        "completed_at": datetime.utcnow().isoformat(),
        "risk_score": 7.8,
        "risk_level": "High",
        "critical_count": 2,
        "high_count": 5,
        "medium_count": 8,
        "low_count": 12,
        "mitre_mapping": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "confidence": 0.92,
                "method": "ml_ensemble"
            },
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "confidence": 0.88,
                "method": "ml_ensemble"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "confidence": 0.85,
                "method": "pattern_match"
            },
            {
                "id": "T1557",
                "name": "Adversary-in-the-Middle",
                "tactic": "Collection",
                "confidence": 0.79,
                "method": "ml_ensemble"
            }
        ],
        "ai_analysis": [
            {
                "title": "Critical SQL Injection Vulnerability",
                "description": "Multiple SQL injection points detected in the application. These vulnerabilities allow attackers to manipulate database queries and potentially access sensitive data.",
                "recommendations": [
                    "Implement parameterized queries or prepared statements",
                    "Use ORM frameworks with built-in SQL injection protection",
                    "Apply input validation and sanitization"
                ],
                "remediation_priority": "critical"
            },
            {
                "title": "Cross-Site Scripting (XSS) Vulnerabilities",
                "description": "Reflected and stored XSS vulnerabilities found in user input fields. Attackers can inject malicious scripts to steal session tokens or perform actions on behalf of users.",
                "recommendations": [
                    "Implement Content Security Policy (CSP) headers",
                    "Use context-aware output encoding",
                    "Validate and sanitize all user inputs"
                ],
                "remediation_priority": "high"
            },
            {
                "title": "Weak Authentication Mechanisms",
                "description": "Authentication system lacks proper security controls including MFA, password complexity requirements, and account lockout mechanisms.",
                "recommendations": [
                    "Implement Multi-Factor Authentication (MFA)",
                    "Enforce strong password policies",
                    "Add rate limiting and account lockout after failed attempts"
                ],
                "remediation_priority": "high"
            }
        ],
        "remediation_strategies": {
            "priority_matrix": {
                "critical": [
                    {"title": "SQL Injection in login form", "estimated_hours": 8},
                    {"title": "Command injection in file upload", "estimated_hours": 12}
                ],
                "high": [
                    {"title": "XSS in search functionality", "estimated_hours": 6},
                    {"title": "Missing authentication on admin endpoints", "estimated_hours": 4},
                    {"title": "Weak password policy", "estimated_hours": 3}
                ],
                "medium": [
                    {"title": "Missing security headers", "estimated_hours": 2},
                    {"title": "Information disclosure in error messages", "estimated_hours": 3}
                ]
            },
            "timeline": {
                "immediate_action": {
                    "description": "Critical vulnerabilities requiring immediate attention",
                    "items": [
                        {"title": "Patch SQL injection vulnerabilities", "estimated_hours": 8},
                        {"title": "Deploy WAF rules", "estimated_hours": 4}
                    ]
                },
                "short_term": {
                    "description": "High priority fixes within 1-2 weeks",
                    "items": [
                        {"title": "Fix XSS vulnerabilities", "estimated_hours": 6},
                        {"title": "Implement MFA", "estimated_hours": 16}
                    ]
                },
                "medium_term": {
                    "description": "Medium priority improvements within 1-2 months",
                    "items": [
                        {"title": "Add security headers", "estimated_hours": 2},
                        {"title": "Implement rate limiting", "estimated_hours": 8}
                    ]
                }
            },
            "cost_benefit": {
                "total_remediation_cost": 35000,
                "potential_breach_cost": 450000,
                "net_benefit": 415000,
                "roi_percentage": 1186,
                "recommendation": "IMMEDIATE FIX",
                "effort_hours": 120
            },
            "recommendations": [
                {
                    "priority": "critical",
                    "category": "Code Fix",
                    "title": "Implement Parameterized Queries",
                    "description": "Replace all dynamic SQL queries with parameterized queries to prevent SQL injection attacks",
                    "action_items": [
                        "Audit all database query code",
                        "Replace string concatenation with prepared statements",
                        "Add code review checklist for SQL injection prevention"
                    ],
                    "estimated_effort": "1-2 weeks"
                },
                {
                    "priority": "high",
                    "category": "Input Validation",
                    "title": "Implement Output Encoding",
                    "description": "Add context-aware output encoding to prevent XSS attacks",
                    "action_items": [
                        "Use OWASP Java Encoder or similar library",
                        "Implement CSP headers",
                        "Add XSS protection middleware"
                    ],
                    "estimated_effort": "1 week"
                },
                {
                    "priority": "high",
                    "category": "Authentication",
                    "title": "Deploy Multi-Factor Authentication",
                    "description": "Implement MFA for all user accounts to prevent unauthorized access",
                    "action_items": [
                        "Choose MFA provider (TOTP, SMS, or hardware tokens)",
                        "Integrate MFA into authentication flow",
                        "Train users on MFA usage"
                    ],
                    "estimated_effort": "2-3 weeks"
                }
            ]
        }
    }
    
    # Mock vulnerabilities
    vulnerabilities = [
        {
            "title": "SQL Injection in Login Form",
            "name": "SQL Injection",
            "description": "The login form is vulnerable to SQL injection attacks. Attackers can bypass authentication by injecting SQL commands into the username or password fields.",
            "severity": "critical",
            "confidence": "high",
            "cvss_score": 9.8,
            "url": "https://demo.testfire.net/login",
            "path": "/login",
            "location": "/login",
            "parameter": "username",
            "evidence": "' OR '1'='1",
            "solution": "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
            "recommendation": "Implement parameterized queries using prepared statements. Add input validation with whitelist approach.",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
            "tags": ["sql-injection", "authentication", "critical"],
            "cwe_id": "CWE-89"
        },
        {
            "title": "Command Injection in File Upload",
            "name": "Command Injection",
            "description": "The file upload functionality does not properly validate file names, allowing attackers to execute arbitrary commands on the server.",
            "severity": "critical",
            "confidence": "high",
            "cvss_score": 9.1,
            "url": "https://demo.testfire.net/upload",
            "path": "/upload",
            "location": "/upload",
            "parameter": "filename",
            "evidence": "; cat /etc/passwd",
            "solution": "Sanitize file names and use a whitelist of allowed characters. Never pass user input directly to system commands.",
            "recommendation": "Implement strict file name validation and use a secure file storage mechanism.",
            "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
            "tags": ["command-injection", "file-upload", "critical"],
            "cwe_id": "CWE-78"
        },
        {
            "title": "Reflected XSS in Search",
            "name": "Cross-Site Scripting (XSS)",
            "description": "The search functionality reflects user input without proper encoding, allowing attackers to inject malicious JavaScript code.",
            "severity": "high",
            "confidence": "high",
            "cvss_score": 7.4,
            "url": "https://demo.testfire.net/search?q=<script>alert(1)</script>",
            "path": "/search",
            "location": "/search",
            "parameter": "q",
            "evidence": "<script>alert(document.cookie)</script>",
            "solution": "Implement proper output encoding and Content Security Policy headers.",
            "recommendation": "Use context-aware output encoding for all user inputs. Deploy CSP headers.",
            "references": ["https://owasp.org/www-community/attacks/xss/"],
            "tags": ["xss", "reflected", "high"],
            "cwe_id": "CWE-79"
        },
        {
            "title": "Stored XSS in Comment Section",
            "name": "Cross-Site Scripting (XSS)",
            "description": "User comments are stored without sanitization and displayed without encoding, allowing persistent XSS attacks.",
            "severity": "high",
            "confidence": "high",
            "cvss_score": 7.1,
            "url": "https://demo.testfire.net/comments",
            "path": "/comments",
            "location": "/comments",
            "parameter": "comment",
            "evidence": "<img src=x onerror=alert(1)>",
            "solution": "Sanitize user input before storage and encode output when displaying.",
            "recommendation": "Implement input sanitization and output encoding. Use DOMPurify or similar library.",
            "references": ["https://owasp.org/www-community/attacks/xss/"],
            "tags": ["xss", "stored", "high"],
            "cwe_id": "CWE-79"
        },
        {
            "title": "Missing Authentication on Admin Panel",
            "name": "Broken Access Control",
            "description": "The admin panel (/admin) is accessible without authentication, exposing sensitive administrative functions.",
            "severity": "high",
            "confidence": "high",
            "cvss_score": 8.2,
            "url": "https://demo.testfire.net/admin",
            "path": "/admin",
            "location": "/admin",
            "parameter": "",
            "evidence": "Direct access to /admin without authentication",
            "solution": "Implement proper authentication and authorization checks for all admin endpoints.",
            "recommendation": "Add authentication middleware to all admin routes. Implement role-based access control.",
            "references": ["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
            "tags": ["authentication", "access-control", "high"],
            "cwe_id": "CWE-306"
        },
        {
            "title": "Weak Password Policy",
            "name": "Insufficient Password Requirements",
            "description": "The application accepts weak passwords without complexity requirements or length restrictions.",
            "severity": "high",
            "confidence": "medium",
            "cvss_score": 6.5,
            "url": "https://demo.testfire.net/register",
            "path": "/register",
            "location": "/register",
            "parameter": "password",
            "evidence": "Accepts passwords like '123456' and 'password'",
            "solution": "Enforce strong password policies including minimum length, complexity requirements, and password history.",
            "recommendation": "Implement NIST password guidelines. Require minimum 12 characters with complexity.",
            "references": ["https://pages.nist.gov/800-63-3/sp800-63b.html"],
            "tags": ["authentication", "password", "high"],
            "cwe_id": "CWE-521"
        },
        {
            "title": "Missing Security Headers",
            "name": "Security Misconfiguration",
            "description": "The application is missing critical security headers like CSP, X-Frame-Options, and HSTS.",
            "severity": "medium",
            "confidence": "high",
            "cvss_score": 5.3,
            "url": "https://demo.testfire.net",
            "path": "/",
            "location": "Response Headers",
            "parameter": "",
            "evidence": "Missing: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security",
            "solution": "Add security headers to all HTTP responses.",
            "recommendation": "Configure web server or application to send security headers. Use helmet.js for Node.js or similar.",
            "references": ["https://owasp.org/www-project-secure-headers/"],
            "tags": ["security-headers", "misconfiguration", "medium"],
            "cwe_id": "CWE-16"
        },
        {
            "title": "Information Disclosure in Error Messages",
            "name": "Information Exposure",
            "description": "Detailed error messages expose sensitive information about the application structure and database.",
            "severity": "medium",
            "confidence": "high",
            "cvss_score": 5.0,
            "url": "https://demo.testfire.net/api/users/999999",
            "path": "/api/users/999999",
            "location": "/api/users/*",
            "parameter": "",
            "evidence": "SQL error: Table 'db.users' doesn't exist at line 42 in UserController.php",
            "solution": "Implement generic error messages for users and log detailed errors server-side.",
            "recommendation": "Use custom error pages. Log detailed errors but show generic messages to users.",
            "references": ["https://owasp.org/www-community/Improper_Error_Handling"],
            "tags": ["information-disclosure", "error-handling", "medium"],
            "cwe_id": "CWE-209"
        },
        {
            "title": "CSRF Token Not Validated",
            "name": "Cross-Site Request Forgery",
            "description": "State-changing operations do not validate CSRF tokens, allowing attackers to perform actions on behalf of authenticated users.",
            "severity": "medium",
            "confidence": "medium",
            "cvss_score": 6.1,
            "url": "https://demo.testfire.net/profile/update",
            "path": "/profile/update",
            "location": "/profile/update",
            "parameter": "",
            "evidence": "POST request accepted without CSRF token validation",
            "solution": "Implement CSRF protection using synchronized tokens or SameSite cookies.",
            "recommendation": "Add CSRF tokens to all forms. Use anti-CSRF middleware.",
            "references": ["https://owasp.org/www-community/attacks/csrf"],
            "tags": ["csrf", "session", "medium"],
            "cwe_id": "CWE-352"
        },
        {
            "title": "Directory Listing Enabled",
            "name": "Directory Indexing",
            "description": "Directory listing is enabled, exposing file structure and potentially sensitive files.",
            "severity": "low",
            "confidence": "high",
            "cvss_score": 3.7,
            "url": "https://demo.testfire.net/uploads/",
            "path": "/uploads/",
            "location": "/uploads/",
            "parameter": "",
            "evidence": "Index of /uploads/ showing all uploaded files",
            "solution": "Disable directory listing in web server configuration.",
            "recommendation": "Add index.html to directories or configure server to deny directory listings.",
            "references": ["https://owasp.org/www-community/vulnerabilities/Directory_indexing"],
            "tags": ["directory-listing", "information-disclosure", "low"],
            "cwe_id": "CWE-548"
        },
        {
            "title": "Clickjacking Vulnerability",
            "name": "Clickjacking",
            "description": "Missing X-Frame-Options header allows the page to be embedded in iframes, enabling clickjacking attacks.",
            "severity": "low",
            "confidence": "high",
            "cvss_score": 4.3,
            "url": "https://demo.testfire.net",
            "path": "/",
            "location": "Response Headers",
            "parameter": "",
            "evidence": "X-Frame-Options header not present",
            "solution": "Add X-Frame-Options: DENY or SAMEORIGIN header.",
            "recommendation": "Configure web server to send X-Frame-Options header.",
            "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
            "tags": ["clickjacking", "framing", "low"],
            "cwe_id": "CWE-1021"
        }
    ]
    
    try:
        # Create scan record
        print(f"Creating mock scan with ID: {scan_id}")
        supabase.create_scan(scan_data)
        print("✓ Scan record created")
        
        # Insert vulnerabilities
        print(f"Inserting {len(vulnerabilities)} vulnerabilities...")
        count = supabase.insert_vulnerabilities(scan_id, vulnerabilities)
        print(f"✓ {count} vulnerabilities inserted")
        
        print("\n" + "="*60)
        print("Mock scan created successfully!")
        print("="*60)
        print(f"Scan ID: {scan_id}")
        print(f"Target URL: {scan_data['target_url']}")
        print(f"Status: {scan_data['status']}")
        print(f"Risk Score: {scan_data['risk_score']}/10")
        print(f"Risk Level: {scan_data['risk_level']}")
        print(f"Total Vulnerabilities: {count}")
        print(f"  - Critical: {scan_data['critical_count']}")
        print(f"  - High: {scan_data['high_count']}")
        print(f"  - Medium: {scan_data['medium_count']}")
        print(f"  - Low: {scan_data['low_count']}")
        print("\nView results at:")
        print(f"http://localhost:3000/scan/{scan_id}")
        print("="*60)
        
        return scan_id
        
    except Exception as e:
        print(f"Error creating mock scan: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    print("Creating mock scan data for demonstration...\n")
    scan_id = create_mock_scan()
    
    if scan_id:
        sys.exit(0)
    else:
        sys.exit(1)
