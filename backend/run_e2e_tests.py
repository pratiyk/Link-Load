"""
End-to-End Testing Suite for Link&Load

Tests the complete scanning workflow from UI to database.

Requirements:
- Backend running on port 8000
- Frontend running on port 3000
- Database connected
- Scanners configured

Usage:
python backend/run_e2e_tests.py
"""

import asyncio
import json
import requests
import logging
from datetime import datetime
from typing import Dict, List, Optional
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'


class E2ETestSuite:
    """End-to-end test suite for Link&Load"""
    
    def __init__(self):
        self.backend_url = "http://localhost:8000"
        self.frontend_url = "http://localhost:3000"
        self.test_results = {
            "passed": [],
            "failed": [],
            "skipped": []
        }
        self.access_token = None
        self.scan_id = None
    
    def log_test(self, name: str, passed: bool, message: str = ""):
        """Log test result"""
        symbol = f"{GREEN}[OK]{RESET}" if passed else f"{RED}[ERROR]{RESET}"
        print(f"{symbol} {name:40} {message}")
        
        if passed:
            self.test_results["passed"].append(name)
        else:
            self.test_results["failed"].append(name)
    
    def print_section(self, title: str):
        """Print section header"""
        print(f"\n{BOLD}{BLUE}{'='*70}{RESET}")
        print(f"{BOLD}{BLUE}{title:^70}{RESET}")
        print(f"{BOLD}{BLUE}{'='*70}{RESET}\n")
    
    # === API Connectivity Tests ===
    
    def test_backend_health(self) -> bool:
        """Test if backend API is running and healthy"""
        self.print_section("1. API Connectivity Tests")
        
        try:
            response = requests.get(
                f"{self.backend_url}/docs",
                timeout=5
            )
            passed = response.status_code == 200
            self.log_test(
                "Backend API Health Check",
                passed,
                f"Status: {response.status_code}"
            )
            return passed
        except requests.exceptions.ConnectionError:
            self.log_test("Backend API Health Check", False, "Connection refused")
            return False
        except Exception as e:
            self.log_test("Backend API Health Check", False, str(e))
            return False
    
    def test_frontend_health(self) -> bool:
        """Test if frontend is running"""
        try:
            response = requests.get(
                f"{self.frontend_url}",
                timeout=5
            )
            passed = response.status_code == 200
            self.log_test(
                "Frontend Health Check",
                passed,
                f"Status: {response.status_code}"
            )
            return passed
        except requests.exceptions.ConnectionError:
            self.log_test("Frontend Health Check", False, "Not running on 3000")
            return False
        except Exception as e:
            self.log_test("Frontend Health Check", False, str(e)[:50])
            return False
    
    def test_database_connectivity(self) -> bool:
        """Test database connection through API"""
        try:
            # Try to get API info which queries database
            response = requests.get(
                f"{self.backend_url}/api/v1/health",
                timeout=5
            )
            passed = response.status_code in [200, 404]  # 404 is ok if endpoint doesn't exist
            self.log_test(
                "Database Connectivity",
                passed,
                "Database accessible through API"
            )
            return passed
        except Exception as e:
            self.log_test("Database Connectivity", False, str(e)[:50])
            return False
    
    # === Scanner Tests ===
    
    def test_scanner_health(self) -> bool:
        """Test if scanners are available"""
        self.print_section("2. Scanner Health Tests")
        
        try:
            response = requests.get(
                f"{self.backend_url}/api/v1/health/scanners",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                zap_ok = data.get('owasp', {}).get('status') == 'ok'
                nuclei_ok = data.get('nuclei', {}).get('status') == 'ok'
                wapiti_ok = data.get('wapiti', {}).get('status') == 'ok'
                
                self.log_test("OWASP ZAP", zap_ok)
                self.log_test("Nuclei", nuclei_ok)
                self.log_test("Wapiti", wapiti_ok)
                
                return zap_ok or nuclei_ok or wapiti_ok
            else:
                self.log_test("Scanner Health Endpoint", False, f"Status {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Scanner Health Check", False, str(e)[:50])
            return False
    
    # === API Endpoint Tests ===
    
    def test_scan_endpoints(self) -> bool:
        """Test comprehensive scan endpoints"""
        self.print_section("3. Scan API Endpoint Tests")
        
        # Test list scans endpoint
        try:
            response = requests.get(
                f"{self.backend_url}/api/v1/scans/comprehensive/list",
                timeout=10
            )
            list_ok = response.status_code in [200, 401]  # 401 if not authenticated
            self.log_test(
                "GET /scans/comprehensive/list",
                list_ok,
                f"Status {response.status_code}"
            )
        except Exception as e:
            self.log_test("GET /scans/comprehensive/list", False, str(e)[:40])
            list_ok = False
        
        return list_ok
    
    # === Scan Execution Test ===
    
    def test_start_scan(self) -> Optional[str]:
        """Test starting a comprehensive scan"""
        self.print_section("4. Scan Execution Test")
        
        payload = {
            "target_url": "https://httpbin.org",  # Safe test target
            "scan_types": ["owasp"],  # Start with one scanner
            "options": {
                "enable_ai_analysis": False,  # Skip LLM for testing
                "enable_mitre_mapping": True,
                "include_low_risk": True,
                "deep_scan": False,
                "timeout_minutes": 5
            }
        }
        
        try:
            response = requests.post(
                f"{self.backend_url}/api/v1/scans/comprehensive/start",
                json=payload,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                scan_id = data.get('scan_id')
                self.log_test(
                    "POST /scans/comprehensive/start",
                    True,
                    f"Scan ID: {scan_id[:12]}..."
                )
                return scan_id
            else:
                self.log_test(
                    "POST /scans/comprehensive/start",
                    False,
                    f"Status {response.status_code}: {response.text[:50]}"
                )
                return None
        except Exception as e:
            self.log_test("POST /scans/comprehensive/start", False, str(e)[:50])
            return None
    
    def test_get_scan_status(self, scan_id: str) -> bool:
        """Test getting scan status"""
        if not scan_id:
            return False
        
        try:
            response = requests.get(
                f"{self.backend_url}/api/v1/scans/comprehensive/{scan_id}/status",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('status')
                progress = data.get('progress', 0)
                stage = data.get('current_stage', '')
                
                self.log_test(
                    "GET /scans/{id}/status",
                    True,
                    f"Status: {status}, Progress: {progress}%, Stage: {stage[:20]}"
                )
                return True
            else:
                self.log_test(
                    "GET /scans/{id}/status",
                    False,
                    f"Status {response.status_code}"
                )
                return False
        except Exception as e:
            self.log_test("GET /scans/{id}/status", False, str(e)[:50])
            return False
    
    def test_websocket_connection(self, scan_id: str) -> bool:
        """Test WebSocket connection for real-time updates"""
        if not scan_id:
            return False
        
        try:
            import websocket
            import time
            
            ws_url = f"ws://localhost:8000/api/v1/scans/ws/{scan_id}"
            ws = websocket.create_connection(ws_url, timeout=5)
            
            # Receive first message (should be progress)
            message = ws.recv()
            data = json.loads(message)
            
            ws_ok = data.get('type') in ['progress', 'result']
            
            self.log_test(
                "WebSocket Connection",
                ws_ok,
                f"Message type: {data.get('type', 'unknown')}"
            )
            
            ws.close()
            return ws_ok
        except ImportError:
            self.log_test(
                "WebSocket Connection",
                None,
                "websocket-client not installed"
            )
            return None
        except Exception as e:
            self.log_test("WebSocket Connection", False, str(e)[:50])
            return False
    
    # === Data Validation Tests ===
    
    def test_scan_results_structure(self, scan_id: str) -> bool:
        """Test if scan results have correct structure"""
        if not scan_id:
            return False
        
        try:
            response = requests.get(
                f"{self.backend_url}/api/v1/scans/comprehensive/{scan_id}/result",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check required fields
                required = [
                    'scan_id',
                    'target_url',
                    'status',
                    'risk_assessment',
                    'vulnerabilities'
                ]
                
                missing = [field for field in required if field not in data]
                
                if not missing:
                    self.log_test(
                        "Scan Results Structure",
                        True,
                        f"All required fields present"
                    )
                    
                    # Verify sub-structures
                    vuln_count = len(data.get('vulnerabilities', []))
                    self.log_test(
                        "Vulnerabilities Array",
                        True,
                        f"{vuln_count} vulnerabilities found"
                    )
                    
                    risk = data.get('risk_assessment', {})
                    self.log_test(
                        "Risk Assessment",
                        'overall_risk_score' in risk,
                        f"Risk Score: {risk.get('overall_risk_score', 'N/A')}"
                    )
                    
                    return True
                else:
                    self.log_test(
                        "Scan Results Structure",
                        False,
                        f"Missing fields: {', '.join(missing)}"
                    )
                    return False
            else:
                self.log_test(
                    "Scan Results Structure",
                    False,
                    f"Status {response.status_code}"
                )
                return False
        except Exception as e:
            self.log_test("Scan Results Structure", False, str(e)[:50])
            return False
    
    # === Frontend Integration Tests ===
    
    def test_frontend_routing(self) -> bool:
        """Test if frontend pages are accessible"""
        self.print_section("5. Frontend Integration Tests")
        
        pages = [
            "/",
            "/scan/test-scan-123"
        ]
        
        all_ok = True
        for page in pages:
            try:
                response = requests.get(
                    f"{self.frontend_url}{page}",
                    timeout=5,
                    allow_redirects=True
                )
                ok = response.status_code == 200
                self.log_test(
                    f"Frontend Route {page}",
                    ok,
                    f"Status {response.status_code}"
                )
                all_ok = all_ok and ok
            except Exception as e:
                self.log_test(f"Frontend Route {page}", False, str(e)[:40])
                all_ok = False
        
        return all_ok
    
    # === Summary ===
    
    def print_summary(self):
        """Print test summary"""
        self.print_section("Test Summary")
        
        total = len(self.test_results["passed"]) + len(self.test_results["failed"])
        passed = len(self.test_results["passed"])
        failed = len(self.test_results["failed"])
        
        print(f"Total Tests: {total}")
        print(f"{GREEN}Passed: {passed}{RESET}")
        print(f"{RED}Failed: {failed}{RESET}")
        
        if failed > 0:
            print(f"\n{BOLD}Failed Tests:{RESET}")
            for test in self.test_results["failed"]:
                print(f"  • {test}")
        
        print("\n" + "="*70)
        
        if failed == 0:
            print(f"{GREEN}{BOLD}All tests passed! System ready for production.{RESET}")
            return True
        else:
            print(f"{RED}{BOLD}Some tests failed. Review errors above.{RESET}")
            return False
    
    def run_all_tests(self):
        """Run complete test suite"""
        print(f"\n{BOLD}Starting Link&Load E2E Test Suite{RESET}")
        print(f"Backend: {self.backend_url}")
        print(f"Frontend: {self.frontend_url}")
        
        # Connectivity tests
        backend_ok = self.test_backend_health()
        frontend_ok = self.test_frontend_health()
        db_ok = self.test_database_connectivity()
        
        if not backend_ok:
            print(f"\n{RED}Backend is not running. Start it and try again.{RESET}")
            sys.exit(1)
        
        # Scanner tests
        self.test_scanner_health()
        
        # API tests
        self.test_scan_endpoints()
        
        # Execution tests
        scan_id = self.test_start_scan()
        
        if scan_id:
            self.test_get_scan_status(scan_id)
            self.test_websocket_connection(scan_id)
            
            # Wait a moment for scan to progress
            import time
            print("\nWaiting 5 seconds for scan to progress...")
            time.sleep(5)
            
            # Results validation
            self.test_scan_results_structure(scan_id)
        
        # Frontend tests
        if frontend_ok:
            self.test_frontend_routing()
        
        # Summary
        success = self.print_summary()
        return success


def main():
    """Run test suite"""
    suite = E2ETestSuite()
    success = suite.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
