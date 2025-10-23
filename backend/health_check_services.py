"""
Health check script to verify all services are running and accessible.
Run: python backend/health_check_services.py
"""

import subprocess
import requests
import os
import sys
from pathlib import Path

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'


def print_status(service_name, success, message):
    """Print status with color formatting"""
    symbol = f"{GREEN}✓{RESET}" if success else f"{RED}✗{RESET}"
    status_color = GREEN if success else RED
    print(f"{symbol} {service_name:25} {status_color}{message}{RESET}")


def check_zap():
    """Check if OWASP ZAP is running"""
    try:
        zap_url = os.getenv('ZAP_URL', 'http://localhost:8090')
        response = requests.get(
            f"{zap_url}/JSON/core/action/version/",
            timeout=5
        )
        if response.status_code == 200:
            return True, "Running and accessible"
        return False, f"HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused - not running"
    except Exception as e:
        return False, str(e)


def check_nuclei():
    """Check if Nuclei is installed"""
    try:
        result = subprocess.run(
            ['nuclei', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            version = result.stdout.strip().split('\n')[0]
            return True, version
        return False, "Installation found but error running"
    except FileNotFoundError:
        return False, "Not found in PATH"
    except Exception as e:
        return False, str(e)


def check_wapiti():
    """Check if Wapiti is installed"""
    try:
        result = subprocess.run(
            ['wapiti', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return True, version
        return False, "Installation found but error running"
    except FileNotFoundError:
        return False, "Not found in PATH"
    except Exception as e:
        return False, str(e)


def check_database():
    """Check if database connection works"""
    try:
        from app.database import supabase
        
        # Try a simple query
        response = supabase.table('owasp_scans').select('count', count='exact').execute()
        return True, "Connected and accessible"
    except ImportError:
        return False, "Cannot import database module"
    except Exception as e:
        error_msg = str(e)
        if 'SUPABASE_URL' in error_msg or 'env' in error_msg.lower():
            return False, "Environment variables not set"
        return False, error_msg[:50]


def check_backend_api():
    """Check if backend API is running"""
    try:
        response = requests.get(
            'http://localhost:8000/docs',
            timeout=5
        )
        if response.status_code == 200:
            return True, "Running on port 8000"
        return False, f"HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Not responding - likely not running"
    except Exception as e:
        return False, str(e)


def check_frontend():
    """Check if frontend is running"""
    try:
        response = requests.get(
            'http://localhost:3000',
            timeout=5
        )
        if response.status_code == 200:
            return True, "Running on port 3000"
        return False, f"HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Not responding - likely not running"
    except Exception as e:
        return False, str(e)


def check_env_file():
    """Check if .env file exists and has required variables"""
    env_file = Path('backend/.env')
    if not env_file.exists():
        return False, ".env file not found"
    
    required_vars = [
        'SUPABASE_URL',
        'SUPABASE_KEY',
        'SECRET_KEY'
    ]
    
    with open(env_file, 'r') as f:
        env_content = f.read()
    
    missing = [var for var in required_vars if var not in env_content]
    
    if missing:
        return False, f"Missing: {', '.join(missing)}"
    return True, "All required variables present"


def main():
    print("\n" + "="*70)
    print(f"{BOLD}LINK&LOAD SERVICE HEALTH CHECK{RESET}")
    print("="*70 + "\n")
    
    checks = [
        ("Environment", check_env_file, "CRITICAL"),
        ("Database", check_database, "CRITICAL"),
        ("Backend API", check_backend_api, "CRITICAL"),
        ("Frontend", check_frontend, "OPTIONAL"),
        ("OWASP ZAP", check_zap, "CRITICAL"),
        ("Nuclei", check_nuclei, "REQUIRED"),
        ("Wapiti", check_wapiti, "REQUIRED"),
    ]
    
    results = {}
    critical_failures = []
    
    print(f"{BOLD}{'SERVICE':<25} {'STATUS':<30} {'LEVEL':<12}{RESET}")
    print("-"*70)
    
    for service_name, check_func, priority in checks:
        try:
            success, message = check_func()
            results[service_name] = (success, priority)
            print_status(service_name, success, message)
            
            if not success and priority == "CRITICAL":
                critical_failures.append((service_name, message))
        except Exception as e:
            print_status(service_name, False, f"Error: {str(e)[:40]}")
            results[service_name] = (False, priority)
            if priority == "CRITICAL":
                critical_failures.append((service_name, str(e)))
    
    print("\n" + "="*70)
    
    # Summary
    total = len(results)
    passed = sum(1 for success, _ in results.values() if success)
    failed = total - passed
    
    print(f"\n{BOLD}Summary:{RESET}")
    print(f"  Total checks: {total}")
    print(f"  {GREEN}Passed: {passed}{RESET}")
    print(f"  {RED}Failed: {failed}{RESET}")
    
    if critical_failures:
        print(f"\n{YELLOW}{BOLD}Critical Issues:{RESET}")
        for service, message in critical_failures:
            print(f"  • {service}: {message}")
        print(f"\n{YELLOW}Please fix critical issues before running scans.{RESET}")
        sys.exit(1)
    else:
        print(f"\n{GREEN}{BOLD}All systems operational! Ready to scan.{RESET}")
        print("="*70 + "\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
