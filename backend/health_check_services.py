"""
Health check script to verify all services are running and accessible.
Run: python backend/health_check_services.py
"""

import subprocess
import requests
import os
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Ensure backend package is importable when executing from repository root
BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# Load environment variables before importing application settings
load_dotenv(BACKEND_ROOT / ".env")

try:
    from app.core.config import settings
except Exception:
    settings = None

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'


def print_status(service_name, success, message):
    """Print status with color formatting"""
    symbol = f"{GREEN}[OK]{RESET}" if success else f"{RED}[ERROR]{RESET}"
    status_color = GREEN if success else RED
    print(f"{symbol} {service_name:25} {status_color}{message}{RESET}")


def _get_setting(attr: str) -> Optional[str]:
    return getattr(settings, attr, None) if settings is not None else None


def _resolve_binary_path(env_name: str, attr_name: str, default: str) -> str:
    configured = _get_setting(attr_name)
    if configured:
        return str(configured)
    env_value = os.getenv(env_name)
    if env_value:
        return env_value
    return default


def _run_version_command(target: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    return subprocess.run(
        [target, '--version'],
        capture_output=True,
        text=True,
        encoding='utf-8',
        timeout=15,
        env=env
    )


def check_zap():
    """Check if OWASP ZAP is running"""
    try:
        zap_url = (
            _get_setting("ZAP_BASE_URL")
            or os.getenv("ZAP_BASE_URL")
            or os.getenv('ZAP_URL')
            or 'http://localhost:8090'
        )
        if not zap_url.startswith("http"):
            zap_url = f"http://{zap_url}"
        zap_url = zap_url.rstrip("/")
        params = {}
        api_key = _get_setting("ZAP_API_KEY") or os.getenv("ZAP_API_KEY")
        if api_key:
            params["apikey"] = api_key

        response = requests.get(
            f"{zap_url}/JSON/core/view/version/",
            params=params,
            timeout=10
        )
        if response.status_code == 200:
            try:
                version = response.json().get("version", "unknown")
            except ValueError:
                version = response.text[:40]
            return True, f"Running (v{version})"
        return False, f"HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused - not running"
    except Exception as e:
        return False, str(e)


def check_nuclei():
    """Check if Nuclei is installed"""
    binary = _resolve_binary_path('NUCLEI_BINARY_PATH', 'NUCLEI_BINARY_PATH', 'nuclei')
    candidate = Path(binary).expanduser()
    target = str(candidate if candidate.exists() else binary)

    if candidate.is_absolute() and not candidate.exists():
        return False, f"Configured path not found: {candidate}"

    try:
        result = _run_version_command(target)
        if result.returncode == 0:
            version = (result.stdout or result.stderr).strip().split('\n')[0]
            return True, version
        tail = (result.stderr or result.stdout).strip().split('\n')[-1]
        return False, f"Exit {result.returncode}: {tail[:80]}"
    except FileNotFoundError:
        return False, "Not found in PATH"
    except Exception as e:
        return False, str(e)


def check_wapiti():
    """Check if Wapiti is installed"""
    binary = _resolve_binary_path('WAPITI_BINARY_PATH', 'WAPITI_BINARY_PATH', 'wapiti')
    candidate = Path(binary).expanduser()
    target = str(candidate if candidate.exists() else binary)

    if candidate.is_absolute() and not candidate.exists():
        return False, f"Configured path not found: {candidate}"

    try:
        result = _run_version_command(target)
        if result.returncode == 0:
            version = (result.stdout or result.stderr).strip().split('\n')[0]
            return True, version
        tail = (result.stderr or result.stdout).strip().split('\n')[-1]
        return False, f"Exit {result.returncode}: {tail[:80]}"
    except FileNotFoundError:
        return False, "Not found in PATH"
    except Exception as e:
        return False, str(e)


def check_database():
    """Check if database connection works"""
    try:
        from app.database.supabase_client import supabase
    except ModuleNotFoundError:
        return False, "Supabase client module not found"
    except Exception as exc:
        return False, f"Supabase client init failed: {exc.__class__.__name__}"

    try:
        if supabase.health_check():
            return True, "Connected and accessible"
        return False, "Health check query failed"
    except Exception as e:
        error_msg = str(e)
        if 'SUPABASE_URL' in error_msg or 'env' in error_msg.lower():
            return False, "Environment variables not set"
        return False, error_msg[:80]


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
