"""
LinkLoad Backend Health Check Script
Run this to verify your backend setup is correct.
"""

import sys
import os
import importlib.util

def check_python_version():
    """Check Python version is 3.9+"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print(f"[ERROR] Python version {version.major}.{version.minor} is too old. Need Python 3.9+")
        return False
    print(f"[OK] Python version {version.major}.{version.minor}.{version.micro} OK")
    return True

def check_module(module_name, package_name=None):
    """Check if a module can be imported"""
    if package_name is None:
        package_name = module_name
    
    spec = importlib.util.find_spec(module_name)
    if spec is None:
        print(f"[ERROR] Module '{package_name}' not installed")
        return False
    print(f"[OK] Module '{package_name}' installed")
    return True

def check_env_file():
    """Check if .env file exists"""
    if os.path.exists(".env"):
        print("[OK] .env file found")
        return True
    print("[ERROR] .env file not found - copy from .env.example or create one")
    return False

def check_required_packages():
    """Check all required packages are installed"""
    required = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("pydantic", "pydantic"),
        ("supabase", "supabase"),
        ("sqlalchemy", "SQLAlchemy"),
        ("httpx", "httpx"),
        ("jwt", "PyJWT"),
        ("passlib", "passlib"),
        ("dotenv", "python-dotenv"),
    ]
    
    all_ok = True
    for module, package in required:
        if not check_module(module, package):
            all_ok = False
    
    return all_ok

def check_app_structure():
    """Check if app structure is correct"""
    required_dirs = [
        "app",
        "app/api",
        "app/core",
        "app/models",
        "app/services",
        "app/database"
    ]
    
    all_ok = True
    for dir_path in required_dirs:
        if os.path.exists(dir_path) and os.path.isdir(dir_path):
            print(f"[OK] Directory '{dir_path}' exists")
        else:
            print(f"[ERROR] Directory '{dir_path}' not found")
            all_ok = False
    
    return all_ok

def check_optional_scanners():
    """Check if optional scanner tools are available"""
    print("\n[CHECK] Optional Scanner Tools:")
    
    # Check Nuclei
    try:
        import subprocess
        result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("[OK] Nuclei scanner installed")
        else:
            print("[WARN] Nuclei not found (optional)")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[WARN] Nuclei not found (optional)")
    
    # Check Wapiti
    try:
        result = subprocess.run(["wapiti", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("[OK] Wapiti scanner installed")
        else:
            print("[WARN] Wapiti not found (optional)")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[WARN] Wapiti not found (optional)")

def test_import_app():
    """Try to import the main app module"""
    try:
        sys.path.insert(0, os.getcwd())
        from app.main import app
        print("[OK] App module imports successfully")
        return True
    except ImportError as e:
        print(f"[ERROR] Failed to import app: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Error importing app: {e}")
        return False

def main():
    print("=" * 60)
    print("LinkLoad Backend Health Check")
    print("=" * 60)
    print()
    
    checks = []
    
    print("[CHECK] Checking Python Environment...")
    checks.append(check_python_version())
    print()
    
    print("[CHECK] Checking Required Packages...")
    checks.append(check_required_packages())
    print()
    
    print("[CHECK] Checking Project Structure...")
    checks.append(check_app_structure())
    print()
    
    print("[CHECK] Checking Configuration...")
    checks.append(check_env_file())
    print()
    
    check_optional_scanners()
    print()
    
    print("[CHECK] Testing App Import...")
    checks.append(test_import_app())
    print()
    
    print("=" * 60)
    if all(checks):
        print("[OK] All critical checks passed!")
        print("You can start the server with:")
        print("  python -m uvicorn app.main:app --reload")
    else:
        print("[ERROR] Some checks failed. Please fix the issues above.")
        print("\nQuick fixes:")
        print("  • Install missing packages: pip install -r requirements.txt")
        print("  • Create .env file with required variables")
        print("  • Ensure you're in the 'backend' directory")
    print("=" * 60)

if __name__ == "__main__":
    main()
