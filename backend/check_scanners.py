"""Quick scanner verification script."""
import subprocess
import sys
from pathlib import Path

print("=" * 70)
print(" Scanner Status Check")
print("=" * 70)

# Check Nuclei
print("\n1. Nuclei Scanner:")
nuclei_path = r"C:\prateek\projects\linkload\tools\nuclei\nuclei.exe"
if Path(nuclei_path).exists():
    try:
        result = subprocess.run([nuclei_path, "-version"], 
                              capture_output=True, text=True, timeout=5)
        version = result.stdout.strip().split('\n')[-1] if result.stdout else "Unknown"
        print(f"   ✓ INSTALLED - {version}")
        print(f"   Path: {nuclei_path}")
    except Exception as e:
        print(f"   ✗ ERROR: {e}")
else:
    print(f"   ✗ NOT FOUND at {nuclei_path}")

# Check Wapiti
print("\n2. Wapiti Scanner:")
wapiti_path = r"C:\prateek\projects\linkload\.venv\Scripts\wapiti.exe"
if Path(wapiti_path).exists():
    try:
        result = subprocess.run([wapiti_path, "--version"], 
                              capture_output=True, text=True, timeout=5)
        # Wapiti outputs to stderr
        version_line = result.stderr.strip().split('\n')[-1] if result.stderr else "Unknown"
        print(f"   ✓ INSTALLED - Wapiti {version_line}")
        print(f"   Path: {wapiti_path}")
    except Exception as e:
        print(f"   ✗ ERROR: {e}")
else:
    print(f"   ✗ NOT FOUND at {wapiti_path}")

# Check ZAP
print("\n3. OWASP ZAP:")
import requests
try:
    response = requests.get("http://localhost:8090/JSON/core/view/version/", timeout=2)
    if response.status_code == 200:
        version_data = response.json()
        print(f"   ✓ RUNNING - {version_data.get('version', 'Unknown')}")
        print(f"   URL: http://localhost:8090")
    else:
        print(f"   ⚠ ACCESSIBLE but returned status {response.status_code}")
except requests.exceptions.ConnectionError:
    print("   ⚠ NOT RUNNING (This is optional)")
    print("   Start with: python backend/mock_zap_server.py")
except Exception as e:
    print(f"   ✗ ERROR: {e}")

# Check Groq AI
print("\n4. Groq AI Integration:")
sys.path.insert(0, str(Path(__file__).parent))
try:
    from app.services.llm_service import llm_service
    from app.core.config import settings
    
    if settings.GROQ_API_KEY:
        print(f"   ✓ CONFIGURED")
        print(f"   Provider: {llm_service._provider.__class__.__name__}")
        print(f"   API Key: {settings.GROQ_API_KEY[:20]}...")
    else:
        print("   ✗ API KEY NOT CONFIGURED")
except Exception as e:
    print(f"   ✗ ERROR: {e}")

# Summary
print("\n" + "=" * 70)
print(" Summary")
print("=" * 70)
print("\n✓ = Working")
print("⚠ = Optional/Not Running")
print("✗ = Error/Not Found")

print("\nReady for scanning: Nuclei + Wapiti + Groq AI")
print("Optional: ZAP (for more comprehensive scanning)")
print("\n" + "=" * 70)
