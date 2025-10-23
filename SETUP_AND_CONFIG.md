# Setup and Configuration Guide

## 1. Database Setup - Supabase

### Option A: Using Alembic Migration (Recommended)

```bash
cd backend

# Run migrations to create tables
alembic upgrade head

# Verify tables were created
python -c "from app.database import supabase; print(supabase)"
```

### Option B: Manual SQL Execution in Supabase Dashboard

1. Go to Supabase Dashboard → Your Project → SQL Editor
2. Create new query and execute the following SQL:

```sql
-- Create OWASP Scans table
CREATE TABLE IF NOT EXISTS owasp_scans (
  scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  target_url TEXT NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  progress INTEGER DEFAULT 0,
  current_stage VARCHAR(255) DEFAULT 'Initializing',
  started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  completed_at TIMESTAMP WITH TIME ZONE,
  scan_types JSONB DEFAULT '[]',
  options JSONB DEFAULT '{}',
  risk_score FLOAT,
  risk_level VARCHAR(50),
  ai_analysis JSONB,
  mitre_mapping JSONB,
  remediation_strategies JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create Vulnerabilities table
CREATE TABLE IF NOT EXISTS owasp_vulnerabilities (
  vulnerability_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES owasp_scans(scan_id) ON DELETE CASCADE,
  title VARCHAR(512) NOT NULL,
  description TEXT,
  severity VARCHAR(50) NOT NULL,
  cvss_score FLOAT,
  location VARCHAR(2048),
  recommendation TEXT,
  mitre_techniques JSONB DEFAULT '[]',
  scanner_source VARCHAR(100),
  scanner_id VARCHAR(256),
  discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create Audit Log table
CREATE TABLE IF NOT EXISTS scan_audit_log (
  audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES owasp_scans(scan_id) ON DELETE CASCADE,
  action VARCHAR(100) NOT NULL,
  old_status VARCHAR(50),
  new_status VARCHAR(50),
  details JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_owasp_scans_user_id ON owasp_scans(user_id);
CREATE INDEX idx_owasp_scans_status ON owasp_scans(status);
CREATE INDEX idx_owasp_scans_created_at ON owasp_scans(created_at);
CREATE INDEX idx_owasp_scans_user_created ON owasp_scans(user_id, created_at);

CREATE INDEX idx_owasp_vulnerabilities_scan_id ON owasp_vulnerabilities(scan_id);
CREATE INDEX idx_owasp_vulnerabilities_severity ON owasp_vulnerabilities(severity);
CREATE INDEX idx_owasp_vulnerabilities_scan_severity ON owasp_vulnerabilities(scan_id, severity);

CREATE INDEX idx_scan_audit_log_scan_id ON scan_audit_log(scan_id);
CREATE INDEX idx_scan_audit_log_created_at ON scan_audit_log(created_at);

-- Enable Row Level Security (RLS)
ALTER TABLE owasp_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE owasp_vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_audit_log ENABLE ROW LEVEL SECURITY;

-- Create RLS policies (users can only see their own scans)
CREATE POLICY "Users can see their own scans" ON owasp_scans
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Users can create scans" ON owasp_scans
  FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can update their own scans" ON owasp_scans
  FOR UPDATE USING (user_id = auth.uid());

CREATE POLICY "View vulnerabilities for own scans" ON owasp_vulnerabilities
  FOR SELECT USING (
    scan_id IN (
      SELECT scan_id FROM owasp_scans WHERE user_id = auth.uid()
    )
  );

-- Verify tables
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('owasp_scans', 'owasp_vulnerabilities', 'scan_audit_log');
```

### Verify Connection

```python
# backend/verify_db.py
from app.database import supabase

try:
    # Test connection
    response = supabase.table('owasp_scans').select('*').limit(1).execute()
    print("✓ Database connection successful")
    print(f"  Tables initialized: owasp_scans exists")
except Exception as e:
    print(f"✗ Database error: {e}")
```

Run: `python backend/verify_db.py`

---

## 2. Scanner Services Configuration

### OWASP ZAP Setup

#### Option A: Docker Container (Recommended)

```bash
# Pull and run OWASP ZAP in daemon mode
docker pull owasp/zap2docker-stable

# Run ZAP API server
docker run -d \
  --name zap \
  -p 8090:8090 \
  -e ZAP_CONFIG_DAEMON=true \
  -e ZAP_CONFIG_API_LISTEN=0.0.0.0 \
  owasp/zap2docker-stable \
  zap.sh -config api.disablekey=true -daemon

# Wait for startup
sleep 10
```

#### Option B: Local Installation

**macOS:**
```bash
brew install zaproxy
zaproxy &  # Run in background
# Access: http://localhost:8080
```

**Windows:**
Download from: https://www.zaproxy.org/download/

**Linux:**
```bash
sudo apt-get install zaproxy
zaproxy &
```

#### Verify ZAP Connection

```python
# backend/test_scanners.py
from app.core.config import settings
from zapv2 import clientapi

try:
    zap = clientapi.ClientApi(proxies={'http': settings.ZAP_URL, 'https': settings.ZAP_URL})
    version = zap.core.version()
    print(f"✓ OWASP ZAP connected: Version {version}")
except Exception as e:
    print(f"✗ ZAP connection failed: {e}")
```

### Nuclei Setup

```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or use package manager
# macOS
brew install nuclei

# Linux
sudo apt-get install nuclei

# Verify installation
nuclei --version

# Download templates
nuclei -update-templates

# Verify templates exist
ls ~/nuclei-templates/
```

#### Set Environment Variable

```bash
# Windows
$env:NUCLEI_PATH = "C:\Users\{username}\go\bin\nuclei.exe"

# macOS/Linux
export NUCLEI_PATH="/usr/local/bin/nuclei"

# Verify
which nuclei  # macOS/Linux
where nuclei  # Windows
```

### Wapiti Setup

```bash
# Install Wapiti
pip install wapiti3

# Verify installation
wapiti --version

# Download vulnerability database
wapiti --update

# Verify
which wapiti  # macOS/Linux
where wapiti  # Windows
```

---

## 3. Environment Variables Configuration

Create `.env` file in backend directory:

```bash
# Database
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
DATABASE_URL=postgresql://user:password@localhost:5432/linkload

# Scanners
ZAP_URL=http://localhost:8090
NUCLEI_PATH=/usr/local/bin/nuclei
WAPITI_PATH=/usr/local/bin/wapiti

# LLM Integration (Optional)
OPENAI_API_KEY=your-openai-key
ANTHROPIC_API_KEY=your-anthropic-key

# Security
SECRET_KEY=your-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# API
CORS_ORIGINS=["http://localhost:3000"]
API_TITLE=Link&Load API
API_VERSION=1.0.0
```

---

## 4. Scanner Health Checks

Create `backend/health_check.py` to verify all services:

```python
import subprocess
import requests
import os
from pathlib import Path

def check_zap():
    try:
        response = requests.get(f"{os.getenv('ZAP_URL', 'http://localhost:8090')}/JSON/core/action/version/")
        if response.status_code == 200:
            return True, "OWASP ZAP running"
        return False, "OWASP ZAP not responding"
    except Exception as e:
        return False, f"OWASP ZAP error: {e}"

def check_nuclei():
    try:
        result = subprocess.run(['nuclei', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.strip()
            return True, f"Nuclei available: {version}"
        return False, "Nuclei not found"
    except Exception as e:
        return False, f"Nuclei error: {e}"

def check_wapiti():
    try:
        result = subprocess.run(['wapiti', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            return True, f"Wapiti available: {result.stdout.strip()}"
        return False, "Wapiti not found"
    except Exception as e:
        return False, f"Wapiti error: {e}"

def check_database():
    try:
        from app.database import supabase
        response = supabase.table('owasp_scans').select('count', count='exact').execute()
        return True, "Database connected"
    except Exception as e:
        return False, f"Database error: {e}"

def main():
    print("\n" + "="*50)
    print("SCANNER HEALTH CHECK")
    print("="*50 + "\n")
    
    checks = [
        ("Database", check_database),
        ("OWASP ZAP", check_zap),
        ("Nuclei", check_nuclei),
        ("Wapiti", check_wapiti),
    ]
    
    all_passed = True
    for name, check_func in checks:
        status, message = check_func()
        symbol = "✓" if status else "✗"
        print(f"{symbol} {name:20} {message}")
        if not status:
            all_passed = False
    
    print("\n" + "="*50)
    if all_passed:
        print("All systems operational!")
    else:
        print("Some services need configuration.")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
```

Run: `python backend/health_check.py`

---

## 5. Running Complete Stack

### Terminal 1 - Backend
```bash
cd backend
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m uvicorn app.main:app --reload --port 8000
```

### Terminal 2 - Frontend
```bash
cd frontend
npm start
```

### Terminal 3 - OWASP ZAP (if using Docker)
```bash
docker run -d --name zap -p 8090:8090 \
  -e ZAP_CONFIG_DAEMON=true \
  owasp/zap2docker-stable zap.sh -daemon
```

---

## 6. Testing the Setup

```python
# backend/test_full_setup.py
import asyncio
from app.services.comprehensive_scanner import ComprehensiveScanner
from app.core.config import settings

async def test():
    scanner = ComprehensiveScanner()
    try:
        await scanner._initialize_scanners()
        print("✓ All scanners initialized successfully")
        
        # Run a test scan
        results = await scanner.start_scan(
            scan_id="test-scan-123",
            target_url="https://httpbin.org",
            scan_types=["owasp"],  # Start with just one
            options={
                "enable_ai_analysis": False,
                "enable_mitre_mapping": True,
                "timeout_minutes": 5
            }
        )
        print(f"✓ Test scan completed: {len(results.get('vulnerabilities', []))} vulnerabilities found")
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    asyncio.run(test())
```

---

## 7. Troubleshooting

### ZAP Connection Failed
```bash
# Check if ZAP is running
curl http://localhost:8090/JSON/core/action/version/

# Docker: Check logs
docker logs zap

# Restart ZAP
docker restart zap
```

### Nuclei Not Found
```bash
# Install/Update
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Add to PATH (Windows)
$env:PATH += ";C:\Users\{username}\go\bin"

# Verify
nuclei --version
```

### Database Connection Error
```bash
# Check Supabase credentials in .env
# Verify tables exist in Supabase dashboard
# Test connection: python backend/verify_db.py
```

### WebSocket Connection Failed
- Check backend port 8000 is accessible
- Verify CORS settings in app/main.py
- Check browser console for specific errors

---

## Next Steps

1. ✓ Database schema created
2. ✓ Scanners configured and health checked
3. Next: Run end-to-end tests
4. Next: Configure LLM integration
5. Next: Setup Docker containerization
6. Next: Configure CI/CD pipeline
7. Next: Production deployment

---

**For questions or issues:** Check IMPLEMENTATION_STATUS.md or DEVELOPER_QUICKSTART.md
