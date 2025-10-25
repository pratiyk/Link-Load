# Scanner Tools Installation Guide

This guide will help you install and configure the three security scanner tools required for LinkLoad.

---

## Prerequisites
- Windows PowerShell or Git Bash
- Python 3.8+ (already installed)
- Docker Desktop (recommended for ZAP)
- Go 1.19+ (optional, for Nuclei)

---

## 1. OWASP ZAP (Recommended: Docker)

### Option A: Docker (Easiest - Recommended)

#### Step 1: Start ZAP container
```powershell
# Pull the ZAP Docker image
docker pull owasp/zap2docker-stable

# Run ZAP in daemon mode
docker run -d `
  --name zap `
  -p 8080:8080 `
  owasp/zap2docker-stable `
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=linkload-zap-key
```

#### Step 2: Update .env
```env
ZAP_BASE_URL=http://localhost:8080
ZAP_API_KEY=linkload-zap-key
```

#### Step 3: Verify
```powershell
# Test ZAP is running
curl http://localhost:8080/JSON/core/view/version/

# Should return JSON with ZAP version
```

#### Managing ZAP
```powershell
# Stop ZAP
docker stop zap

# Start ZAP
docker start zap

# View logs
docker logs zap

# Remove ZAP
docker rm -f zap
```

### Option B: Desktop Installation

1. Download ZAP from: https://www.zaproxy.org/download/
2. Install ZAP
3. Start in daemon mode:
   ```powershell
   # Windows
   "C:\Program Files\ZAP\Zed Attack Proxy\zap.bat" -daemon -port 8080 -config api.key=linkload-zap-key
   ```
4. Update `.env` with `ZAP_BASE_URL=http://localhost:8080`

---

## 2. Nuclei Scanner

### Option A: Download Pre-built Binary (Easiest)

#### Step 1: Download
1. Go to: https://github.com/projectdiscovery/nuclei/releases/latest
2. Download `nuclei_<version>_windows_amd64.zip`
3. Extract to a location (e.g., `C:\Tools\nuclei\`)

#### Step 2: Update .env
```env
NUCLEI_BINARY_PATH=C:\Tools\nuclei\nuclei.exe
```

#### Step 3: Initialize templates
```powershell
# First run will download templates
C:\Tools\nuclei\nuclei.exe -update-templates
```

### Option B: Install with Go

```powershell
# Install Go from https://go.dev/dl/ if not installed

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Find installation path
where.exe nuclei
# Typically: C:\Users\<username>\go\bin\nuclei.exe

# Update .env with the actual path
```

### Verify Installation
```powershell
# Test Nuclei
C:\Tools\nuclei\nuclei.exe -version

# Should output: Nuclei v3.x.x
```

---

## 3. Wapiti Scanner

### Installation

#### Step 1: Install with pip
```powershell
# Activate your virtual environment
.venv\Scripts\Activate.ps1

# Install Wapiti
pip install wapiti3

# Find installation path
where.exe wapiti

# Typical locations:
# - .venv\Scripts\wapiti.exe (if in venv)
# - C:\Python311\Scripts\wapiti.exe (global install)
# - C:\Users\<username>\AppData\Local\Programs\Python\Python311\Scripts\wapiti.exe
```

#### Step 2: Update .env
```env
# Use the path from 'where.exe wapiti'
WAPITI_BINARY_PATH=C:\prateek\projects\linkload\.venv\Scripts\wapiti.exe
```

### Verify Installation
```powershell
# Test Wapiti
wapiti --version

# Should output: Wapiti 3.x.x
```

---

## Quick Setup Script

Save this as `install_scanners.ps1`:

```powershell
# LinkLoad Scanner Tools Installation Script

Write-Host "=" * 60
Write-Host "LinkLoad Scanner Tools Installation"
Write-Host "=" * 60

# 1. Check Docker
Write-Host "`n[1/3] Checking Docker..."
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "   Docker found. Installing OWASP ZAP..."
    
    docker pull owasp/zap2docker-stable
    docker run -d `
        --name zap `
        -p 8080:8080 `
        owasp/zap2docker-stable `
        zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=linkload-zap-key
    
    Write-Host "   ZAP container started on port 8080"
} else {
    Write-Host "   Docker not found. Please install ZAP manually."
}

# 2. Install Wapiti
Write-Host "`n[2/3] Installing Wapiti..."
if (Test-Path ".venv\Scripts\Activate.ps1") {
    .venv\Scripts\Activate.ps1
    pip install wapiti3
    $wapitiPath = (Get-Command wapiti).Source
    Write-Host "   Wapiti installed at: $wapitiPath"
} else {
    Write-Host "   Virtual environment not found. Run from project root."
}

# 3. Check Nuclei
Write-Host "`n[3/3] Checking Nuclei..."
if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    $nucleiPath = (Get-Command nuclei).Source
    Write-Host "   Nuclei found at: $nucleiPath"
} else {
    Write-Host "   Nuclei not found. Please install manually:"
    Write-Host "   https://github.com/projectdiscovery/nuclei/releases"
}

# Summary
Write-Host "`n" + "=" * 60
Write-Host "Installation Complete!"
Write-Host "=" * 60
Write-Host "`nNext steps:"
Write-Host "1. Update backend/.env with the paths shown above"
Write-Host "2. Run: python backend/test_scanner_init.py"
Write-Host "3. Start the backend server"
```

Run it:
```powershell
cd C:\prateek\projects\linkload
powershell -ExecutionPolicy Bypass -File install_scanners.ps1
```

---

## Testing Installation

### Test Script
Run the provided test script:

```powershell
cd C:\prateek\projects\linkload\backend
python test_scanner_init.py
```

Expected output:
```
============================================================
Testing Scanner Initialization
============================================================

1. Testing Nuclei Scanner...
   Binary path: C:\Tools\nuclei\nuclei.exe
   ✓ Nuclei initialized: True

2. Testing Wapiti Scanner...
   Binary path: C:\prateek\projects\linkload\.venv\Scripts\wapiti.exe
   ✓ Wapiti initialized: True

3. Testing OWASP ZAP Scanner...
   Base URL: http://localhost:8080
   ✓ ZAP initialized: True

4. Testing OpenAI Integration...
   API Key configured: Yes
   API Key prefix: sk-proj-gbSR61ZQAe...
   ✓ LLM service initialized: OpenAIProvider

============================================================
Scanner Initialization Test Complete
============================================================
```

---

## Minimal Configuration (.env)

After installation, your `.env` should have:

```env
# OpenAI
OPENAI_API_KEY=sk-proj-gbSR61ZQAe7K1wEI2KPq...

# Scanners
ZAP_BASE_URL=http://localhost:8080
ZAP_API_KEY=linkload-zap-key
NUCLEI_BINARY_PATH=C:\Tools\nuclei\nuclei.exe
WAPITI_BINARY_PATH=C:\prateek\projects\linkload\.venv\Scripts\wapiti.exe
```

---

## Troubleshooting

### ZAP not connecting
```powershell
# Check if ZAP is running
docker ps | Select-String zap

# Check ZAP logs
docker logs zap

# Restart ZAP
docker restart zap

# Test manually
curl http://localhost:8080/JSON/core/view/version/
```

### Nuclei templates not found
```powershell
# Update templates
nuclei -update-templates

# Use specific template directory
NUCLEI_TEMPLATES_DIR=C:\Tools\nuclei\templates
```

### Wapiti not found
```powershell
# Reinstall in virtual environment
.venv\Scripts\Activate.ps1
pip uninstall wapiti3
pip install wapiti3

# Find correct path
where.exe wapiti
```

### Permission errors
```powershell
# Run PowerShell as Administrator
# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Docker Compose Setup (Recommended)

Add to `docker-compose.yml`:

```yaml
services:
  # ... existing services ...
  
  zap:
    image: owasp/zap2docker-stable
    container_name: linkload-zap
    command: zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=linkload-zap-key
    ports:
      - "8080:8080"
    networks:
      - linkload-network
    environment:
      - ZAP_PORT=8080
    restart: unless-stopped

networks:
  linkload-network:
    driver: bridge
```

Then:
```powershell
docker-compose up -d zap
```

Update `.env`:
```env
ZAP_BASE_URL=http://zap:8080  # or http://localhost:8080 for local access
```

---

## Alternative: Use Scanners via API Services

If local installation is difficult, consider using managed scanning services:
- **Pentest-Tools.com** API
- **Intruder.io** API
- **Detectify** API

These would require modifying the scanner implementations to call external APIs instead of local binaries.

---

## Support

For issues:
1. Check scanner logs
2. Verify `.env` paths are correct
3. Test scanners independently (outside LinkLoad)
4. Check GitHub issues for each tool

Scanner Documentation:
- ZAP: https://www.zaproxy.org/docs/
- Nuclei: https://docs.projectdiscovery.io/tools/nuclei/overview
- Wapiti: https://wapiti-scanner.github.io/

---

**Estimated Installation Time**: 15-30 minutes
**Difficulty**: Medium (Docker makes it easier)
