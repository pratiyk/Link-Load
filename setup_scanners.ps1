# Scanner Setup Script for LinkLoad
# This script downloads and configures Nuclei and provides instructions for ZAP

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host " LinkLoad Security Scanner Setup" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

# Create tools directory
$toolsDir = "C:\prateek\projects\linkload\tools"
$nucleiDir = "$toolsDir\nuclei"

Write-Host "`n[1/3] Setting up directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $nucleiDir | Out-Null
Write-Host "   Created: $nucleiDir" -ForegroundColor Green

# Download Nuclei
Write-Host "`n[2/3] Downloading Nuclei..." -ForegroundColor Yellow
$nucleiVersion = "v3.3.8"  # Latest stable version
$nucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/download/$nucleiVersion/nuclei_${nucleiVersion}_windows_amd64.zip"
$nucleiZip = "$nucleiDir\nuclei.zip"

try {
    Write-Host "   Downloading from: $nucleiUrl" -ForegroundColor Gray
    Invoke-WebRequest -Uri $nucleiUrl -OutFile $nucleiZip -UseBasicParsing
    Write-Host "   Downloaded successfully" -ForegroundColor Green
    
    # Extract Nuclei
    Write-Host "   Extracting..." -ForegroundColor Gray
    Expand-Archive -Path $nucleiZip -DestinationPath $nucleiDir -Force
    Remove-Item $nucleiZip
    Write-Host "   Extracted to: $nucleiDir" -ForegroundColor Green
    
    # Download templates
    Write-Host "`n   Downloading Nuclei templates..." -ForegroundColor Gray
    & "$nucleiDir\nuclei.exe" -update-templates
    Write-Host "   Templates downloaded" -ForegroundColor Green
    
} catch {
    Write-Host "   Error downloading Nuclei: $_" -ForegroundColor Red
    Write-Host "   You can manually download from: https://github.com/projectdiscovery/nuclei/releases" -ForegroundColor Yellow
}

# Check Wapiti
Write-Host "`n[3/3] Checking Wapiti..." -ForegroundColor Yellow
$wapitiPath = "C:\prateek\projects\linkload\.venv\Scripts\wapiti.exe"
if (Test-Path $wapitiPath) {
    Write-Host "   Wapiti found: $wapitiPath" -ForegroundColor Green
    & $wapitiPath --version
} else {
    Write-Host "   Wapiti not found. Installing..." -ForegroundColor Yellow
    & "C:\prateek\projects\linkload\.venv\Scripts\pip.exe" install wapiti3
}

# ZAP Instructions
Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
Write-Host " OWASP ZAP Setup Instructions" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "`nZAP requires manual setup. Choose one option:" -ForegroundColor Yellow

Write-Host "`nOption 1: Docker (Recommended)" -ForegroundColor Green
Write-Host "  If you have Docker Desktop installed, run:" -ForegroundColor Gray
Write-Host "  docker run -d -p 8090:8080 --name zap \" -ForegroundColor White
Write-Host "    owasp/zap2docker-stable \" -ForegroundColor White
Write-Host "    zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=1cgbmrgk5k1rk3ijv26ojgnlou" -ForegroundColor White

Write-Host "`nOption 2: Desktop Application" -ForegroundColor Green
Write-Host "  1. Download from: https://www.zaproxy.org/download/" -ForegroundColor Gray
Write-Host "  2. Install ZAP" -ForegroundColor Gray
Write-Host "  3. Start ZAP in daemon mode:" -ForegroundColor Gray
Write-Host "     zap.sh -daemon -port 8090 -config api.key=1cgbmrgk5k1rk3ijv26ojgnlou" -ForegroundColor White

Write-Host "`nOption 3: Skip ZAP (Use only Nuclei and Wapiti)" -ForegroundColor Green
Write-Host "  ZAP is optional. The other scanners will work without it." -ForegroundColor Gray

# Test scanners
Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
Write-Host " Testing Scanner Installation" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

Write-Host "`n1. Nuclei:" -ForegroundColor Yellow
if (Test-Path "$nucleiDir\nuclei.exe") {
    Write-Host "   Status: " -NoNewline -ForegroundColor Gray
    Write-Host "INSTALLED" -ForegroundColor Green
    $nucleiExe = "$nucleiDir\nuclei.exe"
    & $nucleiExe -version 2>&1 | Select-Object -First 1
    Write-Host "   Path: $nucleiExe" -ForegroundColor Gray
} else {
    Write-Host "   Status: " -NoNewline -ForegroundColor Gray
    Write-Host "NOT FOUND" -ForegroundColor Red
}

Write-Host "`n2. Wapiti:" -ForegroundColor Yellow
if (Test-Path $wapitiPath) {
    Write-Host "   Status: " -NoNewline -ForegroundColor Gray
    Write-Host "INSTALLED" -ForegroundColor Green
    & $wapitiPath --version 2>&1 | Select-Object -First 1
    Write-Host "   Path: $wapitiPath" -ForegroundColor Gray
} else {
    Write-Host "   Status: " -NoNewline -ForegroundColor Gray
    Write-Host "NOT FOUND" -ForegroundColor Red
}

Write-Host "`n3. OWASP ZAP:" -ForegroundColor Yellow
try {
    $zapResponse = Invoke-WebRequest -Uri "http://localhost:8090/JSON/core/view/version/" -UseBasicParsing -ErrorAction SilentlyContinue
    Write-Host "   Status: " -NoNewline -ForegroundColor Gray
    Write-Host "RUNNING" -ForegroundColor Green
    Write-Host "   URL: http://localhost:8090" -ForegroundColor Gray
} catch {
    Write-Host "   Status: " -NoNewline -ForegroundColor Gray
    Write-Host "NOT RUNNING" -ForegroundColor Yellow
    Write-Host "   (This is optional - see setup instructions above)" -ForegroundColor Gray
}

# Final summary
Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
Write-Host " Setup Complete!" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Run the test script:" -ForegroundColor White
Write-Host "   cd backend" -ForegroundColor Gray
Write-Host "   python test_scanner_init.py" -ForegroundColor Gray

Write-Host "`n2. Start the backend server:" -ForegroundColor White
Write-Host "   cd backend" -ForegroundColor Gray
Write-Host "   uvicorn app.main:app --reload" -ForegroundColor Gray

Write-Host "`n3. Try a comprehensive scan:" -ForegroundColor White
Write-Host "   POST /api/v1/scans/comprehensive/start" -ForegroundColor Gray

Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
