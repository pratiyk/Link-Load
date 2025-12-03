# OWASP ZAP Daemon Startup Script for Windows
# This script starts ZAP in daemon mode (headless) for API-based scanning

$ZAP_DIR = "$PSScriptRoot\ZAP_2.15.0"
$ZAP_JAR = "$ZAP_DIR\zap-2.15.0.jar"
$ZAP_PORT = 8080
$ZAP_API_KEY = "1cgbmrgk5k1rk3ijv26ojgnlou"
$ZAP_HOME = "$env:USERPROFILE\ZAP"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   OWASP ZAP Daemon Startup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if Java is installed
try {
    $javaVersion = java -version 2>&1
    Write-Host "[OK] Java found" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Java is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Java 11 or later from: https://adoptium.net/" -ForegroundColor Yellow
    exit 1
}

# Check if ZAP JAR exists
if (-not (Test-Path $ZAP_JAR)) {
    Write-Host "[ERROR] ZAP JAR not found at: $ZAP_JAR" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] ZAP JAR found: $ZAP_JAR" -ForegroundColor Green

# Create ZAP home directory if it doesn't exist
if (-not (Test-Path $ZAP_HOME)) {
    New-Item -ItemType Directory -Path $ZAP_HOME -Force | Out-Null
    Write-Host "[OK] Created ZAP home directory: $ZAP_HOME" -ForegroundColor Green
}

# Check if ZAP is already running
$existingProcess = Get-NetTCPConnection -LocalPort $ZAP_PORT -State Listen -ErrorAction SilentlyContinue
if ($existingProcess) {
    Write-Host "[WARN] Port $ZAP_PORT is already in use. ZAP may already be running." -ForegroundColor Yellow
    Write-Host "       Use 'netstat -aon | Select-String $ZAP_PORT' to check" -ForegroundColor Yellow
    
    $response = Read-Host "Do you want to continue anyway? (y/n)"
    if ($response -ne 'y') {
        exit 0
    }
}

# Read JVM options if they exist
$jvmOpts = "-Xmx1g"
$jvmPropsFile = "$ZAP_HOME\.ZAP_JVM.properties"
if (Test-Path $jvmPropsFile) {
    $jvmOpts = Get-Content $jvmPropsFile -Raw
    Write-Host "[OK] Using JVM options from: $jvmPropsFile" -ForegroundColor Green
}

Write-Host ""
Write-Host "Starting OWASP ZAP in daemon mode..." -ForegroundColor Cyan
Write-Host "  Port: $ZAP_PORT" -ForegroundColor White
Write-Host "  API Key: $ZAP_API_KEY" -ForegroundColor White
Write-Host "  Home: $ZAP_HOME" -ForegroundColor White
Write-Host ""
Write-Host "ZAP API will be available at: http://localhost:$ZAP_PORT" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop ZAP" -ForegroundColor Yellow
Write-Host ""

# Start ZAP in daemon mode
# -daemon: Run in daemon mode (no GUI)
# -host: Listen on all interfaces
# -port: API port
# -config api.key: Set API key
# -config api.addrs.addr.regex=true -config api.addrs.addr.name=.*: Allow all addresses
# -config api.disablekey=false: Require API key
Set-Location $ZAP_DIR

# Run ZAP with inline arguments (arrays with -config don't work well)
$cmd = "java $jvmOpts -jar `"$ZAP_JAR`" -daemon -host 0.0.0.0 -port $ZAP_PORT -config api.key=$ZAP_API_KEY -config api.addrs.addr.regex=true -config `"api.addrs.addr.name=.*`" -config api.disablekey=false"
Write-Host "Running: $cmd" -ForegroundColor DarkGray
Invoke-Expression $cmd
