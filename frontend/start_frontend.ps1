# Enhanced Frontend Startup Script
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting Link-Load Frontend" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Move to repo frontend directory
$scriptDir = $PSScriptRoot
Set-Location $scriptDir
Write-Host "[INFO] Working directory: $scriptDir" -ForegroundColor Green

# Ensure Node.js is available
try {
	$nodeVersion = & node --version 2>$null
	Write-Host "[SUCCESS] Node version detected: $nodeVersion" -ForegroundColor Green
} catch {
	Write-Host "[ERROR] Node.js not found. Please install Node 18+ and add it to PATH." -ForegroundColor Red
	exit 1
}

# Install npm dependencies if node_modules missing
if (-not (Test-Path (Join-Path $scriptDir "node_modules"))) {
	Write-Host "[INFO] Installing npm dependencies (node_modules missing)..." -ForegroundColor Yellow
	npm install
} else {
	Write-Host "[INFO] node_modules found, skipping npm install" -ForegroundColor Green
}

# Ensure backend API URL is reachable (optional)
$apiUrl = $env:VITE_API_URL
if (-not $apiUrl) {
	$apiUrl = "http://localhost:8000"
	Write-Host "[WARN] VITE_API_URL not set. Defaulting to $apiUrl" -ForegroundColor Yellow
}
Write-Host "[INFO] Using API URL: $apiUrl" -ForegroundColor Green

# Check if frontend port is free
$port = 3000
Write-Host "[INFO] Checking if port $port is available..." -ForegroundColor Green
$portCheck = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
if ($portCheck) {
	Write-Warning "Port $port currently in use by PID $($portCheck.OwningProcess). Attempting to stop process."
	try {
		Stop-Process -Id $portCheck.OwningProcess -Force -ErrorAction Stop
		Start-Sleep -Seconds 2
		Write-Host "[SUCCESS] Freed port $port" -ForegroundColor Green
	} catch {
		Write-Host "[ERROR] Unable to free port $port. Please stop the process manually." -ForegroundColor Red
		exit 1
	}
} else {
	Write-Host "[SUCCESS] Port $port is available" -ForegroundColor Green
}

# Start frontend dev server
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Launching npm start" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[INFO] Frontend available at http://localhost:$port" -ForegroundColor Green
Write-Host "[INFO] Press Ctrl+C to stop the frontend" -ForegroundColor Green
Write-Host ""

npm start
