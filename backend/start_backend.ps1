# Enhanced Backend Startup Script with Verbose Logging
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting Link-Load Backend Server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$scriptDir = $PSScriptRoot
Write-Host "[INFO] Script directory: $scriptDir" -ForegroundColor Green

# Load environment variables from .env file
$envPath = Join-Path $scriptDir ".env"
Write-Host "[INFO] Looking for .env file at: $envPath" -ForegroundColor Green

if (Test-Path $envPath) {
    Write-Host "[SUCCESS] Found .env file, loading environment variables..." -ForegroundColor Green
    $envCount = 0
    Get-Content $envPath | ForEach-Object {
        if ($_ -match '^([^#].+?)=(.*)$') {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
            $envCount++
            Write-Host "  - Loaded: $name" -ForegroundColor DarkGray
        }
    }
    Write-Host "[SUCCESS] Loaded $envCount environment variables" -ForegroundColor Green
} else {
    Write-Warning "No .env file found at $envPath"
}

# Set PYTHONPATH
$env:PYTHONPATH = $scriptDir
Write-Host "[INFO] PYTHONPATH set to: $env:PYTHONPATH" -ForegroundColor Green

# Check Python executable
$pythonExe = "C:\prateek\projects\linkload\.venv\Scripts\python.exe"
Write-Host "[INFO] Checking Python executable: $pythonExe" -ForegroundColor Green

if (Test-Path $pythonExe) {
    Write-Host "[SUCCESS] Python executable found" -ForegroundColor Green
    $pythonVersion = & $pythonExe --version 2>&1
    Write-Host "[INFO] Python version: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Python executable not found at: $pythonExe" -ForegroundColor Red
    Write-Host "[ERROR] Please ensure the virtual environment is created" -ForegroundColor Red
    exit 1
}

# Check if port 8000 is in use
Write-Host "[INFO] Checking if port 8000 is available..." -ForegroundColor Green
$portCheck = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($portCheck) {
    Write-Host "[WARNING] Port 8000 is in use by process ID: $($portCheck.OwningProcess)" -ForegroundColor Yellow
    Write-Host "[INFO] Attempting to stop existing process..." -ForegroundColor Yellow
    Stop-Process -Id $portCheck.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "[SUCCESS] Stopped existing process" -ForegroundColor Green
} else {
    Write-Host "[SUCCESS] Port 8000 is available" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting Uvicorn Server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[INFO] Server will be available at: http://0.0.0.0:8000" -ForegroundColor Green
Write-Host "[INFO] API docs available at: http://localhost:8000/docs" -ForegroundColor Green
Write-Host "[INFO] Press Ctrl+C to stop the server" -ForegroundColor Green
Write-Host ""

# Start the backend server
try {
    & $pythonExe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
} catch {
    Write-Host ""
    Write-Host "[ERROR] Failed to start backend server" -ForegroundColor Red
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
