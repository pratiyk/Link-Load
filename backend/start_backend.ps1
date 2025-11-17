# Enhanced Backend Startup Script with Verbose Logging
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting Link-Load Backend Server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Force UTF-8 console encoding so scanner CLIs can emit ASCII art/logs without errors
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8

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

# Ensure UTF-8 for CLI scanners (Wapiti banner prints non-ASCII)
if (-not $env:PYTHONIOENCODING) {
    $env:PYTHONIOENCODING = "utf-8"
    Write-Host "[INFO] PYTHONIOENCODING set to utf-8 for scanner compatibility" -ForegroundColor Green
}

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

# Helper to validate scanner binaries
function Test-ScannerBinary {
    param(
        [string]$Name,
        [string]$Path,
        [string[]]$VersionArgs
    )

    if (-not $Path) {
        Write-Warning "$Name path not provided in environment variables"
        return
    }
    if (-not (Test-Path $Path)) {
        Write-Warning "$Name binary not found at $Path"
        return
    }
    try {
        Write-Host "[INFO] Validating $Name binary..." -ForegroundColor Green
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $Path
        $processInfo.Arguments = ($VersionArgs -join ' ')
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        $process = [System.Diagnostics.Process]::Start($processInfo)
        if ($process.WaitForExit(15000)) {
            $stdOut = $process.StandardOutput.ReadToEnd().Trim()
            $stdErr = $process.StandardError.ReadToEnd().Trim()
            if ($process.ExitCode -eq 0) {
                Write-Host "[SUCCESS] $Name is ready" -ForegroundColor Green
            } else {
                Write-Warning "$Name exited with code $($process.ExitCode)."
                if ($stdOut) {
                    Write-Host "[STDOUT] $stdOut" -ForegroundColor DarkGray
                }
                if ($stdErr) {
                    Write-Warning "[STDERR] $stdErr"
                }
            }
        } else {
            $process.Kill()
            Write-Warning "$Name validation timed out"
        }
    } catch {
        Write-Warning "Failed to validate ${Name}: $($_.Exception.Message)"
    }
}

# Ensure OWASP ZAP daemon is running
Write-Host "" 
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Ensuring OWASP ZAP Daemon Is Running" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($env:ZAP_BASE_URL)) {
    $zapUrl = "http://localhost:8090"
    Write-Host "[INFO] ZAP_BASE_URL not configured. Using default http://localhost:8090" -ForegroundColor Yellow
} else {
    $zapUrl = $env:ZAP_BASE_URL
}
try {
    $zapUri = [System.Uri]$zapUrl
    $zapPort = $zapUri.Port
    $zapHost = $zapUri.Host
} catch {
    Write-Warning "Invalid ZAP_BASE_URL '$zapUrl', defaulting to http://localhost:8090"
    $zapUri = [System.Uri]"http://localhost:8090"
    $zapPort = 8090
    $zapHost = "localhost"
}

Write-Host "[INFO] Target ZAP endpoint: $($zapUri.AbsoluteUri)" -ForegroundColor Green
$zapConnection = Get-NetTCPConnection -LocalPort $zapPort -ErrorAction SilentlyContinue
if ($zapConnection) {
    Write-Host "[SUCCESS] ZAP already listening on port $zapPort (PID $($zapConnection.OwningProcess))" -ForegroundColor Green
} else {
    $repoRoot = Split-Path $scriptDir -Parent
    $zapBat = Join-Path $repoRoot "tools/zap/ZAP_2.15.0/zap.bat"
    if (-not (Test-Path $zapBat)) {
        Write-Warning "OWASP ZAP launcher not found at $zapBat. Please install or update ZAP." 
    } else {
        Write-Host "[INFO] Starting OWASP ZAP daemon..." -ForegroundColor Yellow
        $zapArgs = @("-daemon", "-port", $zapPort)
        if ($env:ZAP_API_KEY) {
            $zapArgs += @("-config", "api.key=$($env:ZAP_API_KEY)")
        }
        Start-Process -FilePath $zapBat -ArgumentList $zapArgs -WorkingDirectory (Split-Path $zapBat) -WindowStyle Hidden
        # Wait for ZAP to open the port (max 45 seconds)
        $zapReady = $false
        for ($i = 0; $i -lt 45; $i++) {
            Start-Sleep -Seconds 1
            if (Get-NetTCPConnection -LocalPort $zapPort -ErrorAction SilentlyContinue) {
                $zapReady = $true
                break
            }
        }
        if ($zapReady) {
            Write-Host "[SUCCESS] ZAP is now listening on port $zapPort" -ForegroundColor Green
        } else {
            Write-Warning "ZAP did not open port $zapPort within 45 seconds. Backend scans may fail."
        }
    }
}

# Validate Nuclei scanner
Write-Host "" 
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Validating Nuclei Scanner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
$nucleiPath = $env:NUCLEI_BINARY_PATH
Test-ScannerBinary -Name "Nuclei" -Path $nucleiPath -VersionArgs @("-version")
if ($env:NUCLEI_TEMPLATES_PATH -and (Test-Path $env:NUCLEI_TEMPLATES_PATH)) {
    Write-Host "[SUCCESS] Nuclei templates directory present at $($env:NUCLEI_TEMPLATES_PATH)" -ForegroundColor Green
} elseif ($env:NUCLEI_TEMPLATES_PATH) {
    Write-Warning "Configured Nuclei templates path not found: $($env:NUCLEI_TEMPLATES_PATH)"
}

# Validate Wapiti scanner
Write-Host "" 
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Validating Wapiti Scanner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
$wapitiPath = $env:WAPITI_BINARY_PATH
Test-ScannerBinary -Name "Wapiti" -Path $wapitiPath -VersionArgs @("--version")

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
