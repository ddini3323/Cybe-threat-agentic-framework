# CTI Agentic System — Windows Setup Script
# Run once: Right-click > "Run with PowerShell"  OR  powershell -ExecutionPolicy Bypass -File setup.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Print-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Print-OK($msg)   { Write-Host "  OK  $msg" -ForegroundColor Green }
function Print-Warn($msg) { Write-Host "  WARN  $msg" -ForegroundColor Yellow }
function Print-Fail($msg) { Write-Host "  FAIL  $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "================================================" -ForegroundColor Magenta
Write-Host " CTI Agentic System — Auto Setup (Windows)     " -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Magenta

# ── 1. Python check ────────────────────────────────────────────────────────────
Print-Step "Checking Python 3.10+"
try {
    $pyver = python --version 2>&1
    if ($pyver -match "Python (\d+)\.(\d+)") {
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
            Print-Fail "Python 3.10+ required. Found: $pyver. Download from https://python.org"
        }
        Print-OK $pyver
    }
} catch {
    Print-Fail "Python not found. Install from https://python.org then re-run this script."
}

# ── 2. uv install ──────────────────────────────────────────────────────────────
Print-Step "Checking uv (fast Python package manager)"
$uvAvailable = $false
try {
    uv --version | Out-Null
    Print-OK "uv already installed: $(uv --version)"
    $uvAvailable = $true
} catch {
    Print-Warn "uv not found. Installing via pip..."
    pip install uv --quiet
    try {
        uv --version | Out-Null
        Print-OK "uv installed"
        $uvAvailable = $true
    } catch {
        Print-Warn "uv install failed — will fall back to pip"
    }
}

# ── 3. Python dependencies ─────────────────────────────────────────────────────
Print-Step "Installing Python dependencies"
if ($uvAvailable) {
    uv sync
    Print-OK "Dependencies installed via uv"
} else {
    pip install -r requirements.txt
    Print-OK "Dependencies installed via pip"
}

# ── 4. Ollama install ──────────────────────────────────────────────────────────
Print-Step "Checking Ollama"
$ollamaInstalled = $false
try {
    ollama --version | Out-Null
    Print-OK "Ollama already installed: $(ollama --version)"
    $ollamaInstalled = $true
} catch {
    Print-Warn "Ollama not found. Downloading installer..."
    $ollamaInstaller = "$env:TEMP\OllamaSetup.exe"
    Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" `
        -OutFile $ollamaInstaller -UseBasicParsing
    Print-OK "Running Ollama installer (silent)..."
    Start-Process -FilePath $ollamaInstaller -ArgumentList "/SILENT" -Wait
    # Refresh PATH
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH", "User")
    Start-Sleep -Seconds 3
    try {
        ollama --version | Out-Null
        Print-OK "Ollama installed successfully"
        $ollamaInstalled = $true
    } catch {
        Print-Fail "Ollama install failed. Please install manually from https://ollama.com/download then re-run."
    }
}

# ── 5. Start Ollama service ────────────────────────────────────────────────────
Print-Step "Starting Ollama service"
$ollamaRunning = $false
try {
    $resp = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -UseBasicParsing -TimeoutSec 3
    Print-OK "Ollama already running"
    $ollamaRunning = $true
} catch {
    Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden
    Print-OK "Ollama service started (background)"
    Start-Sleep -Seconds 5
}

# ── 6. Pull llama3.2:3b ────────────────────────────────────────────────────────
Print-Step "Pulling llama3.2:3b model (~2 GB, first time only)"
ollama pull llama3.2:3b
Print-OK "llama3.2:3b ready"

# ── 7. Copy .env if missing ────────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Print-OK ".env created from .env.example"
}

# ── Done ───────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host " Setup complete! Starting CTI Agentic System..." -ForegroundColor Green
Write-Host " Dashboard will open at http://localhost:8888   " -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""

if ($uvAvailable) {
    uv run main.py
} else {
    python main.py
}
