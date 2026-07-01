Write-Host "=== STREAM-IX START ===" -ForegroundColor Cyan

Write-Host "`n[1/5] Checking Docker..." -ForegroundColor Yellow
docker --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker is not installed or not running." -ForegroundColor Red
    exit 1
}

Write-Host "`n[2/5] Checking HTTPS certificates..." -ForegroundColor Yellow

if (!(Test-Path ".\certs")) {
    New-Item -ItemType Directory -Path ".\certs" | Out-Null
}

$certFile = ".\certs\localhost.pem"
$keyFile = ".\certs\localhost-key.pem"

if (!(Test-Path $certFile) -or !(Test-Path $keyFile)) {
    Write-Host "Certificates not found. Generating local HTTPS certificates with mkcert..." -ForegroundColor Yellow

    mkcert -install
    mkcert -key-file certs\localhost-key.pem -cert-file certs\localhost.pem localhost 127.0.0.1 ::1

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to generate certificates. Please install mkcert first." -ForegroundColor Red
        Write-Host "Command: winget install FiloSottile.mkcert" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "HTTPS certificates found." -ForegroundColor Green
}

Write-Host "`n[3/5] Starting Nginx HTTPS with Docker Compose..." -ForegroundColor Yellow
docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to start Docker Compose." -ForegroundColor Red
    exit 1
}

Write-Host "`n[4/5] Installing key-server dependencies if needed..." -ForegroundColor Yellow
Push-Location .\backend\key-server
if (!(Test-Path ".\node_modules")) {
    npm install
}
Pop-Location

Write-Host "`n[5/5] Starting HTTPS key-server..." -ForegroundColor Yellow
Write-Host "Dashboard will be available at:" -ForegroundColor Green
Write-Host "https://localhost:8443/hls/dashboard.html" -ForegroundColor Cyan

Start-Process "https://localhost:8443/hls/dashboard.html?v=1"

node .\backend\key-server\server.js