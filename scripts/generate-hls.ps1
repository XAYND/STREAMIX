Write-Host "=== STREAM-IX HLS AES-128 Generator ===" -ForegroundColor Cyan

$projectRoot = Resolve-Path "$PSScriptRoot\.."
$sourceVideo = Join-Path $projectRoot "demo.mp4"
$hlsDir = Join-Path $projectRoot "media\hls"
$keyPath = Join-Path $projectRoot "enc.key"
$keyInfoPath = Join-Path $projectRoot "key_info.txt"
$manifestPath = Join-Path $hlsDir "video.m3u8"
$segmentPattern = Join-Path $hlsDir "segment_%03d.ts"

if (-not (Get-Command ffmpeg -ErrorAction SilentlyContinue)) {
    Write-Host "Erreur : ffmpeg n'est pas installe ou pas dans le PATH." -ForegroundColor Red
    exit 1
}

if (!(Test-Path $sourceVideo)) {
    Write-Host "Erreur : demo.mp4 est introuvable a la racine du projet." -ForegroundColor Red
    Write-Host "Ajoutez une video nommee demo.mp4 puis relancez le script." -ForegroundColor Yellow
    exit 1
}

if (!(Test-Path $hlsDir)) {
    New-Item -ItemType Directory -Path $hlsDir -Force | Out-Null
}

Write-Host "Nettoyage des anciens fichiers HLS..." -ForegroundColor Yellow
Remove-Item (Join-Path $hlsDir "*.ts") -Force -ErrorAction SilentlyContinue
Remove-Item $manifestPath -Force -ErrorAction SilentlyContinue

if (!(Test-Path $keyPath)) {
    Write-Host "Generation d'une nouvelle cle AES-128..." -ForegroundColor Yellow
    [byte[]]$key = 1..16 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }
    [System.IO.File]::WriteAllBytes($keyPath, $key)
} else {
    Write-Host "Cle AES existante detectee : enc.key" -ForegroundColor Green
}

Write-Host "Creation du fichier key_info.txt..." -ForegroundColor Yellow

@(
    "https://localhost:3001/key",
    $keyPath
) | Set-Content -Encoding ASCII $keyInfoPath

Write-Host "Conversion de demo.mp4 en HLS chiffre AES-128..." -ForegroundColor Cyan

ffmpeg -i $sourceVideo `
  -hls_time 6 `
  -hls_key_info_file $keyInfoPath `
  -hls_playlist_type vod `
  -hls_segment_filename $segmentPattern `
  $manifestPath

if ($LASTEXITCODE -eq 0) {
    Write-Host "Succes : flux HLS AES-128 genere dans le dossier media/hls/" -ForegroundColor Green
    Write-Host "Manifest local : https://localhost:8443/hls/video.m3u8" -ForegroundColor Cyan
} else {
    Write-Host "Erreur pendant la generation HLS." -ForegroundColor Red
    exit 1
}