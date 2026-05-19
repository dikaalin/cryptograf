<#
.SYNOPSIS
    Builds Cryptograf for Windows and creates the NSIS installer.

.DESCRIPTION
    Runs from the project root in a Developer Command Prompt for VS 2022.
    Requires: CMake, Qt 6, OpenSSL, NSIS (makensis on PATH).

.EXAMPLE
    # Auto-detect Qt and OpenSSL:
    .\installer\stage.ps1

    # Specify paths explicitly:
    .\installer\stage.ps1 -QtDir "C:\Qt\6.7.3\msvc2022_64" `
                          -OpenSSL "C:\Program Files\OpenSSL-Win64"
#>

param(
    [string]$QtDir    = $env:QTDIR,
    [string]$OpenSSL  = '',
    [string]$BuildDir = 'build',
    [string]$DistDir  = 'dist'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Step([string]$msg) {
    Write-Host "`n━━━ $msg ━━━" -ForegroundColor Cyan
}
function Ok([string]$msg) {
    Write-Host "  ✓ $msg" -ForegroundColor Green
}

# ── Locate OpenSSL ────────────────────────────────────────────────────────────
if (-not $OpenSSL) {
    $OpenSSL = @(
        'C:\Program Files\OpenSSL-Win64',
        'C:\OpenSSL-Win64',
        'C:\Program Files\OpenSSL'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $OpenSSL) {
    throw 'OpenSSL not found. Install via: choco install openssl'
}
Ok "OpenSSL  : $OpenSSL"
if ($QtDir) { Ok "Qt       : $QtDir" }

# ── 1. Configure ──────────────────────────────────────────────────────────────
Step 'Configure'
$cmakeArgs = @('-B', $BuildDir,
               '-G', 'Visual Studio 17 2022', '-A', 'x64',
               "-DOPENSSL_ROOT_DIR=$OpenSSL")
if ($QtDir) { $cmakeArgs += "-DCMAKE_PREFIX_PATH=$QtDir" }
cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { throw 'cmake configure failed' }

# ── 2. Build ──────────────────────────────────────────────────────────────────
Step 'Build (Release)'
cmake --build $BuildDir --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw 'cmake build failed' }

# ── 3. Stage ──────────────────────────────────────────────────────────────────
Step "Stage → $DistDir\"
Remove-Item $DistDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $DistDir | Out-Null

# Executables
Copy-Item "$BuildDir\Release\cryptograf-gui.exe" $DistDir\
if (Test-Path "$BuildDir\Release\cryptograf.exe") {
    Copy-Item "$BuildDir\Release\cryptograf.exe" $DistDir\
    Ok 'cryptograf.exe (CLI) included'
}

# Qt DLLs and plugin directories (written by windeployqt6 at POST_BUILD)
Get-ChildItem "$BuildDir\Release\" -Filter '*.dll' |
    Copy-Item -Destination $DistDir\
foreach ($d in @('platforms', 'styles', 'iconengines', 'imageformats',
                 'networkinformation', 'tls', 'generic')) {
    $src = "$BuildDir\Release\$d"
    if (Test-Path $src) {
        Copy-Item $src $DistDir\ -Recurse -Force
        Ok "Qt plugin dir: $d\"
    }
}

# OpenSSL runtime DLLs
$sslBin = "$OpenSSL\bin"
if (-not (Test-Path $sslBin)) { throw "OpenSSL bin dir not found: $sslBin" }
$copied = 0
Get-ChildItem $sslBin -Filter 'libssl*.dll'    | ForEach-Object {
    Copy-Item $_.FullName $DistDir\; $copied++
}
Get-ChildItem $sslBin -Filter 'libcrypto*.dll' | ForEach-Object {
    Copy-Item $_.FullName $DistDir\; $copied++
}
Ok "OpenSSL DLLs: $copied file(s) copied"

$total = (Get-ChildItem $DistDir -Recurse -File).Count
Ok "Total staged: $total files"

# ── 4. NSIS installer ─────────────────────────────────────────────────────────
Step 'NSIS'
if (-not (Get-Command makensis -ErrorAction SilentlyContinue)) {
    throw 'makensis not found — download NSIS from https://nsis.sourceforge.io/'
}

# Run from project root so "dist\" and "LICENSE" in the .nsi resolve correctly
makensis installer\cryptograf.nsi
if ($LASTEXITCODE -ne 0) { throw 'makensis failed' }

Step 'Done'
$size = [math]::Round((Get-Item 'Cryptograf-Setup.exe').Length / 1MB, 1)
Write-Host "  Cryptograf-Setup.exe  ($size MB)" -ForegroundColor Yellow
