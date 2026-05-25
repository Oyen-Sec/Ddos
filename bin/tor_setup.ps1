# Tor Auto-Installer v8.0 for Windows
# PowerShell script for Windows Tor installation

Write-Host "--------------------------------------------------------------------------------"
Write-Host "Tor Auto-Installer v8.0 for Windows"
Write-Host "--------------------------------------------------------------------------------"

# Check if Tor is already installed
$torPath = Get-Command tor.exe -ErrorAction SilentlyContinue
if ($torPath) {
    Write-Host "Tor is already installed: $($torPath.Source)"
    exit 0
}

# Check local bin/tor.exe
if (Test-Path "bin\tor.exe") {
    Write-Host "Tor found in bin\tor.exe"
    exit 0
}

Write-Host "Downloading Tor Expert Bundle..."

# Tor download URLs (try multiple mirrors)
$urls = @(
    "https://dist.torproject.org/torbrowser/14.0/tor-expert-bundle-windows-x86_64-14.0.tar.gz",
    "https://archive.torproject.org/tor-package-archive/torbrowser/14.0/tor-expert-bundle-windows-x86_64-14.0.tar.gz"
)

$tarPath = "bin\tor-bundle.tar.gz"
$downloaded = $false

# Create bin directory
New-Item -ItemType Directory -Force -Path "bin" | Out-Null

foreach ($url in $urls) {
    try {
        Write-Host "Trying: $url"
        Invoke-WebRequest -Uri $url -OutFile $tarPath -TimeoutSec 300
        $downloaded = $true
        Write-Host "Download successful!"
        break
    }
    catch {
        Write-Host "Download failed: $_"
        continue
    }
}

if (-not $downloaded) {
    Write-Host "ERROR: All download URLs failed"
    exit 1
}

Write-Host "Extracting Tor bundle..."

# Extract tar.gz using tar (Windows 10+ has built-in tar)
try {
    tar -xzf $tarPath -C bin\
    Write-Host "Extraction successful!"
}
catch {
    Write-Host "ERROR: Extraction failed: $_"
    exit 1
}

# Find tor.exe in extracted files
$torExe = Get-ChildItem -Path "bin\" -Filter "tor.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

if ($torExe) {
    # Move tor.exe to bin\
    Move-Item -Path $torExe.FullName -Destination "bin\tor.exe" -Force
    Write-Host "Tor installed: bin\tor.exe"
    
    # Clean up tar file
    Remove-Item $tarPath -Force
    
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "Tor installation successful!"
    Write-Host "Location: bin\tor.exe"
    Write-Host "--------------------------------------------------------------------------------"
}
else {
    Write-Host "ERROR: tor.exe not found in bundle"
    exit 1
}
