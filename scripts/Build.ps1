#Requires -Version 5.1
[CmdletBinding()] param([string]$Version = '1.1.0-rc.1')
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$') { throw 'Invalid package version.' }
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    python -c "import sys; from packaging.version import Version; from rdp_guard import __version__; assert Version(sys.argv[1]) == Version(__version__), 'Package/tag version must match the source version'" $Version
    if ($LASTEXITCODE -ne 0) { throw 'Package/source version mismatch.' }
    python -m PyInstaller --noconfirm --clean rdpguard.spec
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }
    & '.\dist\RDPGuard\rdpguard.exe' --version
    if ($LASTEXITCODE -ne 0) { throw 'Frozen executable smoke test failed.' }
    $Staging = Join-Path 'dist' "RDPGuard-$Version-win-x64"
    New-Item -ItemType Directory $Staging -Force | Out-Null
    Copy-Item 'dist\RDPGuard' $Staging -Recurse -Force
    Copy-Item 'scripts\Install.ps1','scripts\Update.ps1','scripts\Uninstall.ps1','scripts\Health.ps1','scripts\Emergency-Disable.ps1','scripts\WatchdogTask.ps1','README.md' $Staging
    Copy-Item 'docs' $Staging -Recurse -Force
    python -m pip freeze | Set-Content (Join-Path $Staging 'DEPENDENCIES.txt') -Encoding UTF8
    $Archive = "$Staging.zip"
    Compress-Archive -Path "$Staging\*" -DestinationPath $Archive -Force
    $Hash = (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$Hash  $(Split-Path $Archive -Leaf)" | Set-Content "$Archive.sha256" -Encoding ASCII
    Write-Host "Built $Archive"
} finally { Pop-Location }
