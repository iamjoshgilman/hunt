<#
    Installs hunt into the current user's module path and wires up the profile.

        iex (irm https://raw.githubusercontent.com/iamjoshgilman/hunt/main/install.ps1)

    For a box you do not want to touch, skip this and just load it for the
    session:

        iex (irm https://raw.githubusercontent.com/iamjoshgilman/hunt/main/hunt.ps1)
#>
[CmdletBinding()]
param(
    [string]$Repo = 'iamjoshgilman/hunt',
    [string]$Branch = 'main',
    [switch]$NoProfile
)

$ErrorActionPreference = 'Stop'
$base = "https://raw.githubusercontent.com/$Repo/$Branch"
$dest = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules\Hunt'
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $dest = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules\Hunt'
}

New-Item -ItemType Directory -Path $dest -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

foreach ($f in @('hunt.ps1','Hunt.psm1','Hunt.psd1')) {
    Write-Host "  fetching $f" -ForegroundColor DarkGray
    Invoke-WebRequest -Uri "$base/$f" -OutFile (Join-Path $dest $f) -UseBasicParsing
}

Import-Module (Join-Path $dest 'Hunt.psd1') -Force -Global

if (-not $NoProfile) {
    $line = 'Import-Module Hunt -ErrorAction SilentlyContinue'
    if (-not (Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force | Out-Null }
    if ((Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue) -notmatch 'Import-Module Hunt') {
        Add-Content -Path $PROFILE -Value $line
        Write-Host "  added to $PROFILE" -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host "  installed to $dest" -ForegroundColor Green
Write-Host '  start with:  hunt' -ForegroundColor Green
Write-Host ''
