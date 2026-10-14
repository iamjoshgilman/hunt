<#
    Windows-only smoke test. Unlike run.ps1 and plays.ps1, nothing is mocked:
    this drives EventLogReader against the host's real channels. It is what
    catches Windows-only breakage, such as the event-log XPath dialect
    rejecting XML entities in a time filter.

    Assertions are deliberately shape-based, not count-based, because a fresh
    runner's channels may be nearly empty.
#>
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'hunt.ps1')

$fails = 0
function Check($name, $cond, $detail) {
    if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
    else { Write-Host "  FAIL  $name  $detail" -ForegroundColor Red; $script:fails++ }
}

Write-Host ''
Write-Host "  host: $env:COMPUTERNAME   PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Yellow

Write-Host "`n== discovery surfaces =="
Check 'version'  ((hunt version) -match '^hunt \d+\.\d+') ''
$out = (hunt 6>&1 | Out-String)
Check 'bare help' ($out -match 'GRAMMAR' -and $out -match 'hunt where') ''
$out = (hunt sources 6>&1 | Out-String)
Check 'sources lists channels' ($out -match 'system' -and $out -match 'security') ''
Check 'sources shows real counts' ($out -match '\d{2,}') 'no multi-digit record count found'
$out = (hunt ids 4625 6>&1 | Out-String)
Check 'ids reverse lookup' ($out -match 'Logon failure') ''
$out = (hunt where ransomware 6>&1 | Out-String)
Check 'where concept index' ($out -match 'shadow') ''

Write-Host "`n== real queries against live channels =="
$r = @(hunt system -Max 5)
Check 'system returns records' ($r.Count -gt 0) "got $($r.Count)"
if ($r.Count -gt 0) {
    Check 'Time is set'        (-not [string]::IsNullOrWhiteSpace($r[0].Time)) ''
    Check 'Id is an int'       ($r[0].Id -is [int] -and $r[0].Id -gt 0) "got $($r[0].Id)"
    Check 'Event is described' (-not [string]::IsNullOrWhiteSpace($r[0].Event)) ''
    Check 'TimeCreated typed'  ($r[0].TimeCreated -is [datetime]) "got $($r[0].TimeCreated.GetType().Name)"
    Check 'Data present'       ($null -ne $r[0].Data) ''
    Check 'Record kept'        ($null -ne $r[0].Record) ''
    # Some providers have no message resource, so Message can be null; what
    # matters is that the lazy property exists and does not throw.
    Check 'Message property exists' ($r[0].PSObject.Properties.Name -contains 'Message') ''
    Check 'Level property exists'   ($r[0].PSObject.Properties.Name -contains 'Level') ''
    Check 'Computer set'       (-not [string]::IsNullOrWhiteSpace($r[0].Computer)) ''
}

Write-Host "`n== pushdown actually works against the log =="
# This is the regression guard for the XPath entity bug: a time-filtered query
# must run and must not return events older than the window.
$r = @(hunt system -Last 365d -Max 10)
Check 'time window query runs' ($null -ne $r) ''
$cut = (Get-Date).AddDays(-365)
$bad = @($r | Where-Object { $_.TimeCreated -lt $cut })
Check 'time window is honoured' ($bad.Count -eq 0) "$($bad.Count) records older than the window"

$r = @(hunt system -Last 1s -Max 5)
Check 'tiny window does not throw' ($r.Count -ge 0) ''

$r = @(hunt system -Id 6005 -Max 3)
Check 'id filter runs' ($r.Count -ge 0) ''
$wrong = @($r | Where-Object { $_.Id -ne 6005 })
Check 'id filter is honoured' ($wrong.Count -eq 0) "$($wrong.Count) records with the wrong id"

$r = @(hunt system -Id 6005,6006 -Max 6)
$wrong = @($r | Where-Object { $_.Id -notin @(6005, 6006) })
Check 'multi-id filter honoured' ($wrong.Count -eq 0) "$($wrong.Count) off-list records"

Write-Host "`n== keyword matching on real data =="
Check 'no-match returns nothing' (@(hunt system zzqqxxnomatch -Max 5).Count -eq 0) ''
$r = @(hunt system -Id 6005 -Max 200)
if ($r.Count -gt 0) {
    Check 'oldest flag runs' (@(hunt system -Id 6005 -Max 3 -Oldest).Count -ge 1) ''
}

Write-Host "`n== output modes on real data =="
Check 'raw'   (@(hunt system -Max 3 -Raw).Count -ge 1) ''
Check 'full'  (@(hunt system -Max 3 -Full)[0].PSObject.Properties.Name -contains 'Message') ''
Check 'show'  (@(hunt system -Max 3 -Show Computer)[0].PSObject.Properties.Name -contains 'Computer') ''
$c = @(hunt system -Count Computer -Last 365d)
Check 'count returns pairs' ($c.Count -eq 0 -or ($c[0].PSObject.Properties.Name -contains 'Count')) ''

Write-Host "`n== graceful failure =="
# A channel that cannot exist: this must warn, never silently return nothing.
$w = @()
hunt 'No-Such-Channel/Nope' x -WarningVariable w -WarningAction SilentlyContinue | Out-Null
Check 'bogus channel warns' ($w.Count -ge 1) 'a missing channel returned silently'
Check 'bogus warning is actionable' (($w -join ' ') -match 'channel|sources') "got: $($w -join '; ')"

# Sysmon may or may not be installed on the host running this; assert whichever
# branch applies, because both are behaviour worth guarding.
$sysmonHere = $null -ne (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
$w = @()
$r = @(hunt sysmon zzqqxxnomatch -WarningVariable w -WarningAction SilentlyContinue)
if ($sysmonHere) {
    Check 'sysmon present: no spurious warning' ($w.Count -eq 0) "got: $($w -join '; ')"
    Check 'sysmon present: query ran'           ($r.Count -eq 0) ''
} else {
    Check 'sysmon absent: warns'      ($w.Count -ge 1) 'expected a warning about the Sysmon channel'
    Check 'sysmon absent: points at 4688' (($w -join ' ') -match '4688') "got: $($w -join '; ')"
}

Write-Host "`n== a couple of plays end to end =="
foreach ($p in @('boot', 'audit', 'svc', 'logons', 'newusers')) {
    $err = $null
    try { $null = Invoke-Hunt play $p -Max 3 -WarningAction SilentlyContinue }
    catch { $err = $_.Exception.Message }
    Check "play $p" ($null -eq $err) $err
}

Write-Host ''
if ($fails -eq 0) { Write-Host 'SMOKE TESTS PASSED' -ForegroundColor Green; exit 0 }
else { Write-Host "$fails FAILURES" -ForegroundColor Red; exit 1 }
