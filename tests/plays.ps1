# Resolve relative to this file so the suite runs the same way in a container,
# in CI, and from the repo root.
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'hunt.ps1')
. (Join-Path $PSScriptRoot 'mock.ps1')

$fails = 0
Write-Host "`n== every play executes =="
foreach ($name in $script:HuntPlays.Keys) {
    $err = $null
    try {
        $r = Invoke-Hunt play $name -Max 5 -ErrorAction Stop -WarningAction SilentlyContinue 2>$null
        $n = @($r).Count
        Write-Host ("  PASS  {0,-14} {1} hit(s)" -f $name, $n) -ForegroundColor Green
    } catch {
        Write-Host ("  FAIL  {0,-14} {1}" -f $name, $_.Exception.Message) -ForegroundColor Red
        $fails++
    }
}

Write-Host "`n== play step shapes =="
foreach ($name in $script:HuntPlays.Keys) {
    $play = $script:HuntPlays[$name]
    if (-not $play.Desc) { Write-Host "  FAIL  $name has no Desc" -ForegroundColor Red; $fails++ }
    if (-not $play.Steps -or @($play.Steps).Count -eq 0) { Write-Host "  FAIL  $name has no Steps" -ForegroundColor Red; $fails++ }
    foreach ($step in $play.Steps) {
        foreach ($k in $step.Keys) {
            if ($k -notin @('S','Id','Match','Field','Not','Count','Show')) {
                Write-Host "  FAIL  $name step has unknown key '$k'" -ForegroundColor Red; $fails++
            }
        }
        if (-not $step.S) { Write-Host "  FAIL  $name step has no source" -ForegroundColor Red; $fails++ }
        $logs = Resolve-HuntSource $step.S
        if (-not ($script:HuntSources.Contains($step.S))) {
            Write-Host "  FAIL  $name step source '$($step.S)' is not a known source" -ForegroundColor Red; $fails++
        }
        # every regex in a step must compile, or it silently degrades to literal
        foreach ($key in @('Match','Not')) {
            if ($step.ContainsKey($key) -and $step[$key]) {
                try { [void](New-Object Text.RegularExpressions.Regex ([string]$step[$key])) }
                catch { Write-Host "  FAIL  $name step $key does not compile: $($_.Exception.Message)" -ForegroundColor Red; $fails++ }
            }
        }
        if ($step.ContainsKey('Field')) {
            foreach ($f in @($step.Field)) {
                if ($f -notmatch '.+!?=.+') { Write-Host "  FAIL  $name field spec '$f' is malformed" -ForegroundColor Red; $fails++ }
                $pat = $f.Substring($f.IndexOf('=') + 1)
                try { [void](New-Object Text.RegularExpressions.Regex $pat) }
                catch { Write-Host "  FAIL  $name field regex '$pat' does not compile" -ForegroundColor Red; $fails++ }
            }
        }
    }
}
if ($fails -eq 0) { Write-Host "  PASS  all $($script:HuntPlays.Count) plays well-formed" -ForegroundColor Green }

Write-Host "`n== index regexes compile =="
foreach ($e in $script:HuntIndex) {
    try { [void](New-Object Text.RegularExpressions.Regex ([string]$e.T)) }
    catch { Write-Host "  FAIL  index '$($e.Run)': $($_.Exception.Message)" -ForegroundColor Red; $fails++ }
    if ($e.Run -match '^hunt play (\w+)$') {
        if (-not $script:HuntPlays.Contains($Matches[1])) {
            Write-Host "  FAIL  index points at missing play '$($Matches[1])'" -ForegroundColor Red; $fails++
        }
    }
}
Write-Host "  checked $($script:HuntIndex.Count) index entries"

Write-Host "`n== detail map keys reference real sources =="
foreach ($k in $script:HuntDetail.Keys) {
    $src = $k.Split(':')[0]
    if (-not $script:HuntIds.ContainsKey($src) -and -not $script:HuntSources.Contains($src)) {
        Write-Host "  FAIL  detail key '$k' has unknown source" -ForegroundColor Red; $fails++
    }
}

Write-Host "`n== show columns via a play =="
$r = Invoke-Hunt play tree -Max 3 -WarningAction SilentlyContinue
if (@($r).Count -gt 0 -and ($r[0].PSObject.Properties.Name -contains 'ParentImage')) {
    Write-Host '  PASS  play-defined -Show applied' -ForegroundColor Green
} else {
    Write-Host "  FAIL  play tree columns: $(@($r)[0].PSObject.Properties.Name -join ',')" -ForegroundColor Red; $fails++
}

Write-Host ''
if ($fails -eq 0) { Write-Host 'PLAY SUITE PASSED' -ForegroundColor Green } else { Write-Host "$fails FAILURES" -ForegroundColor Red; exit 1 }
