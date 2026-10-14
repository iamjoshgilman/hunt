. /w/hunt.ps1
. /w/tests/mock.ps1

$fails = 0
function Check($name, $cond, $detail) {
    if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
    else { Write-Host "  FAIL  $name  $detail" -ForegroundColor Red; $script:fails++ }
}

Write-Host "`n== time spans =="
Check 'bare = hours'  ((ConvertTo-HuntTimeSpan '6').TotalHours -eq 6) ''
Check '30m'           ((ConvertTo-HuntTimeSpan '30m').TotalMinutes -eq 30) ''
Check '2d'            ((ConvertTo-HuntTimeSpan '2d').TotalDays -eq 2) ''
Check '1w'            ((ConvertTo-HuntTimeSpan '1w').TotalDays -eq 7) ''
$threw = $false
try { ConvertTo-HuntTimeSpan 'banana' | Out-Null } catch { $threw = $true }
Check 'bad span throws' $threw ''

Write-Host "`n== query logic =="
$q = New-HuntQuery @('mimikatz')
Check 'single term'   ((Test-HuntQuery $q 'c:\tools\MIMIKATZ.exe') -and -not (Test-HuntQuery $q 'notepad')) ''
$q = New-HuntQuery @('lsass','dmp')
Check 'AND both'      (Test-HuntQuery $q 'procdump lsass.dmp') ''
Check 'AND one fails' (-not (Test-HuntQuery $q 'lsass only')) ''
$q = New-HuntQuery @('mimikatz','or','rubeus')
Check 'OR left'       (Test-HuntQuery $q 'mimikatz.exe') ''
Check 'OR right'      (Test-HuntQuery $q 'Rubeus.exe') ''
Check 'OR neither'    (-not (Test-HuntQuery $q 'notepad.exe')) ''
$q = New-HuntQuery @('powershell','!svchost')
Check 'NOT excludes'  (-not (Test-HuntQuery $q 'powershell via svchost')) ''
Check 'NOT keeps'     (Test-HuntQuery $q 'powershell.exe -enc') ''
$q = New-HuntQuery @('a','not','b')
Check 'not keyword'   ((Test-HuntQuery $q 'a here') -and -not (Test-HuntQuery $q 'a and b')) ''
$q = New-HuntQuery @('mimikatz,rubeus')
Check 'comma = OR'    ((Test-HuntQuery $q 'rubeus') -and (Test-HuntQuery $q 'mimikatz')) ''
$q = New-HuntQuery @('C:\Users\bob')
Check 'bad regex -> literal' ((Test-HuntQuery $q 'file at C:\Users\bob\x.txt') -and -not (Test-HuntQuery $q 'C:/Users/bob')) ''
Check 'empty query is null' ($null -eq (New-HuntQuery @())) ''

Write-Host "`n== xpath construction =="
Check 'no filter'    ((New-HuntXPath) -eq '*') "got: $(New-HuntXPath)"
$xp = New-HuntXPath -Id @(1,3)
Check 'ids'          ($xp -eq '*[System[(EventID=1 or EventID=3)]]') "got: $xp"
$xp = New-HuntXPath -After ([datetime]'2026-10-12T00:00:00Z')
Check 'raw >= not entity' ($xp -match '@SystemTime>=' -and $xp -notmatch '&gt;') "got: $xp"
Check 'utc iso8601'  ($xp -match "'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z'") "got: $xp"
$xp = New-HuntXPath -Id @(4625) -After ([datetime]'2026-10-12T00:00:00Z') -Before ([datetime]'2026-10-13T00:00:00Z')
Check 'id + both bounds' ($xp -match 'EventID=4625' -and $xp -match '>=' -and $xp -match '<=' -and $xp -match ' and ') "got: $xp"

Write-Host "`n== match text excludes the System block =="
$x = '<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><Computer>WS01</Computer></System><EventData><Data Name="Image">x.exe</Data></EventData></Event>'
$mt = Get-HuntMatchText $x
Check 'keeps event data'   ($mt -match 'x\.exe') ''
Check 'drops system block' ($mt -notmatch 'WS01' -and $mt -notmatch 'Microsoft-Windows-Sysmon') "got: $mt"

Write-Host "`n== source resolution =="
Check 'alias sec'     ((Resolve-HuntSource 'sec') -contains 'Security') ''
Check 'alias ps'      ((Resolve-HuntSource 'ps') -contains 'Microsoft-Windows-PowerShell/Operational') ''
Check 'literal pass'  ((Resolve-HuntSource 'Some-Weird/Channel') -contains 'Some-Weird/Channel') ''
Check 'all is 4 logs' ((Resolve-HuntSource 'all').Count -eq 4) ''
Check 'short name'    ((Get-HuntShortName 'Microsoft-Windows-Sysmon/Operational') -eq 'sysmon') ''

Write-Host "`n== xml / record parsing =="
$ev = $script:MockEvents | Where-Object { $_.Id -eq 10 -and $_.SourceImage -eq $null } | Select-Object -First 1
$e10 = $script:MockEvents | Where-Object { $_.Id -eq 10 } | Select-Object -First 1
$d = ConvertFrom-HuntEventXml $e10
Check 'named fields'  ($d.Contains('TargetImage')) "keys: $($d.Keys -join ',')"
Check 'field value'   ($d['TargetImage'] -match 'lsass\.exe') ''
Check 'not element name' (-not $d.Contains('Data')) 'Data element name leaked as a field'
$r = New-HuntRecord -Event $e10 -Log 'Microsoft-Windows-Sysmon/Operational'
Check 'record id'     ($r.Id -eq 10) ''
Check 'event name'    ($r.Event -match 'Process access') "got: $($r.Event)"
Check 'detail built'  ($r.Detail -match 'lsass') "got: $($r.Detail)"
Check 'flattened'     ($r.TargetImage -match 'lsass') ''
Check 'lazy message'  ($r.Message -match 'Rendered message') ''

Write-Host "`n== search =="
$h = hunt sysmon mimikatz
Check 'keyword hits'  (@($h).Count -eq 2) "got $(@($h).Count)"
$h = hunt sysmon lsass dmp
Check 'AND search'    (@($h).Count -eq 1 -and $h.Id -eq 11) "got $(@($h).Count)"
$h = hunt sysmon -Id 10
Check 'by id'         (@($h).Count -eq 2) "got $(@($h).Count)"
$h = hunt sysmon -Id 10 !svchost
Check 'id + NOT'      (@($h).Count -eq 1) "got $(@($h).Count)"
$h = hunt sysmon -Id 3 -Field DestinationPort=445
Check 'field filter'  (@($h).Count -eq 1) "got $(@($h).Count)"
$h = hunt sysmon -Id 3 -Field 'DestinationPort!=445'
Check 'field exclude' (@($h).Count -eq 0) "got $(@($h).Count)"
$h = hunt sysmon -Id 1 -Max 1
Check 'max caps'      (@($h).Count -eq 1) "got $(@($h).Count)"
$h = hunt security -Id 4625 -Count TargetUserName
Check 'count rows'    (@($h).Count -eq 3) "got $(@($h).Count)"
Check 'count top'     ($h[0].TargetUserName -eq 'alice' -and $h[0].Count -eq 3) "got $($h[0])"
$h = hunt sysmon -Id 1 -Show Image,CommandLine
Check 'show columns'  ($h[0].PSObject.Properties.Name -contains 'CommandLine') ''
$h = hunt system -Id 1074 -Last 2d
Check 'time window in'  (@($h).Count -eq 1) "got $(@($h).Count)"
$h = hunt system -Id 1074 -Last 1h
Check 'time window out' (@($h).Count -eq 0) "got $(@($h).Count)"
$h = hunt sysmon -Id 1 -Raw
Check 'raw keeps Data'  ($h[0].Data.Count -gt 0) ''
$h = hunt sysmon -Id 1 -Full
Check 'full has Message' ($h[0].PSObject.Properties.Name -contains 'Message') ''
$h = hunt sec -Id 4624
Check 'alias searches'  (@($h).Count -eq 1) "got $(@($h).Count)"
$warn = @()
$h = hunt defender something -WarningVariable warn -WarningAction SilentlyContinue
Check 'missing log warns' ($warn.Count -ge 1) "warnings: $($warn.Count)"

Write-Host "`n== empty results in every output mode =="
# a channel that exists but has no matching events
Check 'list empty'    (@(hunt sysmon -Id 1 zzqqxxnomatch).Count -eq 0) ''
Check 'count empty'   (@(hunt sysmon -Id 1 zzqqxxnomatch -Count Image).Count -eq 0) ''
Check 'raw empty'     (@(hunt sysmon -Id 1 zzqqxxnomatch -Raw).Count -eq 0) ''
Check 'full empty'    (@(hunt sysmon -Id 1 zzqqxxnomatch -Full).Count -eq 0) ''
Check 'show empty'    (@(hunt sysmon -Id 1 zzqqxxnomatch -Show Image).Count -eq 0) ''
Check 'field empty'   (@(hunt sysmon -Id 1 -Field 'Image=zzqqxxnomatch').Count -eq 0) ''
Check 'count no match on real id' (@(hunt security -Id 9999 -Count TargetUserName).Count -eq 0) ''
Check 'play empty'    (@(hunt play dcsync).Count -eq 0) ''
Check 'formatter null-safe' ($null -eq (Format-HuntResult -Results $null -Count 'X')) ''

Write-Host "`n== plays =="
$h = hunt play creds
Check 'play creds'    (@($h).Count -eq 1 -and $h.SourceImage -match 'mimikatz') "got $(@($h).Count)"
$h = hunt play dumps
Check 'play dumps'    (@($h).Count -ge 3) "got $(@($h).Count)"
$h = hunt play persist
Check 'play persist'  (@($h).Count -ge 2) "got $(@($h).Count)"
$h = hunt play spray
Check 'play spray'    ($h[0].TargetUserName -eq 'alice') "got $($h[0])"
$h = hunt play psexec
Check 'play psexec'   (@($h).Count -ge 1) "got $(@($h).Count)"
$h = hunt play encoded
Check 'play encoded'  (@($h).Count -ge 1) "got $(@($h).Count)"
$h = hunt play boot
Check 'play boot'     (@($h).Count -ge 1) "got $(@($h).Count)"
$h = hunt play creds -Last 1h
Check 'play honours -Last' (@($h).Count -eq 1) "got $(@($h).Count)"
$h = hunt play procs mimikatz
Check 'play + keyword' (@($h).Count -eq 1) "got $(@($h).Count)"

Write-Host "`n== discovery =="
$out = (hunt where mimikatz 6>&1 | Out-String)
Check 'where mimikatz' ($out -match 'hunt play dumps') ''
$out = (hunt where 'brute force' 6>&1 | Out-String)
Check 'where brute'    ($out -match 'spray') ''
$out = (hunt where ransomware 6>&1 | Out-String)
Check 'where ransom'   ($out -match 'shadow') ''
$out = (hunt where 'turn off defender' 6>&1 | Out-String)
Check 'where tamper'   ($out -match 'tamper') ''
$out = (hunt where zzzznothing 6>&1 | Out-String)
Check 'where miss'     ($out -match 'hunt sysmon zzzznothing') ''
$out = (hunt ids 4625 6>&1 | Out-String)
Check 'ids reverse'    ($out -match 'security' -and $out -match 'Logon failure') ''
$out = (hunt ids 1116 6>&1 | Out-String)
Check 'ids 1116=defender' ($out -match 'defender') ''
$out = (hunt ids sysmon 6>&1 | Out-String)
Check 'ids cheatsheet' ($out -match 'CreateRemoteThread') ''
$out = (hunt ids 'kerberos' 6>&1 | Out-String)
Check 'ids free text'  ($out -match '4769') ''
$out = (hunt plays 6>&1 | Out-String)
Check 'plays list'     ($out -match 'kerberoast' -and $out -match 'persist') ''
$out = (hunt plays cred 6>&1 | Out-String)
Check 'plays filtered' ($out -match 'creds') ''
$out = (hunt play nosuchplay 6>&1 | Out-String)
Check 'bad play lists' ($out -match 'PLAYS') ''
$warn = @()
hunt plays cred -WarningVariable warn -WarningAction SilentlyContinue 6>&1 | Out-Null
Check 'plays search does not warn' ($warn.Count -eq 0) "warnings: $($warn -join '; ')"
$warn = @()
hunt play cred -WarningVariable warn -WarningAction SilentlyContinue 6>&1 | Out-Null
Check 'play run warns on typo' ($warn.Count -ge 1) ''
$out = (hunt 6>&1 | Out-String)
Check 'bare help'      ($out -match 'GRAMMAR' -and $out -match 'hunt where') ''
$out = (hunt help 6>&1 | Out-String)
Check 'help'           ($out -match 'EXAMPLES') ''
$out = (hunt sources 6>&1 | Out-String)
Check 'sources'        ($out -match 'sysmon') ''
Check 'sources counts' ($out -match '\d') ''

Write-Host ''
if ($fails -eq 0) { Write-Host "ALL TESTS PASSED" -ForegroundColor Green }
else { Write-Host "$fails FAILURES" -ForegroundColor Red; exit 1 }
