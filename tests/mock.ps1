# Mock harness: stands in for Get-WinEvent so the search path can be exercised
# off-Windows. A function outranks a cmdlet of the same name, so hunt.ps1 picks
# this up unchanged.

$script:MockEvents = New-Object Collections.ArrayList

function New-MockEvent {
    param(
        [string]$Log,
        [int]$Id,
        [datetime]$Time,
        [System.Collections.Specialized.OrderedDictionary]$Data,
        [string]$Computer = 'WS01',
        [string]$Provider = 'Mock'
    )
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">')
    [void]$sb.Append("<System><EventID>$Id</EventID><Channel>$Log</Channel>")
    [void]$sb.Append("<Computer>$Computer</Computer></System><EventData>")
    foreach ($k in $Data.Keys) {
        $v = [string]$Data[$k]
        $v = $v.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
        [void]$sb.Append("<Data Name=""$k"">$v</Data>")
    }
    [void]$sb.Append('</EventData></Event>')
    $xml = $sb.ToString()

    $props = @()
    foreach ($k in $Data.Keys) { $props += [pscustomobject]@{ Value = $Data[$k] } }

    $e = [pscustomobject]@{
        Id = $Id; TimeCreated = $Time; MachineName = $Computer; ProviderName = $Provider
        LevelDisplayName = 'Information'; RecordId = [int64](Get-Random -Maximum 99999)
        LogName = $Log; Properties = $props; TaskDisplayName = "Task $Id"
        Message = "Rendered message for event $Id"
    }
    Add-Member -InputObject $e -MemberType ScriptMethod -Name ToXml -Value { $xml }.GetNewClosure()
    [void]$script:MockEvents.Add($e)
    return $e
}

function Get-WinEvent {
    [CmdletBinding()]
    param(
        [hashtable]$FilterHashtable,
        [string]$ListLog,
        [string]$ComputerName,
        $Credential,
        [switch]$Oldest,
        [int]$MaxEvents
    )
    if ($ListLog) {
        $n = @($script:MockEvents | Where-Object { $_.LogName -eq $ListLog }).Count
        if ($n -eq 0) { return }
        return [pscustomobject]@{ LogName = $ListLog; RecordCount = $n }
    }
    $log = $FilterHashtable['LogName']
    $set = @($script:MockEvents | Where-Object { $_.LogName -eq $log })
    if ($set.Count -eq 0) {
        throw "There is not an event log on the localhost computer with that name: $log"
    }
    if ($FilterHashtable.ContainsKey('Id')) {
        $ids = @($FilterHashtable['Id'])
        $set = @($set | Where-Object { $ids -contains $_.Id })
    }
    if ($FilterHashtable.ContainsKey('StartTime')) {
        $st = $FilterHashtable['StartTime']
        $set = @($set | Where-Object { $_.TimeCreated -ge $st })
    }
    if ($FilterHashtable.ContainsKey('EndTime')) {
        $et = $FilterHashtable['EndTime']
        $set = @($set | Where-Object { $_.TimeCreated -le $et })
    }
    if ($set.Count -eq 0) { throw 'No events were found that match the specified selection criteria.' }
    if ($Oldest) { $set = @($set | Sort-Object TimeCreated) }
    else         { $set = @($set | Sort-Object TimeCreated -Descending) }
    foreach ($e in $set) { $e }
}

# ------------------------------------------------------------------ fixtures --
$now = Get-Date
$SY  = 'Microsoft-Windows-Sysmon/Operational'

New-MockEvent -Log $SY -Id 1 -Time $now.AddMinutes(-2) -Data ([ordered]@{
    User='LAB\jdoe'; Image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    CommandLine='powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'
    ParentImage='C:\Windows\System32\cmd.exe' }) | Out-Null

New-MockEvent -Log $SY -Id 1 -Time $now.AddMinutes(-5) -Data ([ordered]@{
    User='LAB\jdoe'; Image='C:\Tools\mimikatz.exe'
    CommandLine='mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'
    ParentImage='C:\Windows\System32\cmd.exe' }) | Out-Null

New-MockEvent -Log $SY -Id 10 -Time $now.AddMinutes(-5) -Data ([ordered]@{
    SourceImage='C:\Tools\mimikatz.exe'; TargetImage='C:\Windows\system32\lsass.exe'
    GrantedAccess='0x1410'; CallTrace='C:\Windows\SYSTEM32\ntdll.dll+9d234' }) | Out-Null

New-MockEvent -Log $SY -Id 10 -Time $now.AddMinutes(-6) -Data ([ordered]@{
    SourceImage='C:\Windows\System32\svchost.exe'; TargetImage='C:\Windows\system32\lsass.exe'
    GrantedAccess='0x1000'; CallTrace='noise' }) | Out-Null

New-MockEvent -Log $SY -Id 11 -Time $now.AddMinutes(-4) -Data ([ordered]@{
    Image='C:\Tools\procdump.exe'; TargetFilename='C:\Users\Public\lsass.dmp' }) | Out-Null

New-MockEvent -Log $SY -Id 3 -Time $now.AddMinutes(-9) -Data ([ordered]@{
    Image='C:\Windows\System32\cmd.exe'; SourceIp='10.77.0.31'
    DestinationIp='10.77.0.50'; DestinationPort='445'; DestinationHostname='kali' }) | Out-Null

New-MockEvent -Log $SY -Id 13 -Time $now.AddMinutes(-20) -Data ([ordered]@{
    Image='C:\Windows\regedit.exe'
    TargetObject='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater'
    Details='C:\Users\Public\evil.exe' }) | Out-Null

foreach ($u in @('alice','alice','alice','bob','svc_sql')) {
    New-MockEvent -Log 'Security' -Id 4625 -Time $now.AddMinutes(-(Get-Random -Maximum 50)) -Data ([ordered]@{
        TargetUserName=$u; LogonType='3'; IpAddress='10.77.0.50'
        WorkstationName='KALI'; Status='0xc000006d'; SubStatus='0xc000006a' }) | Out-Null
}

New-MockEvent -Log 'Security' -Id 4624 -Time $now.AddMinutes(-3) -Data ([ordered]@{
    TargetUserName='adm.lfischer'; LogonType='10'; IpAddress='10.77.0.50'
    WorkstationName='KALI'; ProcessName='C:\Windows\System32\winlogon.exe' }) | Out-Null

New-MockEvent -Log 'System' -Id 7045 -Time $now.AddMinutes(-7) -Data ([ordered]@{
    AccountName='LocalSystem'; ServiceName='PSEXESVC'
    ImagePath='%SystemRoot%\PSEXESVC.exe'; StartType='demand service'; ServiceType='user mode service' }) | Out-Null

New-MockEvent -Log 'System' -Id 1074 -Time $now.AddHours(-30) -Data ([ordered]@{
    param1='C:\Windows\System32\shutdown.exe'; param2='LAB\jdoe'; param3='No title for this reason could be found' }) | Out-Null
