#Requires -Version 5.1
<#
    hunt - threat hunting for Windows event logs, from the command line.

    Search any channel by keyword, event id, field or time window; aggregate
    by any event-data field; or run one of 42 prebuilt hunts.

        hunt sysmon mimikatz            # search event data across a channel
        hunt security -Id 4625          # by event id
        hunt sysmon -Id 3 -Field DestinationPort=445   # by event-data field
        hunt security -Id 4625 -Count TargetUserName   # aggregate
        hunt play creds                 # one of 42 prebuilt hunts
        hunt where ransomware           # when you know what, not where
        hunt ids 4625                   # what is this event, and which log
        hunt sources                    # what you can query here

    Single file, no dependencies, PowerShell 5.1+. Dot-source it or install
    as a module; both expose the 'hunt' alias.
#>

$script:HuntVersion = '0.2.0'

# ---------------------------------------------------------------- catalogue --

$script:HuntSources = [ordered]@{
    sysmon     = [pscustomobject]@{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Desc = 'Processes, network, registry, image loads, pipes' }
    security   = [pscustomobject]@{ Logs = @('Security'); Desc = 'Logons, privilege use, account and policy change (needs admin)' }
    system     = [pscustomobject]@{ Logs = @('System'); Desc = 'Service installs, driver loads, log clears' }
    app        = [pscustomobject]@{ Logs = @('Application'); Desc = 'Application crashes and errors' }
    powershell = [pscustomobject]@{ Logs = @('Microsoft-Windows-PowerShell/Operational','Windows PowerShell'); Desc = 'Script blocks, module and pipeline logging' }
    defender   = [pscustomobject]@{ Logs = @('Microsoft-Windows-Windows Defender/Operational'); Desc = 'Detections, remediation, config and tamper changes' }
    tasks      = [pscustomobject]@{ Logs = @('Microsoft-Windows-TaskScheduler/Operational'); Desc = 'Scheduled task registration and execution' }
    wmi        = [pscustomobject]@{ Logs = @('Microsoft-Windows-WMI-Activity/Operational'); Desc = 'WMI queries and provider activity' }
    rdp        = [pscustomobject]@{ Logs = @('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'); Desc = 'RDP session connect, reconnect, disconnect' }
    smb        = [pscustomobject]@{ Logs = @('Microsoft-Windows-SMBServer/Security','Microsoft-Windows-SMBClient/Security'); Desc = 'SMB share access and client connections' }
    firewall   = [pscustomobject]@{ Logs = @('Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'); Desc = 'Firewall rule add, change, delete' }
    winrm      = [pscustomobject]@{ Logs = @('Microsoft-Windows-WinRM/Operational'); Desc = 'WinRM / PowerShell remoting sessions' }
    bits       = [pscustomobject]@{ Logs = @('Microsoft-Windows-Bits-Client/Operational'); Desc = 'BITS transfer jobs (common download channel)' }
    applocker  = [pscustomobject]@{ Logs = @('Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script'); Desc = 'AppLocker allow and block decisions' }
    dns        = [pscustomobject]@{ Logs = @('Microsoft-Windows-DNS-Client/Operational'); Desc = 'DNS client queries (Sysmon 22 is usually richer)' }
    all        = [pscustomobject]@{ Logs = @('Microsoft-Windows-Sysmon/Operational','Security','System','Microsoft-Windows-PowerShell/Operational'); Desc = 'Sysmon + Security + System + PowerShell together' }
}

$script:HuntAliases = @{
    sec = 'security'; sysmon64 = 'sysmon'; sys = 'system'; application = 'app'
    ps = 'powershell'; pwsh = 'powershell'; posh = 'powershell'
    av = 'defender'; mde = 'defender'; schtasks = 'tasks'; task = 'tasks'
    fw = 'firewall'; svc = 'system'; services = 'system'; remoting = 'winrm'
    everything = 'all'
}

$script:HuntIds = @{
    sysmon = @{
        1  = 'Process creation';              2  = 'File creation time changed'
        3  = 'Network connection';            4  = 'Sysmon service state change'
        5  = 'Process terminated';            6  = 'Driver loaded'
        7  = 'Image loaded';                  8  = 'CreateRemoteThread'
        9  = 'RawAccessRead';                 10 = 'Process access (LSASS reads live here)'
        11 = 'File created';                  12 = 'Registry key create/delete'
        13 = 'Registry value set';            14 = 'Registry key/value renamed'
        15 = 'File stream created (ADS / mark-of-the-web)'
        16 = 'Sysmon config changed';         17 = 'Named pipe created'
        18 = 'Named pipe connected';          19 = 'WMI event filter'
        20 = 'WMI event consumer';            21 = 'WMI consumer-to-filter binding'
        22 = 'DNS query';                     23 = 'File delete (archived)'
        24 = 'Clipboard changed';             25 = 'Process tampering (hollow/herpaderp)'
        26 = 'File delete (not archived)';    27 = 'File block executable'
        255= 'Sysmon internal error'
    }
    security = @{
        1102 = 'Audit log cleared - anti-forensics'
        4624 = 'Logon success';               4625 = 'Logon failure'
        4634 = 'Logoff';                      4647 = 'User-initiated logoff'
        4648 = 'Logon with explicit credentials (runas, lateral movement)'
        4656 = 'Handle to an object requested (file, key, process)'
        4657 = 'Registry value modified';     4658 = 'Handle closed'
        4660 = 'Object deleted';              4663 = 'Object access attempt'
        4662 = 'Directory object operation (DCSync shows up here)'
        4670 = 'Object permissions changed'
        4672 = 'Special privileges assigned (admin-equivalent logon)'
        4688 = 'Process creation (needs audit policy)'
        4689 = 'Process exited'
        4697 = 'Service installed';           4698 = 'Scheduled task created'
        4699 = 'Scheduled task deleted';      4700 = 'Scheduled task enabled'
        4701 = 'Scheduled task disabled';     4702 = 'Scheduled task updated'
        4719 = 'System audit policy changed - often used to blind logging'
        4720 = 'User account created';        4722 = 'User account enabled'
        4723 = 'Password change attempted';   4724 = 'Password reset attempt'
        4725 = 'User account disabled';       4726 = 'User account deleted'
        4728 = 'Member added to global group';  4729 = 'Member removed from global group'
        4732 = 'Member added to local group';   4733 = 'Member removed from local group'
        4738 = 'User account changed';        4740 = 'Account locked out'
        4756 = 'Member added to universal group'
        4768 = 'Kerberos TGT requested';      4769 = 'Kerberos service ticket (kerberoasting)'
        4771 = 'Kerberos pre-auth failed (Kerberos brute force)'
        4776 = 'NTLM credential validation by the DC'
        4778 = 'Session reconnected';         4779 = 'Session disconnected'
        4798 = 'Local group membership enumerated'
        4799 = 'Security-enabled local group enumerated'
        5140 = 'Network share accessed';      5142 = 'Network share added'
        5143 = 'Network share modified';      5144 = 'Network share deleted'
        5145 = 'Share object access check (share enumeration)'
        5157 = 'Windows Filtering Platform blocked a connection'
        5379 = 'Credential Manager credentials read'
    }
    system = @{
        104  = 'Event log cleared'
        1074 = 'System shutdown/restart initiated (with reason and process)'
        6005 = 'Event Log service started - system boot'
        6006 = 'Event Log service stopped - clean shutdown'
        6008 = 'Previous shutdown was unexpected'
        6013 = 'Windows uptime (logged daily, in seconds)'
        7034 = 'Service crashed unexpectedly';  7036 = 'Service state changed'
        7040 = 'Service start type changed (manual <-> automatic)'
        7045 = 'New service installed (PsExec and friends)'
    }
    powershell = @{
        4100 = 'Pipeline execution error';    4103 = 'Module / pipeline logging'
        4104 = 'Script block logging (deobfuscated source)'
        40961= 'Console host starting';       53504= 'Named pipe IPC'
        400  = 'Engine state changed to available'
        403  = 'Engine state changed to stopped';  600 = 'Provider lifecycle'
        800  = 'Pipeline execution details'
    }
    defender = @{
        1006 = 'Malware detected';            1007 = 'Action taken against malware'
        1008 = 'Action against malware failed';  1015 = 'Suspicious behaviour detected'
        1116 = 'Threat detected'
        1117 = 'Threat action taken'
        1118 = 'Remediation started'
        1119 = 'Remediation succeeded'
        1120 = 'Remediation FAILED - threat may still be live'
        5001 = 'Real-time protection disabled'
        5004 = 'Real-time protection config changed'
        5007 = 'Defender configuration changed (exclusions land here)'
        5010 = 'Antivirus scanning disabled'; 5012 = 'Antimalware scanning disabled'
        5013 = 'Tamper protection blocked a change'
    }
    tasks = @{
        106 = 'Task registered';              129 = 'Task launched process'
        140 = 'Task updated';                 141 = 'Task deleted'
        200 = 'Task action started';          201 = 'Task action completed'
    }
    firewall = @{
        2004 = 'Firewall rule added';         2005 = 'Firewall rule modified'
        2006 = 'Firewall rule deleted';       2009 = 'Firewall failed to load rules'
        2097 = 'Firewall rule deleted by group policy'
    }
    winrm = @{
        6   = 'WSMan session created';        91  = 'Remote shell created'
        168 = 'Remote shell processing';      142 = 'WSMan operation failed'
    }
    smb = @{
        551  = 'SMB client authentication';   1009 = 'SMB session established'
        31001= 'SMB client failed to authenticate'
    }
}

# -------------------------------------------------------------------- plays --
# A play is a named hunt: one or more steps, each a log + id + filter combo.
# Steps are keyed S(ource), Id, Match (regex over event data), Field
# (Name=regex), Not (exclusion regex), Count (aggregate by field).

$script:HuntLolbins = 'certutil|bitsadmin|mshta|regsvr32|rundll32|wmic|msbuild|installutil|regasm|regsvcs|cscript|wscript|odbcconf|forfiles|pcalua|hh\.exe|cmstp|msiexec|scriptrunner|at\.exe|schtasks|dfsvc|presentationhost|rpcping|xwizard|wsreset|mavinject|csc\.exe|ieexec'
$script:HuntStartupRe = 'CurrentVersion\\Run|CurrentVersion\\RunOnce|Winlogon\\(Shell|Userinit|Notify)|CurrentVersion\\Explorer\\Shell Folders|Image File Execution Options|AppInit_DLLs|\\Services\\[^\\]+\\ImagePath|LsaStart|SilentProcessExit|CurrentVersion\\Windows\\Load|Start Menu\\Programs\\Startup'

$script:HuntPlays = [ordered]@{
    procs = [pscustomobject]@{ Desc = 'Recent process creations with full command lines'
        Steps = @( @{ S='sysmon'; Id=@(1) }, @{ S='security'; Id=@(4688) } ) }

    tree = [pscustomobject]@{ Desc = 'Process creations shown as child <- parent pairs'
        Steps = @( @{ S='sysmon'; Id=@(1); Show=@('Time','User','Image','ParentImage','CommandLine') } ) }

    net = [pscustomobject]@{ Desc = 'Outbound network connections by process'
        Steps = @( @{ S='sysmon'; Id=@(3) } ) }

    dns = [pscustomobject]@{ Desc = 'DNS queries by process'
        Steps = @( @{ S='sysmon'; Id=@(22) } ) }

    creds = [pscustomobject]@{ Desc = 'LSASS process access - the credential-theft smoke alarm'
        Steps = @( @{ S='sysmon'; Id=@(10); Field=@('TargetImage=lsass\.exe'); Not='svchost\.exe|wmiprvse\.exe|MsMpEng\.exe|csrss\.exe|lsm\.exe|taskmgr\.exe' } ) }

    dumps = [pscustomobject]@{ Desc = 'Credential dumping: LSASS access plus dump files hitting disk'
        Steps = @(
            @{ S='sysmon'; Id=@(10); Field=@('TargetImage=lsass\.exe') }
            @{ S='sysmon'; Id=@(11); Field=@('TargetFilename=\.dmp$|lsass|SAM$|ntds\.dit|SYSTEM$|SECURITY$') }
            @{ S='sysmon'; Id=@(1);  Match='procdump|comsvcs.*MiniDump|rundll32.*MiniDump|nanodump|lsassy|reg.*save.*(sam|system|security)|ntdsutil|vssadmin.*create' }
            @{ S='sysmon'; Id=@(9) } ) }

    persist = [pscustomobject]@{ Desc = 'Autostart persistence: run keys, services, startup folder, tasks'
        Steps = @(
            @{ S='sysmon'; Id=@(12,13,14); Field=@("TargetObject=$script:HuntStartupRe") }
            @{ S='sysmon'; Id=@(11); Field=@('TargetFilename=Start Menu\\Programs\\Startup') }
            @{ S='system'; Id=@(7045) }
            @{ S='tasks';  Id=@(106) }
            @{ S='security'; Id=@(4697,4698,4702) } ) }

    sched = [pscustomobject]@{ Desc = 'Scheduled task creation, change and deletion'
        Steps = @( @{ S='tasks'; Id=@(106,140,141) }, @{ S='security'; Id=@(4698,4699,4702) } ) }

    svc = [pscustomobject]@{ Desc = 'New services installed and start-type changes'
        Steps = @( @{ S='system'; Id=@(7045,7040) }, @{ S='security'; Id=@(4697) } ) }

    spray = [pscustomobject]@{ Desc = 'Password spraying: failed logons counted by account'
        Steps = @( @{ S='security'; Id=@(4625); Count='TargetUserName' } ) }

    sprayip = [pscustomobject]@{ Desc = 'Failed logons counted by source address'
        Steps = @( @{ S='security'; Id=@(4625); Count='IpAddress' } ) }

    logons = [pscustomobject]@{ Desc = 'Successful logons (network and RDP are the interesting types)'
        Steps = @( @{ S='security'; Id=@(4624); Not='ANONYMOUS LOGON|\$$' } ) }

    lockouts = [pscustomobject]@{ Desc = 'Account lockouts counted by account'
        Steps = @( @{ S='security'; Id=@(4740); Count='TargetUserName' } ) }

    kerberoast = [pscustomobject]@{ Desc = 'Service tickets issued with RC4 - classic kerberoasting'
        Steps = @( @{ S='security'; Id=@(4769); Field=@('TicketEncryptionType=0x17|0x18'); Not='\$@|krbtgt' } ) }

    dcsync = [pscustomobject]@{ Desc = 'Directory replication rights used - DCSync'
        Steps = @( @{ S='security'; Id=@(4662); Match='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c' } ) }

    goldenish = [pscustomobject]@{ Desc = 'TGS requests with no matching TGT request - ticket forgery hint'
        Steps = @( @{ S='security'; Id=@(4769); Field=@('TicketOptions=0x40810000') } ) }

    psexec = [pscustomobject]@{ Desc = 'Remote execution over SMB: service installs and tool pipes'
        Steps = @(
            @{ S='sysmon'; Id=@(17,18); Field=@('PipeName=psexe|paexec|csexec|remcom|atsvc|svcctl|winreg|samr|lsarpc|PSEXESVC') }
            @{ S='system'; Id=@(7045); Match='PSEXESVC|PAExec|RemCom|csexec' }
            @{ S='security'; Id=@(5145); Field=@('ShareName=IPC\$|ADMIN\$') } ) }

    lateral = [pscustomobject]@{ Desc = 'Lateral movement: explicit creds, network logons, remoting'
        Steps = @(
            @{ S='security'; Id=@(4648) }
            @{ S='security'; Id=@(4624); Field=@('LogonType=^(3|10)$'); Not='ANONYMOUS LOGON|\$$' }
            @{ S='winrm'; Id=@(6,91,168) }
            @{ S='sysmon'; Id=@(1); Match='wmic.*\/node|Invoke-Command|Enter-PSSession|winrs|PsExec|wsmprovhost' } ) }

    lolbas = [pscustomobject]@{ Desc = 'Living-off-the-land binaries executing'
        Steps = @( @{ S='sysmon'; Id=@(1); Field=@("Image=$script:HuntLolbins") } ) }

    encoded = [pscustomobject]@{ Desc = 'Obfuscated or encoded PowerShell'
        Steps = @(
            @{ S='sysmon'; Id=@(1); Match='-e(nc|ncod|ncodedcommand)?\s+[A-Za-z0-9+/=]{30,}|FromBase64String|-nop\b|-w\s*hid|-windowstyle\s*hidden|-noni|bypass' }
            @{ S='powershell'; Id=@(4104); Match='FromBase64String|-join|char\[\]|Invoke-Expression|\biex\b|DownloadString|\$env:comspec|SecureString' } ) }

    downloads = [pscustomobject]@{ Desc = 'Files pulled from the network'
        Steps = @(
            @{ S='sysmon'; Id=@(1); Match='certutil.*(urlcache|split|decode)|bitsadmin.*transfer|curl\.exe|wget|Invoke-WebRequest|\biwr\b|DownloadFile|DownloadString|Start-BitsTransfer|New-Object\s+Net\.WebClient' }
            @{ S='bits'; Id=@(3,4,59,60) }
            @{ S='sysmon'; Id=@(15) } ) }

    injection = [pscustomobject]@{ Desc = 'Remote thread creation and process tampering'
        Steps = @( @{ S='sysmon'; Id=@(8) }, @{ S='sysmon'; Id=@(25) } ) }

    scripts = [pscustomobject]@{ Desc = 'Script files written and script hosts launched'
        Steps = @(
            @{ S='sysmon'; Id=@(11); Field=@('TargetFilename=\.(ps1|psm1|vbs|vbe|js|jse|bat|cmd|hta|wsf|wsh|lnk|scr)$') }
            @{ S='sysmon'; Id=@(1); Field=@('Image=wscript|cscript|mshta|hh\.exe|powershell|pwsh') } ) }

    shadow = [pscustomobject]@{ Desc = 'Backup and recovery destruction - ransomware precursor'
        Steps = @( @{ S='sysmon'; Id=@(1); Match='vssadmin.*delete|wbadmin.*delete|bcdedit.*(recoveryenabled|bootstatuspolicy)|wmic.*shadowcopy.*delete|Remove-ComputerRestorePoint|cipher\s*/w' } ) }

    tamper = [pscustomobject]@{ Desc = 'Defender and logging being turned off'
        Steps = @(
            @{ S='defender'; Id=@(5001,5004,5007,5010,5012) }
            @{ S='sysmon'; Id=@(1); Match='Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|DisableScriptScanning|ExclusionPath|mpcmdrun.*RemoveDefinitions|sc.*(stop|delete).*(windefend|sense|sysmon)|wevtutil.*(cl|sl)|Clear-EventLog|auditpol.*disable' }
            @{ S='security'; Id=@(1102) }
            @{ S='system'; Id=@(104) } ) }

    threats = [pscustomobject]@{ Desc = 'Defender detections and remediation actions'
        Steps = @( @{ S='defender'; Id=@(1006,1015,1116,1117,1119) } ) }

    newusers = [pscustomobject]@{ Desc = 'Account creation, enabling, resets and group additions'
        Steps = @( @{ S='security'; Id=@(4720,4722,4724,4728,4732,4738,4756) } ) }

    admins = [pscustomobject]@{ Desc = 'Privileged logons and sensitive group changes'
        Steps = @( @{ S='security'; Id=@(4672) }, @{ S='security'; Id=@(4728,4732,4756) } ) }

    wmi = [pscustomobject]@{ Desc = 'WMI persistence and remote WMI execution'
        Steps = @( @{ S='sysmon'; Id=@(19,20,21) }, @{ S='wmi'; Id=@(5857,5858,5860,5861) } ) }

    pipes = [pscustomobject]@{ Desc = 'Named pipes created and connected - C2 and tool fingerprints'
        Steps = @( @{ S='sysmon'; Id=@(17,18) } ) }

    rdp = [pscustomobject]@{ Desc = 'RDP logons, reconnects and session activity'
        Steps = @(
            @{ S='security'; Id=@(4624); Field=@('LogonType=^10$') }
            @{ S='security'; Id=@(4778,4779) }
            @{ S='rdp'; Id=@(21,22,25,1149) } ) }

    shares = [pscustomobject]@{ Desc = 'Network share access'
        Steps = @( @{ S='security'; Id=@(5140,5145) } ) }

    clearlog = [pscustomobject]@{ Desc = 'Event logs cleared - anti-forensics'
        Steps = @( @{ S='security'; Id=@(1102) }, @{ S='system'; Id=@(104) } ) }

    drivers = [pscustomobject]@{ Desc = 'Driver loads, including unsigned - BYOVD'
        Steps = @( @{ S='sysmon'; Id=@(6) } ) }

    ads = [pscustomobject]@{ Desc = 'Alternate data streams and mark-of-the-web - downloaded payloads'
        Steps = @( @{ S='sysmon'; Id=@(15) } ) }

    uac = [pscustomobject]@{ Desc = 'UAC bypass fingerprints'
        Steps = @(
            @{ S='sysmon'; Id=@(13); Field=@('TargetObject=ms-settings|mscfile|exefile\\shell|Classes\\.*\\shell\\open\\command|DelegateExecute') }
            @{ S='sysmon'; Id=@(1); Match='fodhelper|computerdefaults|sdclt|eventvwr|CompMgmtLauncher|slui|wsreset' } ) }

    recon = [pscustomobject]@{ Desc = 'Host and domain discovery commands'
        Steps = @( @{ S='sysmon'; Id=@(1); Match='whoami|net\s+(user|group|localgroup|view|share|accounts)|nltest|dsquery|setspn|systeminfo|ipconfig\s*/all|arp\s+-a|netstat|tasklist|quser|qwinsta|Get-ADUser|Get-ADComputer|Get-DomainUser|adfind|bloodhound|sharphound' } ) }
    boot = [pscustomobject]@{ Desc = 'Shutdowns, restarts, boots and uptime - unexpected reboots stand out'
        Steps = @( @{ S='system'; Id=@(1074,6005,6006,6008,6013) } ) }

    audit = [pscustomobject]@{ Desc = 'Attempts to blind the logging: policy changes and log clears'
        Steps = @( @{ S='security'; Id=@(4719,1102) }, @{ S='system'; Id=@(104) } ) }

    blocked = [pscustomobject]@{ Desc = 'Connections dropped by the Windows Filtering Platform'
        Steps = @( @{ S='security'; Id=@(5157); Count='DestPort' } ) }

    handles = [pscustomobject]@{ Desc = 'Handle requests to sensitive objects (LSASS, SAM, NTDS)'
        Steps = @( @{ S='security'; Id=@(4656,4663); Field=@('ObjectName=lsass|SAM|SECURITY|ntds\.dit') } ) }

    sharechange = [pscustomobject]@{ Desc = 'Network shares added, modified or deleted'
        Steps = @( @{ S='security'; Id=@(5142,5143,5144) } ) }

}

# ------------------------------------------------------------------ helpers --
# Which event-data fields matter, per log and event id. These drive the
# Detail column so output stays one line per event instead of a wall of XML.

$script:HuntDetail = @{
    'sysmon:1'  = @('User','Image','CommandLine','ParentImage')
    'sysmon:2'  = @('Image','TargetFilename')
    'sysmon:3'  = @('Image','SourceIp','DestinationIp','DestinationPort','DestinationHostname')
    'sysmon:5'  = @('User','Image')
    'sysmon:6'  = @('ImageLoaded','Signature','SignatureStatus')
    'sysmon:7'  = @('Image','ImageLoaded','Signed')
    'sysmon:8'  = @('SourceImage','TargetImage','StartFunction','StartModule')
    'sysmon:9'  = @('Image','Device')
    'sysmon:10' = @('SourceImage','TargetImage','GrantedAccess','CallTrace')
    'sysmon:11' = @('Image','TargetFilename')
    'sysmon:12' = @('Image','TargetObject','EventType')
    'sysmon:13' = @('Image','TargetObject','Details')
    'sysmon:14' = @('Image','TargetObject','NewName')
    'sysmon:15' = @('Image','TargetFilename','Contents')
    'sysmon:17' = @('Image','PipeName')
    'sysmon:18' = @('Image','PipeName')
    'sysmon:19' = @('Operation','Name','Query')
    'sysmon:20' = @('Operation','Name','Destination')
    'sysmon:21' = @('Operation','Consumer','Filter')
    'sysmon:22' = @('Image','QueryName','QueryResults')
    'sysmon:23' = @('Image','TargetFilename','IsExecutable')
    'sysmon:25' = @('Image','Type')
    'security:1102' = @('SubjectUserName','SubjectDomainName')
    'security:4624' = @('TargetUserName','LogonType','IpAddress','WorkstationName','ProcessName')
    'security:4625' = @('TargetUserName','LogonType','IpAddress','WorkstationName','Status','SubStatus')
    'security:4634' = @('TargetUserName','LogonType')
    'security:4648' = @('SubjectUserName','TargetUserName','TargetServerName','ProcessName','IpAddress')
    'security:4662' = @('SubjectUserName','ObjectType','Properties','AccessMask')
    'security:4663' = @('SubjectUserName','ObjectName','AccessList','ProcessName')
    'security:4672' = @('SubjectUserName','PrivilegeList')
    'security:4688' = @('SubjectUserName','NewProcessName','CommandLine','ParentProcessName')
    'security:4697' = @('SubjectUserName','ServiceName','ServiceFileName','ServiceStartType')
    'security:4698' = @('SubjectUserName','TaskName')
    'security:4699' = @('SubjectUserName','TaskName')
    'security:4702' = @('SubjectUserName','TaskName')
    'security:4720' = @('SubjectUserName','TargetUserName')
    'security:4722' = @('SubjectUserName','TargetUserName')
    'security:4724' = @('SubjectUserName','TargetUserName')
    'security:4728' = @('SubjectUserName','MemberName','TargetUserName')
    'security:4732' = @('SubjectUserName','MemberName','TargetUserName')
    'security:4738' = @('SubjectUserName','TargetUserName')
    'security:4740' = @('TargetUserName','TargetDomainName')
    'security:4756' = @('SubjectUserName','MemberName','TargetUserName')
    'security:4768' = @('TargetUserName','IpAddress','TicketEncryptionType','Status')
    'security:4769' = @('TargetUserName','ServiceName','IpAddress','TicketEncryptionType','TicketOptions')
    'security:4771' = @('TargetUserName','IpAddress','Status')
    'security:4776' = @('TargetUserName','Workstation','Status')
    'security:4778' = @('AccountName','ClientName','ClientAddress')
    'security:4779' = @('AccountName','ClientName','ClientAddress')
    'security:5140' = @('SubjectUserName','ShareName','IpAddress')
    'security:5145' = @('SubjectUserName','ShareName','RelativeTargetName','IpAddress','AccessList')
    'system:7045'   = @('AccountName','ServiceName','ImagePath','StartType','ServiceType')
    'system:7040'   = @('param1','param2','param3')
    'system:104'    = @('SubjectUserName','Channel')
    'powershell:4104' = @('Path','ScriptBlockText')
    'powershell:4103' = @('Payload','ContextInfo')
    'defender:1116' = @('Threat Name','Path','Process Name','Action Name')
    'defender:1117' = @('Threat Name','Path','Action Name','Status')
    'defender:5007' = @('Old Value','New Value')
    'defender:5001' = @('Product Name')
    'tasks:106'     = @('TaskName','UserContext')
    'tasks:129'     = @('TaskName','Path')
    'tasks:141'     = @('TaskName','UserName')
    'tasks:200'     = @('TaskName','ActionName')
}

# Used when an event id has no explicit mapping above.
$script:HuntDetailFallback = @(
    'User','SubjectUserName','TargetUserName','AccountName','UserName','UserContext'
    'Image','NewProcessName','ProcessName','SourceImage','TargetImage','ImageLoaded','ImagePath'
    'CommandLine','ParentImage','ParentProcessName','ParentCommandLine'
    'TargetFilename','TargetObject','Details','Path','FileName'
    'ServiceName','TaskName','PipeName','ShareName','RelativeTargetName'
    'SourceIp','DestinationIp','DestinationPort','DestinationHostname','IpAddress','ClientAddress'
    'QueryName','QueryResults','ScriptBlockText','Payload','param1','param2'
    'Threat Name','Action Name','New Value','Old Value','Status','LogonType','GrantedAccess'
)

$script:HuntReserved = @('Time','TimeCreated','Id','Event','Detail','Log','Source','Computer','Provider','Level','RecordId','Data','Record','Message','Keywords','Opcode','Task')

function Resolve-HuntSource {
    [CmdletBinding()] param([string]$Name)
    if (-not $Name) { return @() }
    $n = $Name.ToLower()
    if ($script:HuntAliases.ContainsKey($n)) { $n = $script:HuntAliases[$n] }
    if ($script:HuntSources.Contains($n)) { return @($script:HuntSources[$n].Logs) }
    return @($Name)   # fall through: treat it as a literal channel name
}

$script:HuntShortCache = @{}

function Get-HuntShortName {
    [CmdletBinding()] param([string]$Log)
    if ($script:HuntShortCache.ContainsKey($Log)) { return $script:HuntShortCache[$Log] }
    $script:HuntShortCache[$Log] = Get-HuntShortNameUncached $Log
    return $script:HuntShortCache[$Log]
}

function Get-HuntShortNameUncached {
    [CmdletBinding()] param([string]$Log)
    foreach ($k in $script:HuntSources.Keys) {
        if ($k -eq 'all') { continue }
        if ($script:HuntSources[$k].Logs -contains $Log) { return $k }
    }
    return ($Log -replace '^Microsoft-Windows-','' -replace '/.*$','').ToLower()
}

function ConvertTo-HuntTimeSpan {
    [CmdletBinding()] param([string]$Spec)
    if (-not $Spec) { return $null }
    $m = [regex]::Match($Spec.Trim(), '^(?<n>\d+(?:\.\d+)?)\s*(?<u>s|m|h|d|w|min|mins|minute|minutes|hour|hours|day|days|week|weeks)?$', 'IgnoreCase')
    if (-not $m.Success) { throw "Could not read the time span '$Spec'. Try 30m, 6h, 2d or 1w." }
    $n = [double]$m.Groups['n'].Value
    switch -Regex (($m.Groups['u'].Value).ToLower()) {
        '^s$'            { return [TimeSpan]::FromSeconds($n) }
        '^(m|min)'       { return [TimeSpan]::FromMinutes($n) }
        '^(h|hour)'      { return [TimeSpan]::FromHours($n) }
        '^(d|day)'       { return [TimeSpan]::FromDays($n) }
        '^(w|week)'      { return [TimeSpan]::FromDays(7 * $n) }
        default          { return [TimeSpan]::FromHours($n) }   # bare number = hours
    }
}

function New-HuntRegex {
    [CmdletBinding()] param([string]$Pattern)
    try   { return New-Object Text.RegularExpressions.Regex ($Pattern, 'IgnoreCase') }
    catch { return New-Object Text.RegularExpressions.Regex ([regex]::Escape($Pattern), 'IgnoreCase') }
}

function ConvertFrom-HuntEventXml {
    [CmdletBinding()] param($Event, [string]$Xml)
    $d = [ordered]@{}
    if (-not $Xml) {
        try { $Xml = $Event.ToXml() } catch { return $d }
    }
    try { $x = [xml]$Xml } catch { return $d }
    $ed = $x.Event.EventData
    if ($ed -and $ed.Data) {
        $i = 0
        foreach ($node in @($ed.Data)) {
            # NB: $node.Name is the element name ('Data'), not the attribute.
            $name = $null
            if ($node -is [System.Xml.XmlElement]) { $name = $node.GetAttribute('Name') }
            if ([string]::IsNullOrEmpty($name)) { $name = "Data$i" }
            $d[$name] = [string]$node.InnerText
            $i++
        }
    }
    elseif ($x.Event.UserData) {
        foreach ($child in $x.Event.UserData.ChildNodes) {
            foreach ($g in $child.ChildNodes) {
                if ($g.NodeType -eq 'Element') { $d[$g.LocalName] = [string]$g.InnerText }
            }
        }
    }
    return $d
}

function Get-HuntEventName {
    [CmdletBinding()] param([string]$Short, [int]$Id)
    if ($script:HuntIds.ContainsKey($Short) -and $script:HuntIds[$Short].ContainsKey($Id)) {
        return [string]$script:HuntIds[$Short][$Id]
    }
    return ''
}

# ------------------------------------------------------------------- query --
# Keyword logic, deliberately shallow: terms are ANDed, 'or' joins the
# previous term, '!term' excludes. Commas inside a token are an OR group.
# Anything that compiles as a regex is used as one; if it doesn't, it falls
# back to a literal match, so C:\Users\bob doesn't blow up.

function New-HuntQuery {
    [CmdletBinding()] param([string[]]$Terms)
    $groups = New-Object Collections.ArrayList
    $nots   = New-Object Collections.ArrayList
    $pendingOr = $false
    $pendingNot = $false
    foreach ($raw in $Terms) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $t = $raw.Trim()
        if ($t -match '^(and|&&|\+)$') { $pendingOr = $false; continue }
        if ($t -match '^(or|\|\|)$')   { $pendingOr = $true;  continue }
        if ($t -match '^(not|except|without)$') { $pendingNot = $true; continue }
        $neg = $pendingNot
        $pendingNot = $false
        if ($t.StartsWith('!')) { $neg = $true; $t = $t.Substring(1) }
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $rx = @()
        foreach ($piece in ($t -split ',')) {
            if (-not [string]::IsNullOrWhiteSpace($piece)) { $rx += (New-HuntRegex $piece.Trim()) }
        }
        if ($rx.Count -eq 0) { continue }
        if ($neg) { foreach ($r in $rx) { [void]$nots.Add($r) }; $pendingOr = $false; continue }
        if ($pendingOr -and $groups.Count -gt 0) {
            $groups[$groups.Count - 1] = @($groups[$groups.Count - 1]) + $rx
        } else {
            [void]$groups.Add($rx)
        }
        $pendingOr = $false
    }
    if ($groups.Count -eq 0 -and $nots.Count -eq 0) { return $null }
    return [pscustomobject]@{ Groups = @($groups); Nots = @($nots) }
}

function Test-HuntQuery {
    [CmdletBinding()] param($Query, [string]$Text)
    if (-not $Query) { return $true }
    foreach ($r in $Query.Nots) { if ($r.IsMatch($Text)) { return $false } }
    foreach ($g in $Query.Groups) {
        $hit = $false
        foreach ($r in @($g)) { if ($r.IsMatch($Text)) { $hit = $true; break } }
        if (-not $hit) { return $false }
    }
    return $true
}

function Format-HuntValue {
    [CmdletBinding()] param([string]$Value, [int]$Limit = 300)
    if ($null -eq $Value) { return '' }
    $v = ($Value -replace '\s+', ' ').Trim()
    if ($v.Length -gt $Limit) { $v = $v.Substring(0, $Limit) + '...' }
    return $v
}

function New-HuntRecord {
    [CmdletBinding()] param($Event, [string]$Log, [string]$Xml)
    $short = Get-HuntShortName $Log
    $id    = [int]$Event.Id
    $data  = ConvertFrom-HuntEventXml -Event $Event -Xml $Xml
    $key   = $short + ':' + $id

    $parts = New-Object Collections.ArrayList
    if ($script:HuntDetail.ContainsKey($key)) {
        foreach ($f in $script:HuntDetail[$key]) {
            if ($data.Contains($f) -and -not [string]::IsNullOrWhiteSpace([string]$data[$f])) {
                [void]$parts.Add((Format-HuntValue ([string]$data[$f])))
            }
        }
    }
    if ($parts.Count -eq 0) {
        foreach ($f in $script:HuntDetailFallback) {
            if ($parts.Count -ge 4) { break }
            if ($data.Contains($f) -and -not [string]::IsNullOrWhiteSpace([string]$data[$f])) {
                [void]$parts.Add((Format-HuntValue ([string]$data[$f])))
            }
        }
    }
    if ($parts.Count -eq 0) {
        foreach ($k in $data.Keys) {
            if ($parts.Count -ge 3) { break }
            if (-not [string]::IsNullOrWhiteSpace([string]$data[$k])) {
                [void]$parts.Add((Format-HuntValue ([string]$data[$k])))
            }
        }
    }

    $name = Get-HuntEventName $short $id
    if (-not $name) {
        try { $name = [string]$Event.TaskDisplayName } catch { $name = '' }
    }
    if (-not $name) { $name = 'Event ' + $id }

    $tc = $Event.TimeCreated
    if ($tc -and $tc.Date -eq (Get-Date).Date) { $ts = $tc.ToString('HH:mm:ss') }
    elseif ($tc) { $ts = $tc.ToString('MM-dd HH:mm') }
    else { $ts = '' }

    $h = [ordered]@{
        Time        = $ts
        Id          = $id
        Event       = $name
        Detail      = ($parts -join ' | ')
        TimeCreated = $tc
        Log         = $Log
        Source      = $short
        Computer    = $Event.MachineName
        Provider    = $Event.ProviderName
        RecordId    = $Event.RecordId
        Data        = $data
        Record      = $Event
    }

    # Promote every event-data field to a real property, so you can do
    # -Show Image,CommandLine, -Count TargetUserName, or $r.ParentImage.
    # Built into the hashtable rather than via Add-Member: one object
    # construction instead of a member add per field, per event.
    foreach ($k in $data.Keys) {
        if ([string]::IsNullOrWhiteSpace($k)) { continue }
        $pname = $k -replace '[^A-Za-z0-9_]', ''
        if (-not $pname) { continue }
        if ($script:HuntReserved -contains $pname) { $pname = 'd_' + $pname }
        if ($h.Contains($pname)) { continue }
        $h[$pname] = $data[$k]
    }

    $o = [pscustomobject]$h
    # Message and Level both cost a provider-metadata lookup, so they stay lazy.
    Add-Member -InputObject $o -MemberType ScriptProperty -Name Message -Value { try { $this.Record.Message } catch { '' } }
    Add-Member -InputObject $o -MemberType ScriptProperty -Name Level -Value { try { $this.Record.LevelDisplayName } catch { '' } }
    $o.PSObject.TypeNames.Insert(0, 'Hunt.Event')
    $set = New-Object Management.Automation.PSPropertySet 'DefaultDisplayPropertySet', ([string[]]@('Time','Id','Event','Detail'))
    Add-Member -InputObject $o -MemberType MemberSet -Name PSStandardMembers -Value ([Management.Automation.PSMemberInfo[]]@($set))
    return $o
}

function Test-HuntField {
    [CmdletBinding()] param($Record, [string[]]$Field)
    foreach ($spec in $Field) {
        if ([string]::IsNullOrWhiteSpace($spec)) { continue }
        $i = $spec.IndexOfAny([char[]]@('=', ':'))
        if ($i -lt 1) { continue }
        $name = $spec.Substring(0, $i).Trim()
        $pat  = $spec.Substring($i + 1).Trim()
        $neg  = $false
        if ($name.EndsWith('!')) { $neg = $true; $name = $name.TrimEnd('!') }
        $val = $null
        if ($Record.Data.Contains($name)) { $val = [string]$Record.Data[$name] }
        else {
            foreach ($k in $Record.Data.Keys) {
                if ($k -and $k.ToLower() -eq $name.ToLower()) { $val = [string]$Record.Data[$k]; break }
            }
        }
        $rx = New-HuntRegex $pat
        $hit = ($null -ne $val) -and $rx.IsMatch($val)
        if ($neg -and $hit) { return $false }
        if (-not $neg -and -not $hit) { return $false }
    }
    return $true
}

# ------------------------------------------------------------------- engine --
# Get-WinEvent costs ~20ms per event on a real host, which turns a full-channel
# keyword scan into a 10-minute wait. EventLogReader is the API it wraps and
# runs ~80x faster (measured: 0.23ms vs 21ms per event on Win10 + Sysmon), so
# the engine drives that directly. Event id and time window are still pushed
# down, now as structured XPath.

function New-HuntXPath {
    [CmdletBinding()]
    param([int[]]$Id, [Nullable[datetime]]$After, [Nullable[datetime]]$Before)
    $conds = @()
    if ($Id) {
        $parts = foreach ($i in $Id) { "EventID=$i" }
        $conds += '(' + ($parts -join ' or ') + ')'
    }
    $t = @()
    # Raw >= and <=, not XML entities: EventLogQuery takes a bare XPath string
    # and rejects &gt;= with 'The specified query is invalid' (verified on Win10).
    if ($After)  { $t += "@SystemTime>='" + $After.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') + "'" }
    if ($Before) { $t += "@SystemTime<='" + $Before.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') + "'" }
    if ($t.Count -gt 0) { $conds += 'TimeCreated[' + ($t -join ' and ') + ']' }
    if ($conds.Count -eq 0) { return '*' }
    return '*[System[' + ($conds -join ' and ') + ']]'
}

# The one place that touches the event log. Mocked in tests.
function Read-HuntRawEvents {
    [CmdletBinding()]
    param(
        [string]$Log,
        [int[]]$Id,
        [Nullable[datetime]]$After,
        [Nullable[datetime]]$Before,
        [switch]$Oldest,
        [string]$Computer,
        $Credential
    )
    $xpath = New-HuntXPath -Id $Id -After $After -Before $Before
    $session = $null
    if ($Computer -and $Computer -notin @('.', 'localhost', $env:COMPUTERNAME)) {
        if ($Credential) {
            $session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession(
                $Computer, $Credential.GetNetworkCredential().Domain, $Credential.UserName,
                $Credential.Password, [System.Diagnostics.Eventing.Reader.SessionAuthentication]::Default)
        } else {
            $session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession($Computer)
        }
    }
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        $Log, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    if ($session) { $query.Session = $session }
    $query.ReverseDirection = (-not $Oldest)     # newest first by default
    # Deliberately NOT TolerateQueryErrors: that swallows the missing-channel
    # error and returns an empty result, so 'hunt sysmon x' on a box without
    # Sysmon would look like "no hits" instead of "Sysmon is not installed".
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader $query
    try {
        while ($true) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            $e
        }
    }
    finally {
        $reader.Dispose()
        if ($session) { $session.Dispose() }
    }
}

# Keywords match event data, so trim the <System> block off the front rather
# than matching provider names and GUIDs by accident.
function Get-HuntMatchText {
    [CmdletBinding()] param([string]$Xml)
    if (-not $Xml) { return '' }
    $i = $Xml.IndexOf('<EventData')
    if ($i -lt 0) { $i = $Xml.IndexOf('<UserData') }
    if ($i -lt 0) { return $Xml }
    return $Xml.Substring($i)
}

function Search-HuntEvents {
    [CmdletBinding()]
    param(
        [string[]]$Logs,
        [int[]]$Id,
        $Query,
        [string[]]$Field,
        [string]$MatchRegex,
        [string]$NotRegex,
        [string]$CountField,
        [Nullable[datetime]]$After,
        [Nullable[datetime]]$Before,
        [int]$Max = 40,
        [string[]]$Computers = @('.'),
        $Credential,
        [switch]$Oldest
    )

    $out     = New-Object Collections.ArrayList
    $stepRx  = $null; if ($MatchRegex) { $stepRx = New-HuntRegex $MatchRegex }
    $stepNot = $null; if ($NotRegex)   { $stepNot = New-HuntRegex $NotRegex }
    $missing = New-Object Collections.ArrayList
    $denied  = $false
    $unreachable = $false
    $touched = 0

    # Aggregating only needs one field, so skip building a record per event and
    # pull the value straight out of the XML. Over a few thousand events the
    # difference is minutes, not milliseconds.
    # A positive Name=regex can only match if the pattern appears somewhere in
    # the event data, so test it against the cheap text first. Without this, a
    # field filter forces an XML parse of every event in the channel just to
    # discover it does not match. Negated specs cannot be pre-filtered.
    $fieldPre = @()
    if ($Field) {
        foreach ($spec in $Field) {
            if ([string]::IsNullOrWhiteSpace($spec)) { continue }
            $i = $spec.IndexOfAny([char[]]@('=', ':'))
            if ($i -lt 1) { continue }
            if ($spec.Substring(0, $i).Trim().EndsWith('!')) { continue }
            $fieldPre += (New-HuntRegex $spec.Substring($i + 1).Trim())
        }
    }

    $cfRx = $null
    if ($CountField) {
        $pat = '<Data Name=[''"]' + [regex]::Escape($CountField) + '[''"]\s*>(.*?)</Data>'
        $cfRx = New-Object Text.RegularExpressions.Regex ($pat, ([Text.RegularExpressions.RegexOptions]'Singleline, IgnoreCase'))
    }

    foreach ($comp in $Computers) {
        foreach ($log in $Logs) {
            if ($out.Count -ge $Max) { break }
            $remaining = $Max - $out.Count

            try {
                $hits = Read-HuntRawEvents -Log $log -Id $Id -After $After -Before $Before `
                            -Oldest:$Oldest -Computer $comp -Credential $Credential | ForEach-Object {
                    $e = $_
                    # One ToXml per event is the whole per-event cost; everything
                    # filters against that string before any XML is parsed.
                    try { $xmlText = $e.ToXml() } catch { $xmlText = '' }
                    $text = Get-HuntMatchText $xmlText
                    if ($stepNot -and $stepNot.IsMatch($text)) { return }
                    if ($stepRx  -and -not $stepRx.IsMatch($text)) { return }
                    if (-not (Test-HuntQuery $Query $text)) { return }
                    foreach ($fr in $fieldPre) { if (-not $fr.IsMatch($text)) { return } }

                    if ($cfRx) {
                        $m = $cfRx.Match($xmlText)
                        $v = '(none)'
                        if ($m.Success) {
                            $v = $m.Groups[1].Value
                            if ($v.IndexOf('&') -ge 0) {
                                $v = $v.Replace('&lt;','<').Replace('&gt;','>').Replace('&quot;','"').Replace('&apos;',"'").Replace('&amp;','&')
                            }
                        }
                        if ([string]::IsNullOrWhiteSpace($v)) { $v = '(none)' }
                        return [pscustomobject]@{ CountValue = $v }
                    }

                    $rec = New-HuntRecord -Event $e -Log $log -Xml $xmlText
                    if ($Field -and -not (Test-HuntField -Record $rec -Field $Field)) { return }
                    $rec
                } | Select-Object -First $remaining

                foreach ($h in $hits) { [void]$out.Add($h) }
                $touched++
            }
            catch {
                $ex = $_.Exception
                while ($ex.InnerException) { $ex = $ex.InnerException }
                $tn  = $ex.GetType().Name
                $msg = [string]$ex.Message
                if     ($tn -eq 'EventLogNotFoundException') { [void]$missing.Add($log) }
                elseif ($tn -eq 'UnauthorizedAccessException') { $denied = $true }
                elseif ($msg -match 'unauthorized|Access is denied') { $denied = $true }
                elseif ($msg -match 'not an event log|could not be found|does not exist|no event log') { [void]$missing.Add($log) }
                elseif ($msg -match 'RPC server is unavailable|cannot be found.*network|network path') {
                    $unreachable = $true
                }
                else   { Write-Warning ("{0}: {1}" -f $log, $msg) }
            }
        }
    }

    if ($denied) {
        Write-Warning 'Access denied on at least one log. The Security log needs an elevated session.'
    }
    if ($unreachable) {
        Write-Warning ("Could not reach the event log service on {0}. Remote reads need the " +
            "'Remote Event Log Management' firewall rules enabled on the target: " +
            "netsh advfirewall firewall set rule group=`"Remote Event Log Management`" new enable=yes" -f ($Computers -join ', '))
    }
    if ($touched -eq 0 -and $missing.Count -gt 0) {
        foreach ($m in ($missing | Select-Object -Unique)) {
            if ($m -like '*Sysmon*') {
                Write-Warning "Sysmon is not installed here (no '$m' channel). Try: hunt security -Id 4688"
            } else {
                Write-Warning "No '$m' channel on this host. Run 'hunt sources' to see what is available."
            }
        }
    }
    return $out
}

function Invoke-Hunt {
    <#
    .SYNOPSIS
        Search Windows event logs with two words instead of a Get-WinEvent pipeline.
    .EXAMPLE
        hunt sysmon mimikatz
    .EXAMPLE
        hunt security -Id 4625 -Last 1h
    .EXAMPLE
        hunt play creds -Last 24h
    .EXAMPLE
        hunt where lsass
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Source,

        [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
        [string[]]$Query,

        [Alias('e','EventId')]
        [int[]]$Id,

        [Alias('t','Since')]
        [string]$Last,

        [Nullable[datetime]]$After,
        [Nullable[datetime]]$Before,

        [Alias('n','Top')]
        [int]$Max = 40,

        # Name=regex, repeatable. Name!=regex to exclude.
        [Alias('f','w','Where')]
        [string[]]$Field,

        # Aggregate matches by one event-data field instead of listing them.
        [Alias('c','By','Stats')]
        [string]$Count,

        [Alias('s','Columns')]
        [string[]]$Show,

        [switch]$Full,
        [switch]$Raw,
        [switch]$Oldest,

        [Alias('On')]
        [string[]]$ComputerName = @('.'),

        [pscredential]$Credential
    )

    # ---- subcommands ----
    $sub = ''
    if ($Source) { $sub = $Source.ToLower().TrimStart([char[]]@('-','/')) }

    if (-not $Source -or $sub -in @('help','h','?','tldr','usage','--help')) {
        Show-HuntHelp; return
    }
    if ($sub -in @('version','--version','-v')) { "hunt $script:HuntVersion"; return }
    if ($sub -in @('sources','logs','channels')) { Show-HuntSources; return }
    if ($sub -in @('where','find','what','which','lookup','search')) {
        Find-HuntTarget -Term $Query; return
    }
    if ($sub -in @('ids','id','events')) {
        Show-HuntIds -Term $Query; return
    }
    if ($sub -in @('play','plays','p','run')) {
        # 'plays <text>' is a search of the catalogue; 'play <name>' runs one.
        # Only the second should complain about an unknown name.
        $listing = ($sub -eq 'plays')
        $name = ''
        if ($Query -and $Query.Count -gt 0) { $name = $Query[0].ToLower() }
        if (-not $name -or -not $script:HuntPlays.Contains($name)) {
            Show-HuntPlays -Filter $Query
            if ($name -and -not $listing) {
                Write-Warning "No play called '$name'. Closest matches listed above."
            }
            return
        }
        $rest = @()
        if ($Query.Count -gt 1) { $rest = $Query[1..($Query.Count - 1)] }
        $null = $PSBoundParameters.Remove('Source')
        $null = $PSBoundParameters.Remove('Query')
        return Invoke-HuntPlay -Name $name -Extra $rest -Options $PSBoundParameters
    }

    # ---- time window ----
    $afterTime = $After
    if ($Last) {
        $span = ConvertTo-HuntTimeSpan $Last
        if ($span) { $afterTime = (Get-Date).Subtract($span) }
    }
    if ($Count -and -not $afterTime) {
        $afterTime = (Get-Date).AddDays(-7)
        Write-Verbose 'No window given with -Count; defaulting to the last 7 days.'
    }

    $logs = Resolve-HuntSource $Source
    $parsed = New-HuntQuery -Terms $Query
    $effMax = $Max
    if ($Count) { $effMax = 100000 }

    $countFast = ''
    if ($Count -and -not $Field) { $countFast = $Count }

    $results = Search-HuntEvents -Logs $logs -Id $Id -Query $parsed -Field $Field `
        -CountField $countFast -After $afterTime -Before $Before -Max $effMax `
        -Computers $ComputerName -Credential $Credential -Oldest:$Oldest

    return Format-HuntResult -Results $results -Count $Count -Show $Show -Full:$Full -Raw:$Raw -Max $Max
}

function Invoke-HuntPlay {
    [CmdletBinding()]
    param([string]$Name, [string[]]$Extra, [hashtable]$Options)

    $play = $script:HuntPlays[$Name]
    $o = @{}
    if ($Options) { foreach ($k in $Options.Keys) { $o[$k] = $Options[$k] } }

    $afterTime = $null
    if ($o.ContainsKey('After')) { $afterTime = $o['After'] }
    if ($o.ContainsKey('Last') -and $o['Last']) {
        $span = ConvertTo-HuntTimeSpan $o['Last']
        if ($span) { $afterTime = (Get-Date).Subtract($span) }
    }
    $before = $null; if ($o.ContainsKey('Before')) { $before = $o['Before'] }
    $max    = 40;    if ($o.ContainsKey('Max'))    { $max = [int]$o['Max'] }
    $comps  = @('.'); if ($o.ContainsKey('ComputerName')) { $comps = $o['ComputerName'] }
    $cred   = $null; if ($o.ContainsKey('Credential')) { $cred = $o['Credential'] }
    $userField = @(); if ($o.ContainsKey('Field')) { $userField = @($o['Field']) }
    $countBy = ''; if ($o.ContainsKey('Count')) { $countBy = [string]$o['Count'] }
    $resolvedCount = $countBy   # an explicit -Count beats the play's own default
    $show = $null; if ($o.ContainsKey('Show')) { $show = $o['Show'] }

    $parsed = New-HuntQuery -Terms $Extra
    $all = New-Object Collections.ArrayList

    foreach ($step in $play.Steps) {
        $logs = Resolve-HuntSource $step.S
        $fields = @()
        if ($step.ContainsKey('Field') -and $step.Field) { $fields += @($step.Field) }
        if ($userField) { $fields += $userField }
        if (-not $resolvedCount -and $step.ContainsKey('Count')) { $resolvedCount = [string]$step.Count }
        $effMax = $max
        if ($resolvedCount) { $effMax = 100000 }
        if (-not $show -and $step.ContainsKey('Show')) { $show = $step.Show }

        $stepMatch = $null; if ($step.ContainsKey('Match')) { $stepMatch = [string]$step.Match }
        $stepNot   = $null; if ($step.ContainsKey('Not'))   { $stepNot   = [string]$step.Not }
        if ($resolvedCount -and -not $afterTime) { $afterTime = (Get-Date).AddDays(-7) }

        $countFast = ''
        if ($resolvedCount -and -not $fields) { $countFast = $resolvedCount }

        $r = Search-HuntEvents -Logs $logs -Id $step.Id -Query $parsed -Field $fields `
            -MatchRegex $stepMatch -NotRegex $stepNot -CountField $countFast `
            -After $afterTime -Before $before -Max $effMax `
            -Computers $comps -Credential $cred -WarningAction SilentlyContinue
        foreach ($x in $r) { [void]$all.Add($x) }
    }

    if ($all.Count -eq 0) {
        Write-Host ("no hits for play '{0}' - {1}" -f $Name, $play.Desc) -ForegroundColor DarkGray
        return
    }
    $sorted = $all
    if (-not $resolvedCount) { $sorted = $all | Sort-Object TimeCreated -Descending }
    return Format-HuntResult -Results $sorted -Count $resolvedCount -Show $show `
        -Full:([bool]$o['Full']) -Raw:([bool]$o['Raw']) -Max $max
}

function Format-HuntResult {
    [CmdletBinding()]
    param($Results, [string]$Count, [string[]]$Show, [switch]$Full, [switch]$Raw, [int]$Max = 40)

    # An empty ArrayList unrolls to nothing on return, so $Results arrives as
    # $null and @($null) has Count 1. Strip nulls before the emptiness check.
    $list = @($Results | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { return }

    if ($Count) {
        $name = $Count
        $fast = $null -ne $list[0].PSObject.Properties['CountValue']
        return $list | ForEach-Object {
            if ($fast) { $v = [string]$_.CountValue }
            else {
                $v = $null
                if ($_.Data -and $_.Data.Contains($name)) { $v = [string]$_.Data[$name] }
                elseif ($_.PSObject.Properties[$name]) { $v = [string]$_.$name }
            }
            if ([string]::IsNullOrWhiteSpace($v)) { $v = '(none)' }
            [pscustomobject]@{ Value = $v }
        } | Group-Object Value | Sort-Object Count -Descending |
            Select-Object -First $Max @{n=$name;e={$_.Name}}, Count
    }

    if ($Raw)  { return $list }
    if ($Full) { return $list | Select-Object -First $Max Time, Id, Event, Computer, Log, Detail, Message }
    if ($Show) { return $list | Select-Object -First $Max ( @('Time','Id') + $Show | Select-Object -Unique ) }
    return $list | Select-Object -First $Max
}

# --------------------------------------------------------------- discovery --
# Concept words that do not literally appear in the catalogue descriptions,
# so that 'hunt where mimikatz' and 'hunt where ransomware' still land.

$script:HuntIndex = @(
    @{ T = 'mimikatz|lsass|sekurlsa|dump cred|credential (theft|dump)|procdump|comsvcs|nanodump|secretsdump'; Run = 'hunt play dumps';      Why = 'LSASS access, dump files on disk, and the usual tooling' }
    @{ T = 'hash|ntlm|pass.?the.?hash|overpass';                      Run = 'hunt play lateral';    Why = 'explicit-credential logons (4648) and network logons' }
    @{ T = 'kerberos|kerberoast|spn|ticket|silver|golden';            Run = 'hunt play kerberoast'; Why = 'service tickets issued with RC4' }
    @{ T = 'dcsync|replicat|ntds';                                    Run = 'hunt play dcsync';     Why = 'directory replication rights being used' }
    @{ T = 'brute|spray|guess|password attack|failed (login|logon)';  Run = 'hunt play spray';      Why = 'failed logons counted by account' }
    @{ T = 'backdoor|persist|autorun|autostart|run key|startup|survive reboot'; Run = 'hunt play persist'; Why = 'run keys, services, startup folder and tasks together' }
    @{ T = 'ransom|encrypt|shadow cop|vss|backup delet';              Run = 'hunt play shadow';     Why = 'vssadmin/wbadmin/bcdedit destruction commands' }
    @{ T = 'privesc|escalat|uac|bypass|fodhelper|admin rights';       Run = 'hunt play uac';         Why = 'UAC bypass registry and binary fingerprints' }
    @{ T = 'pivot|lateral|move|psexec|wmiexec|smbexec|remote exec';   Run = 'hunt play lateral';     Why = 'explicit creds, network logons, remoting, service installs' }
    @{ T = 'exfil|upload|data (theft|out)|steal';                     Run = 'hunt play net';         Why = 'outbound connections per process (add: hunt play dns, hunt play shares)' }
    @{ T = 'c2|command and control|beacon|implant|callback';          Run = 'hunt play net';         Why = 'outbound connections; pair with hunt play pipes for named-pipe C2' }
    @{ T = 'download|payload|stager|dropper|fetch|wget|curl';         Run = 'hunt play downloads';   Why = 'certutil, bitsadmin, curl, Invoke-WebRequest and BITS jobs' }
    @{ T = 'obfusc|base64|encoded|encode|amsi|iex|invoke.?expr';      Run = 'hunt play encoded';     Why = 'encoded command lines and script-block logging' }
    @{ T = 'inject|hollow|remote thread|shellcode';                   Run = 'hunt play injection';   Why = 'CreateRemoteThread and process tampering' }
    @{ T = 'disable|turn off|tamper|exclusion|defender off|evade';    Run = 'hunt play tamper';      Why = 'Defender config changes and logging being switched off' }
    @{ T = 'cover|anti.?forensic|clear log|wipe|delete log';          Run = 'hunt play audit';       Why = 'audit policy changes and cleared logs' }
    @{ T = 'recon|enumerat|discovery|whoami|net user|bloodhound';     Run = 'hunt play recon';       Why = 'host and domain discovery commands' }
    @{ T = 'new (user|account)|added to group|group member|privileged account'; Run = 'hunt play newusers'; Why = 'account creation, resets and group additions' }
    @{ T = 'reboot|restart|shutdown|uptime|boot|power';               Run = 'hunt play boot';        Why = 'shutdown reasons, boots and daily uptime' }
    @{ T = 'rdp|remote desktop|3389|mstsc';                           Run = 'hunt play rdp';         Why = 'type-10 logons, reconnects and session events' }
    @{ T = 'share|smb|445|unc|net use';                               Run = 'hunt play shares';      Why = 'share access and access checks' }
    @{ T = 'service install|new service|sc create';                   Run = 'hunt play svc';         Why = 'service installs and start-type changes' }
    @{ T = 'task|cron|schtasks|scheduled';                            Run = 'hunt play sched';       Why = 'task registration, update and deletion' }
    @{ T = 'wmi|subscription|event consumer';                         Run = 'hunt play wmi';         Why = 'WMI persistence triplets and remote WMI' }
    @{ T = 'lolbin|lolbas|signed binary|certutil|regsvr32|rundll32';  Run = 'hunt play lolbas';      Why = 'living-off-the-land binaries executing' }
    @{ T = 'firewall|blocked|dropped|filtering platform';             Run = 'hunt play blocked';     Why = 'WFP connection blocks, counted by port' }
    @{ T = 'virus|malware|detection|threat|quarantine';               Run = 'hunt play threats';     Why = 'Defender detections and remediation outcomes' }
    @{ T = 'process|command line|what ran|execution|parent';          Run = 'hunt play procs';       Why = 'process creation with full command lines' }
    @{ T = 'file (write|created|dropped)|wrote|dropped file';          Run = 'hunt sysmon -Id 11';    Why = 'Sysmon file-create events' }
    @{ T = 'registry|regkey|reg add';                                  Run = 'hunt sysmon -Id 12,13'; Why = 'registry key and value changes' }
    @{ T = 'dll|module|image load|sideload';                           Run = 'hunt sysmon -Id 7';     Why = 'image loads, with signature status' }
    @{ T = 'driver|byovd|kernel';                                      Run = 'hunt play drivers';     Why = 'driver loads with signature status' }
    @{ T = 'pipe|named pipe';                                          Run = 'hunt play pipes';       Why = 'named pipes created and connected' }
    @{ T = 'dns|domain lookup|resolve|query';                          Run = 'hunt play dns';         Why = 'DNS queries attributed to a process' }
)

function Write-HuntRow {
    param([string]$Left, [string]$Right, [int]$Width = 16, [ConsoleColor]$Color = 'Cyan')
    Write-Host ('  ' + $Left.PadRight($Width)) -ForegroundColor $Color -NoNewline
    Write-Host $Right
}

function Show-HuntHelp {
    Write-Host ''
    Write-Host "  hunt $script:HuntVersion" -ForegroundColor Green -NoNewline
    Write-Host '  -  Threat hunting for Windows event logs.'
    Write-Host ''
    Write-Host '  GRAMMAR' -ForegroundColor Yellow
    Write-Host '    hunt <source> <keyword...> [options]'
    Write-Host ''
    Write-Host '  START HERE' -ForegroundColor Yellow
    Write-HuntRow 'hunt where X'  'you know WHAT you want, not where it lives  <- start here'
    Write-HuntRow 'hunt plays'    'the 42 prebuilt hunts, by name'
    Write-HuntRow 'hunt sources'  'which logs exist on this host, and how full they are'
    Write-HuntRow 'hunt ids X'    'cheat sheet: "hunt ids sysmon", or "hunt ids 4625"'
    Write-Host ''
    Write-Host '  EXAMPLES' -ForegroundColor Yellow
    Write-HuntRow 'keyword'   'hunt sysmon mimikatz'                     14 DarkGray
    Write-HuntRow 'and'       'hunt sysmon lsass dmp'                    14 DarkGray
    Write-HuntRow 'or'        'hunt sysmon mimikatz or rubeus'           14 DarkGray
    Write-HuntRow 'not'       'hunt sysmon powershell !svchost'          14 DarkGray
    Write-HuntRow 'by id'     'hunt security -Id 4625 -Last 1h'          14 DarkGray
    Write-HuntRow 'by field'  'hunt sysmon -Id 3 -Field DestinationPort=445' 14 DarkGray
    Write-HuntRow 'a play'    'hunt play creds -Last 24h'                14 DarkGray
    Write-HuntRow 'counting'  'hunt security -Id 4625 -Count TargetUserName' 14 DarkGray
    Write-HuntRow 'columns'   'hunt sysmon -Id 1 -Show Image,CommandLine' 14 DarkGray
    Write-Host ''
    Write-Host '  OPTIONS' -ForegroundColor Yellow
    Write-HuntRow '-Id 1,3,11'   'event ids (pushed down to the log, so it is fast)' 14 DarkGray
    Write-HuntRow '-Last 30m'    'time window: 30m, 6h, 2d, 1w'                      14 DarkGray
    Write-HuntRow '-Max 100'     'how many hits to show (default 40)'                14 DarkGray
    Write-HuntRow '-Field N=rx'  'filter one event-data field; N!=rx excludes'       14 DarkGray
    Write-HuntRow '-Count N'     'aggregate by a field instead of listing events'    14 DarkGray
    Write-HuntRow '-Show a,b'    'pick output columns from any event-data field'     14 DarkGray
    Write-HuntRow '-Full'        'include the rendered event message'                14 DarkGray
    Write-HuntRow '-Raw'         'emit objects for the pipeline instead of a table'  14 DarkGray
    Write-HuntRow '-On host1'    'run against another machine (needs rights)'        14 DarkGray
    Write-Host ''
    Write-Host '  Keywords match event DATA (command lines, paths, users, IPs), not the' -ForegroundColor DarkGray
    Write-Host '  rendered description. Regex works; if it will not compile it is treated' -ForegroundColor DarkGray
    Write-Host '  as literal text, so C:\Users\bob is fine as-is.' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-HuntSources {
    Write-Host ''
    Write-Host '  SOURCES' -ForegroundColor Yellow -NoNewline
    Write-Host '   (Events = records present on this host right now)' -ForegroundColor DarkGray
    Write-Host ''
    $rows = foreach ($k in $script:HuntSources.Keys) {
        $src = $script:HuntSources[$k]
        $total = 0; $present = 0
        foreach ($log in $src.Logs) {
            $li = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
            if ($li) { $present++; $total += [int64]$li.RecordCount }
        }
        $state = 'missing'
        if ($present -gt 0 -and $present -eq $src.Logs.Count) { $state = 'ok' }
        elseif ($present -gt 0) { $state = "partial ($present/$($src.Logs.Count))" }
        $count = 0
        if ($present -gt 0) { $count = $total }
        [pscustomobject]@{
            Source = $k
            Status = $state
            Events = $count
            Covers = $src.Desc
        }
    }
    # Render into the information stream too, or the table lands after the
    # footer when both streams are interleaved by the host.
    Write-Host (($rows | Format-Table -AutoSize -Wrap | Out-String).TrimEnd())
    Write-Host ''
    $aliasText = ($script:HuntAliases.Keys | Sort-Object | ForEach-Object { "$_=$($script:HuntAliases[$_])" }) -join '  '
    Write-Host '  aliases: ' -ForegroundColor DarkGray -NoNewline
    Write-Host $aliasText -ForegroundColor DarkGray
    Write-Host '  any other value is used as a literal channel name, e.g. hunt "Microsoft-Windows-Bits-Client/Operational"' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-HuntPlays {
    param([string[]]$Filter)
    $terms = @()
    foreach ($t in @($Filter)) { if ($t -and $t -notmatch '^(or|and|not)$') { $terms += $t } }
    Write-Host ''
    Write-Host '  PLAYS' -ForegroundColor Yellow -NoNewline
    Write-Host '   run with: hunt play <name> [-Last 24h] [-Max 100]' -ForegroundColor DarkGray
    Write-Host ''
    $shown = 0
    foreach ($k in $script:HuntPlays.Keys) {
        $play = $script:HuntPlays[$k]
        if ($terms.Count -gt 0) {
            $hay = $k + ' ' + $play.Desc
            $ok = $false
            foreach ($t in $terms) { if ($hay -match [regex]::Escape($t)) { $ok = $true; break } }
            if (-not $ok) { continue }
        }
        $srcs = (@($play.Steps | ForEach-Object { $_.S }) | Select-Object -Unique) -join ','
        Write-Host ('  ' + $k.PadRight(12)) -ForegroundColor Cyan -NoNewline
        Write-Host $play.Desc
        Write-Host ('  ' + ''.PadRight(12) + $srcs) -ForegroundColor DarkGray
        $shown++
    }
    if ($shown -eq 0) { Write-Host '  nothing matched. try: hunt plays' -ForegroundColor DarkGray }
    Write-Host ''
}

function Show-HuntIds {
    param([string[]]$Term)
    $t = ''
    if ($Term -and $Term.Count -gt 0) { $t = ($Term -join ' ').Trim() }

    # A bare number: which log is that id in?
    if ($t -match '^\d+$') {
        $n = [int]$t
        $found = $false
        Write-Host ''
        foreach ($src in ($script:HuntIds.Keys | Sort-Object)) {
            if ($script:HuntIds[$src].ContainsKey($n)) {
                Write-Host ('  ' + $src.PadRight(12)) -ForegroundColor Cyan -NoNewline
                Write-Host ("{0}  -  {1}" -f $n, $script:HuntIds[$src][$n])
                Write-Host ('  ' + ''.PadRight(12) + "hunt $src -Id $n") -ForegroundColor DarkGray
                $found = $true
            }
        }
        if (-not $found) { Write-Host "  event id $n is not in the cheat sheet. Try: hunt ids security" -ForegroundColor DarkGray }
        Write-Host ''
        return
    }

    $srcKey = ''
    if ($t) {
        $resolved = $t.ToLower()
        if ($script:HuntAliases.ContainsKey($resolved)) { $resolved = $script:HuntAliases[$resolved] }
        if ($script:HuntIds.ContainsKey($resolved)) { $srcKey = $resolved }
    }

    # A source name: print its cheat sheet.
    if ($srcKey) {
        Write-Host ''
        Write-Host ("  {0} EVENT IDS" -f $srcKey.ToUpper()) -ForegroundColor Yellow
        Write-Host ''
        foreach ($id in ($script:HuntIds[$srcKey].Keys | Sort-Object { [int]$_ })) {
            Write-Host ('  ' + ([string]$id).PadRight(8)) -ForegroundColor Cyan -NoNewline
            Write-Host $script:HuntIds[$srcKey][$id]
        }
        Write-Host ''
        return
    }

    # Free text: search every description.
    if ($t) {
        $rx = New-HuntRegex $t
        $hits = 0
        Write-Host ''
        foreach ($src in ($script:HuntIds.Keys | Sort-Object)) {
            foreach ($id in ($script:HuntIds[$src].Keys | Sort-Object { [int]$_ })) {
                $desc = [string]$script:HuntIds[$src][$id]
                if ($rx.IsMatch($desc) -or $rx.IsMatch([string]$id)) {
                    Write-Host ('  ' + "$src $id".PadRight(20)) -ForegroundColor Cyan -NoNewline
                    Write-Host $desc
                    $hits++
                }
            }
        }
        if ($hits -eq 0) { Write-Host "  nothing matched '$t'. Try: hunt where $t" -ForegroundColor DarkGray }
        Write-Host ''
        return
    }

    Write-Host ''
    Write-Host '  cheat sheets available:' -ForegroundColor Yellow
    foreach ($src in ($script:HuntIds.Keys | Sort-Object)) {
        Write-HuntRow $src ("{0} ids   ->  hunt ids {1}" -f $script:HuntIds[$src].Count, $src) 14
    }
    Write-Host ''
    Write-Host '  or look an id up directly: hunt ids 4625' -ForegroundColor DarkGray
    Write-Host ''
}

function Find-HuntTarget {
    param([string[]]$Term)
    $t = ''
    if ($Term -and $Term.Count -gt 0) { $t = ($Term -join ' ').Trim() }
    if (-not $t) {
        Write-Host ''
        Write-Host '  hunt where <what you are looking for>' -ForegroundColor Yellow
        Write-Host '  e.g. hunt where mimikatz | hunt where persistence | hunt where brute force' -ForegroundColor DarkGray
        Write-Host ''
        return
    }

    $rx = New-HuntRegex $t
    $scored = New-Object Collections.ArrayList

    foreach ($e in $script:HuntIndex) {
        if ($rx.IsMatch($e.T) -or ($t -match $e.T)) {
            [void]$scored.Add([pscustomobject]@{ Score = 10; Run = $e.Run; Why = $e.Why })
        }
    }
    foreach ($k in $script:HuntPlays.Keys) {
        $play = $script:HuntPlays[$k]
        $score = 0
        if ($rx.IsMatch($k))         { $score += 6 }
        if ($rx.IsMatch($play.Desc)) { $score += 4 }
        if ($score -gt 0) {
            [void]$scored.Add([pscustomobject]@{ Score = $score; Run = "hunt play $k"; Why = $play.Desc })
        }
    }
    foreach ($k in $script:HuntSources.Keys) {
        $src = $script:HuntSources[$k]
        $score = 0
        if ($rx.IsMatch($k))        { $score += 3 }
        if ($rx.IsMatch($src.Desc)) { $score += 2 }
        if ($score -gt 0) {
            [void]$scored.Add([pscustomobject]@{ Score = $score; Run = "hunt $k"; Why = $src.Desc })
        }
    }
    foreach ($src in ($script:HuntIds.Keys | Sort-Object)) {
        foreach ($id in ($script:HuntIds[$src].Keys | Sort-Object { [int]$_ })) {
            $desc = [string]$script:HuntIds[$src][$id]
            if ($rx.IsMatch($desc)) {
                [void]$scored.Add([pscustomobject]@{ Score = 2; Run = "hunt $src -Id $id"; Why = $desc })
            }
        }
    }

    Write-Host ''
    if ($scored.Count -eq 0) {
        Write-Host "  Nothing in the catalogue mentions '$t'." -ForegroundColor DarkGray
        Write-Host '  It may still be in the data - keywords search event fields directly:' -ForegroundColor DarkGray
        Write-Host ("    hunt sysmon {0}" -f $t) -ForegroundColor Cyan
        Write-Host ("    hunt all {0} -Max 100" -f $t) -ForegroundColor Cyan
        Write-Host ''
        return
    }
    Write-Host ("  WHERE TO LOOK FOR '{0}'" -f $t.ToUpper()) -ForegroundColor Yellow
    Write-Host ''
    $seen = @{}
    $n = 0
    foreach ($row in ($scored | Sort-Object Score -Descending)) {
        if ($seen.ContainsKey($row.Run)) { continue }
        $seen[$row.Run] = $true
        Write-Host ('  ' + $row.Run.PadRight(30)) -ForegroundColor Cyan -NoNewline
        Write-Host $row.Why
        $n++
        if ($n -ge 8) { break }
    }
    Write-Host ''
    Write-Host ("  or search the raw data: hunt all {0}" -f $t) -ForegroundColor DarkGray
    Write-Host ''
}

Set-Alias -Name hunt -Value Invoke-Hunt -Force
