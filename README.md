# hunt

Windows event logs, two words at a time.

```powershell
hunt sysmon mimikatz
```

instead of

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational |
    Where-Object { $_.Id -eq 13 -and $_.Message -match 'mimikatz' } | Format-List Message
```

Single file, no dependencies, PowerShell 5.1+. Built for CTFs, HTB labs and
quick triage on a box you do not own — not as a replacement for a SIEM. If the
question is complicated enough to need joins and a timechart, go use Splunk.

## Install

Permanent, for your own machine:

```powershell
iex (irm https://raw.githubusercontent.com/iamjoshgilman/hunt/main/install.ps1)
```

Session only, for a box you do not want to leave artifacts on:

```powershell
iex (irm https://raw.githubusercontent.com/iamjoshgilman/hunt/main/hunt.ps1)
```

Or drop `hunt.ps1` next to you and `. .\hunt.ps1`.

## The three commands that matter

The hard part of event-log hunting is not the syntax, it is knowing *where* to
look. Event IDs and the channels they live in are learned separately, which is
why "Defender detected malware" is ID 1116 but is **not** in the Security log.

```powershell
hunt where ransomware      # you know WHAT you want, not where it lives
hunt plays                 # 47 prebuilt hunts, by name
hunt ids 4625              # which log is this ID in, and what is it?
```

`hunt where` searches plays, sources, event-ID descriptions and a concept index,
then hands you a runnable command:

```
  WHERE TO LOOK FOR 'RANSOMWARE'

  hunt play shadow              vssadmin/wbadmin/bcdedit destruction commands
  hunt play threats             Defender detections and remediation outcomes
  hunt play tamper              Defender config changes and logging being switched off
```

## Query grammar

```
hunt <source> <keyword...> [options]
```

| Form | Example | Means |
|---|---|---|
| keyword | `hunt sysmon mimikatz` | matches event data |
| AND | `hunt sysmon lsass dmp` | both terms |
| OR | `hunt sysmon mimikatz or rubeus` | either term |
| OR | `hunt sysmon mimikatz,rubeus` | same thing, no spaces |
| NOT | `hunt sysmon powershell !svchost` | exclude |
| regex | `hunt sysmon 'cmd\|powershell'` | any .NET regex |

Keywords match the **event data** — command lines, paths, users, IPs — not the
rendered description. Regex works; anything that will not compile is treated as
literal text, so `hunt sysmon C:\Users\bob` does not blow up on `\U`.

## Options

| Option | Does |
|---|---|
| `-Id 1,3,11` | event IDs, pushed down into the log query (fast) |
| `-Last 30m` | time window: `30m`, `6h`, `2d`, `1w`; a bare number is hours |
| `-Max 100` | how many hits (default 40) |
| `-Field Name=rx` | filter one event-data field; `Name!=rx` excludes |
| `-Count Name` | aggregate by a field instead of listing events |
| `-Show a,b` | pick output columns from any event-data field |
| `-Full` | include the rendered event message |
| `-Raw` | emit objects for the pipeline instead of a table |
| `-On host` | query another machine |
| `-After` / `-Before` | absolute datetime bounds |

## Output

Every hit carries the event ID *and* what it means, so the output teaches you
the IDs as you go:

```
Time      Id Event                                 Detail
----      -- -----                                 ------
14:22:07  10 Process access (LSASS reads live here) C:\Tools\mimikatz.exe | C:\Windows\system32\lsass.exe | 0x1410
14:22:05   1 Process creation                      LAB\jdoe | C:\Tools\mimikatz.exe | mimikatz.exe "privilege::debug" ...
```

Every event-data field is also promoted to a real property, so the pipeline
still works:

```powershell
hunt sysmon -Id 3 -Raw | Group-Object DestinationPort | Sort-Object Count -Descending
hunt sysmon -Id 1 -Raw | Where-Object { $_.ParentImage -match 'winword' }
hunt security -Id 4625 -Count IpAddress
```

## Plays

A play is a named hunt that already knows the IDs, channels and filters.
`hunt plays` lists them all; `hunt play <name>` runs one.

| | | |
|---|---|---|
| `procs` | `tree` | `net` |
| `dns` | `creds` | `dumps` |
| `persist` | `sched` | `svc` |
| `spray` | `sprayip` | `logons` |
| `lockouts` | `kerberoast` | `dcsync` |
| `psexec` | `lateral` | `lolbas` |
| `encoded` | `downloads` | `injection` |
| `scripts` | `shadow` | `tamper` |
| `threats` | `newusers` | `admins` |
| `wmi` | `pipes` | `rdp` |
| `shares` | `clearlog` | `drivers` |
| `ads` | `uac` | `recon` |
| `boot` | `audit` | `blocked` |
| `handles` | `sharechange` | `goldenish` |

Plays take the same options as a normal query:

```powershell
hunt play creds -Last 24h
hunt play spray -Last 7d          # already counts by account
hunt play procs mimikatz          # a play, narrowed by keyword
```

## Sources

`hunt sources` prints the aliases, whether each channel exists on this host and
how many records it holds — so you can see where the data actually is before
you search it.

`sysmon` `security` `system` `app` `powershell` `defender` `tasks` `wmi` `rdp`
`smb` `firewall` `winrm` `bits` `applocker` `dns` `all`

Plus aliases (`sec`, `ps`, `av`, `fw`, `schtasks`, ...). Anything unrecognised
is used as a literal channel name:

```powershell
hunt "Microsoft-Windows-TaskScheduler/Operational" -Id 106
```

## Notes

- The Security log needs an elevated session. `hunt` says so rather than
  throwing a raw access-denied.
- `-Id` and the time window are pushed down into the event-log query. Keyword
  matching happens client-side, because the Windows event-log XPath dialect has
  no `contains()`.
- No Sysmon on the box? `hunt` tells you and points at `hunt security -Id 4688`.

## Tests

`tests/` mocks `Get-WinEvent` so the search path can be exercised off-Windows:

```bash
docker run --rm -v "$PWD:/w" -w /w mcr.microsoft.com/powershell:latest \
    pwsh -NoProfile -File /w/tests/run.ps1
```
