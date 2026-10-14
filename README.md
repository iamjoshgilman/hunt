# hunt

**Threat hunting for Windows event logs, from the command line.**

[![tests](https://github.com/iamjoshgilman/hunt/actions/workflows/test.yml/badge.svg)](https://github.com/iamjoshgilman/hunt/actions/workflows/test.yml)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Search any channel by keyword, event ID, field or time window. Aggregate what
you find. Or run one of 44 prebuilt hunts for the behaviour you are chasing.

```powershell
hunt sysmon mimikatz                            # search event data across a channel
hunt sysmon -Id 3 -Field DestinationPort=445    # filter on any event-data field
hunt security -Id 4625 -Count TargetUserName    # aggregate: who is being sprayed
hunt play persist -Last 24h                     # a prebuilt hunt, time-bounded
hunt -Path triage.evtx mimikatz                 # a saved export, not a live host
hunt where ransomware                           # when you know what, not where
hunt ids 4625                                   # what is this event, and which log
```

Four things it does:

| | |
|---|---|
| **search** | any channel, by keyword (AND/OR/NOT), event ID, field or time window |
| **count** | aggregate by any event-data field, without writing a `Group-Object` |
| **plays** | 44 named hunts — credential theft, persistence, lateral movement, defence evasion, discovery |
| **lookup** | find the right log and event ID when you only know what you are after |

Results come back as objects with every event-data field promoted to a
property, so anything it does not do directly, the pipeline still can.

Single file, no dependencies, PowerShell 5.1+. Built for CTFs, HTB labs and
quick triage on a box you do not own — not as a replacement for a SIEM. If the
question needs joins and a timechart, go use Splunk.

<details>
<summary>What it replaces</summary>

```powershell
# this
hunt sysmon mimikatz

# instead of this
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational |
    Where-Object { $_.Id -eq 13 -and $_.Message -match 'mimikatz' } |
    Format-List Message
```
</details>

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

The `iex` form is the one to reach for on a locked-down host: dot-sourcing a
`.ps1` from disk is subject to execution policy and fails with
*"running scripts is disabled on this system"*, while `iex` of a string is not.
Nothing touches disk either way.

On an isolated target that cannot reach GitHub at all — most CTF and lab boxes
— stage it from your own machine instead. See
[On a box with no internet](#on-a-box-with-no-internet) just below.

### On a box with no internet

Which is most of them. A CTF or lab target usually has no egress at all, so
`irm` fails before it starts:

```
irm : The remote name could not be resolved: 'raw.githubusercontent.com'
```

That is DNS, not the tool. The target cannot reach GitHub, but it can reach
*you* over the VPN. Run one command on your own machine to stage it, then paste
the one line it prints into the target.

The launcher depends on your attacking box's shell — the command you paste into
the target is the same either way.

**On a Linux box (Pwnbox, Kali):**

```bash
curl -sL https://raw.githubusercontent.com/iamjoshgilman/hunt/main/serve.py | python3 -
```

**On a Windows or PowerShell box:**

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/iamjoshgilman/hunt/main/install.ps1))) -Remote
```

Either one prints:

```
  hunt staging server

  pulled     hunt.ps1  78,216 bytes  (from github)
  saved      /tmp/hunt.ps1
  serving    http://10.10.14.5:8000/hunt.ps1  [tun0]
  clipboard  copied with xclip

  copy this to the target:

  $b=(New-Object Net.WebClient).DownloadData('http://10.10.14.5:8000/hunt.ps1');if($b.Length -eq 78216){iex([Text.Encoding]::UTF8.GetString($b));hunt}else{"TRUNCATED $($b.Length)/78216"}

  waiting for the target to pull it ... ctrl-c to stop
```

It fetches hunt.ps1, picks your VPN address, serves it, copies that command to
your clipboard, and tells you when the target pulls it. Paste the command into
the target's shell — RDP, a reverse shell, Evil-WinRM, wherever you are — and
`hunt` is loaded. The target reaches back to you, so nothing on it needs
internet. One good pull is the job, so it prints `done` and stops on its own;
pass `--keep` / `-Keep` to stay up for more targets.

The command it prints is doing three things worth knowing about:

- **It checks the byte count before running anything.** A truncated transfer
  reports `TRUNCATED 41203/78216` rather than failing as a parse error
  somewhere in the middle of the catalogue — which is how `python3 -m
  http.server` fails, truncating large files to Windows clients at a different
  count each time. The staging server sends a correct `Content-Length` and the
  target verifies it; re-run the paste if it ever reports short.
- **Nothing touches the target's disk.** It runs from memory, which also keeps
  it clear of execution policy — that applies to running a `.ps1` file, not to
  `iex` of a string.
- **The server hands out one path.** It serves `/hunt.ps1` and 404s everything
  else, rather than exposing a whole directory to the target.

Flags, same idea on both launchers: `--ip` / `-Ip` when it guesses the wrong
interface, `--port` / `-Port`, `--keep` / `-Keep` to serve more than one target,
`--file` / `-Source` to stage a local copy when your own box is offline too, and
`--curl` / `-Curl` for a `curl.exe` target command instead of `Net.WebClient`.

If a box *does* have egress and `irm` still fails, Windows PowerShell 5.1
negotiates TLS 1.0 by default and GitHub refuses it:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

## The three commands that matter

The hard part of event-log hunting is not the syntax, it is knowing *where* to
look. Event IDs and the channels they live in are learned separately, which is
why "Defender detected malware" is ID 1116 but is **not** in the Security log.

```powershell
hunt where ransomware      # you know WHAT you want, not where it lives
hunt plays                 # 44 prebuilt hunts, by name
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
| `-Path f.evtx` | read saved exports — a file, a wildcard, or a folder (expands to its .evtx) |
| `-After` / `-Before` | absolute datetime bounds |

Tab completion covers source names, play names, event IDs for the chosen
source, and event-data field names for `-Show`, `-Count` and `-Field`.

## Output

Every hit carries the event ID *and* what it means, so the output teaches you
the IDs as you go:

```
Time      Id Event                                 Detail
----      -- -----                                 ------
14:22:07  10 Process access (LSASS reads live here) C:\Tools\mimikatz.exe | C:\Windows\system32\lsass.exe | 0x1410
14:22:05   1 Process creation                      LAB\jdoe | C:\Tools\mimikatz.exe | mimikatz.exe "privilege::debug" ...
```

The `Time` column always keeps seconds, and grows only as far back as it needs
to: `HH:mm:ss` for today, `MM-dd HH:mm:ss` earlier this year, and
`yyyy-MM-dd HH:mm:ss` for an older `.evtx`, so a years-old export still reads
exactly in the default table.

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
| `goldenish` | `psexec` | `lateral` |
| `lolbas` | `encoded` | `downloads` |
| `injection` | `hijack` | `dotnet` |
| `scripts` | `shadow` | `tamper` |
| `threats` | `newusers` | `admins` |
| `wmi` | `pipes` | `rdp` |
| `shares` | `clearlog` | `drivers` |
| `ads` | `uac` | `recon` |
| `boot` | `audit` | `blocked` |
| `handles` | `sharechange` |  |

Plays take the same options as a normal query:

```powershell
hunt play creds -Last 24h
hunt play spray -Last 7d          # already counts by account
hunt play procs mimikatz          # a play, narrowed by keyword
```

## Saved exports

Everything works the same against a `.evtx` file, which is how most DFIR
challenges hand you a log:

```powershell
hunt -Path triage.evtx mimikatz
hunt -Path triage.evtx -Id 4625 -Count TargetUserName
hunt play persist -Path triage.evtx
hunt -Path *.evtx lsass            # several files at once
hunt play hijack -Path C:\Logs\DLLHijack    # a folder - every .evtx inside it
```

Records keep their original channel, so event IDs still resolve to names and
the per-event detail fields still apply — a Sysmon 10 out of a file reads the
same as one off a live host. Grab an export with:

```powershell
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\export.evtx
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

## Speed

`hunt` drives `EventLogReader` rather than `Get-WinEvent`. On a Windows 10 host
with a 36,000-event Sysmon channel, measured:

| | per event | full channel scan |
|---|---|---|
| `Get-WinEvent` | 21 ms | ~13 minutes |
| `EventLogReader` | 0.23 ms | 18 seconds |

`Get-WinEvent` is the convenient wrapper around the same API, and it is ~80x
slower per record — enough to make a bare `hunt sysmon mimikatz` look hung.
Measured numbers on that host:

```
sysmon -Id 1 -Max 40 (id pushed into the query)      1.09s
sysmon powershell -Max 5 (matches, exits early)      0.08s
sysmon zzqqxx (no match, full 36k scan)             18.42s
security -Id 4624 -Count TargetUserName -Last 1d     0.42s
play persist -Max 5                                  3.55s
```

Three things keep it quick:

- **`-Id` and the time window are pushed down** into the event-log query as
  XPath, so unmatched events are never read.
- **Keywords match a single `ToXml()` string** per event — no XML parse and no
  provider message lookup unless an event actually matches.
- **`-Field Name=regex` pre-filters on that same string** before parsing, since
  a value can only match the field if it appears in the event at all.

Keyword matching has to happen client-side: the Windows event-log XPath dialect
has no `contains()`, so substring search cannot be pushed down. Narrow with
`-Id` or `-Last` when a channel is large.

## Notes

- The Security log needs an elevated session. `hunt` says so rather than
  throwing a raw access-denied.
- No Sysmon on the box? `hunt` tells you and points at `hunt security -Id 4688`.
- `-On <host>` needs the *Remote Event Log Management* firewall rules enabled on
  the target; `hunt` prints the `netsh` line to fix it rather than an RPC error.
- A keyword can hit channels you did not have in mind. `hunt sysmon certutil`
  matches Amcache registry writes (ID 13) as well as process creations, because
  the binary name genuinely appears in both. Add `-Id 1` when you only want
  execution.

## Tests

Three suites. The first two mock `Read-HuntRawEvents` — the only function that
touches the event log — so the whole search path runs anywhere:

```bash
pwsh -File tests/run.ps1      # units, query logic, search, discovery
pwsh -File tests/plays.ps1    # every play executes and is well-formed
pwsh -File tests/smoke.ps1    # Windows only: real channels, nothing mocked
```

Off-Windows, in a container:

```bash
docker run --rm -v "$PWD:/w" -w /w mcr.microsoft.com/powershell:latest \
    pwsh -NoProfile -File tests/run.ps1
```

CI runs the mocked suites on Linux and all three on Windows, under both
Windows PowerShell 5.1 and PowerShell 7. The smoke suite exists because the
interesting bugs were Windows-only: the event-log XPath dialect rejecting XML
entities in a time filter, and `TolerateQueryErrors` silently turning a missing
channel into an empty result.

## License

MIT. See [LICENSE](LICENSE).

Bring your own authorization. This reads local event logs; it does not change
anything on the host.
