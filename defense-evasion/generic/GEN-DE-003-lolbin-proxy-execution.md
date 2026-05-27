# GEN-DE-003 — Defense Evasion: System Binary Proxy Execution (LOLBins)

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DE-003` |
| **MITRE Tactic** | Defense Evasion |
| **MITRE Technique** | T1218 — System Binary Proxy Execution |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Execution of malicious code via trusted, signed Windows binaries (Living-Off-the-Land Binaries — LOLBins) to bypass application whitelisting and reduce detection. Common LOLBins abused: `regsvr32.exe` (Squiblydoo), `mshta.exe` (HTA execution), `rundll32.exe` (DLL execution), `certutil.exe` (download/decode), `installutil.exe` (AppDomain execution), `msbuild.exe` (inline C# execution), `cmstp.exe` (INF file bypass).

---

## Microsoft Sentinel KQL

```kql
// GEN-DE-003 | Frequency: 5m | Lookback: 5m
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where (
    // regsvr32 loading remote scriptlet (Squiblydoo)
    (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("/s","/u","/n","/i:http","/i:ftp",".sct",".dll"))
    // mshta executing remote/local HTA
    or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http://","https://","ftp://","javascript:","vbscript:"))
    // certutil downloading or decoding
    or (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-urlcache","-decode","-decodehex","-ping","http","ftp"))
    // installutil executing arbitrary code
    or (FileName =~ "installutil.exe" and ProcessCommandLine has_any ("/logfile=","/LogToConsole=false"))
    // msbuild inline task execution
    or (FileName =~ "msbuild.exe" and ProcessCommandLine has_any (".xml",".csproj",".proj") and not(FolderPath has "Program Files"))
    // cmstp bypass
    or (FileName =~ "cmstp.exe" and ProcessCommandLine has_any ("/s",".inf"))
    // rundll32 executing script content
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has_any ("javascript:","vbscript:","shell32","http","https"))
    // wmic spawning child processes
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("process call create","os get /format:","http","ftp"))
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, SHA256, FolderPath
| extend AlertTitle = strcat("LOLBin Abuse: ", FileName)
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-DE-003 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("/i:http",".sct"))
    or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http://","https://","javascript:"))
    or (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-urlcache","-decode","http"))
    or (FileName =~ "installutil.exe" and ProcessCommandLine has "/logfile=")
    or (FileName =~ "msbuild.exe" and not(FolderPath has "Program Files") and ProcessCommandLine has ".xml")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1 — Decode and identify the payload (0–10 min)**
Extract the URL or file path from the command line. What is being loaded?
For certutil decode: the output file contains the real payload.

**Step 2 — Network connections (10–20 min)**
Did the LOLBin make any outbound connections?
```kql
DeviceNetworkEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(1h)
| where InitiatingProcessFileName in~ ("regsvr32.exe","mshta.exe","certutil.exe","msbuild.exe")
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
```

**Step 3 — Child processes and files written**
Did the LOLBin spawn a child process or drop a file to disk?

---

## Response Actions
- [ ] Kill the LOLBin process via MDE Live Response
- [ ] Block the download URL/IP in MDE custom indicators
- [ ] Block execution of the specific LOLBin if not needed in the environment (via AppLocker/WDAC)

## References
- [MITRE T1218](https://attack.mitre.org/techniques/T1218/)
- [LOLBAS Project](https://lolbas-project.github.io/)
