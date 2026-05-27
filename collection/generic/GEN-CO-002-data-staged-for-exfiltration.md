# GEN-CO-002 — Collection: Data Staged for Exfiltration

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CO-002` |
| **MITRE Tactic** | Collection |
| **MITRE Technique** | T1074 — Data Staged |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceFileEvents` · `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Large archive files (ZIP, RAR, 7z, tar.gz) created in user-writable staging locations — indicating data is being packaged for exfiltration. Commonly follows bulk file collection (browsing file shares, SharePoint downloads). The staging archive is usually created immediately before exfiltration, providing a detection window of minutes to hours.

---

## Microsoft Sentinel KQL

```kql
// GEN-CO-002 | Frequency: 10m | Lookback: 30m
// Detection A: Large archive created in staging location
let StagingPaths = dynamic(["Temp","Downloads","Desktop","AppData","ProgramData","Public","Recycle"]);
let ArchiveExtensions = dynamic([".zip",".7z",".rar",".tar",".gz",".tar.gz",".tgz",".cab"]);
DeviceFileEvents
| where TimeGenerated >= ago(30m)
| where ActionType == "FileCreated"
| where FileName has_any (ArchiveExtensions)
| where FolderPath has_any (StagingPaths)
| summarize ArchiveCount=count(), TotalFiles=dcount(FileName), 
    Archives=make_set(FileName,5)
    by DeviceName, AccountName, InitiatingProcessFileName, bin(TimeGenerated, 10m)
| where ArchiveCount >= 1
| extend AlertTitle = strcat("Data Staged: Archive created in staging path on ", DeviceName)
```

```kql
// Detection B: Mass archive tool usage (7zip, WinRAR, compact.exe)
DeviceProcessEvents
| where TimeGenerated >= ago(30m)
| where FileName in~ ("7z.exe","7za.exe","rar.exe","winrar.exe","compact.exe","zip.exe")
| where ProcessCommandLine has_any ("a ","add","e ","extract","-r")
| where ProcessCommandLine has_any (
    "Temp","AppData","ProgramData","Users\\Public","Desktop","Downloads"
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-CO-002 | Run: Every hour
DeviceFileEvents
| where Timestamp >= ago(1h)
| where ActionType == "FileCreated"
| where FileName has_any (".zip",".7z",".rar",".tar",".gz",".cab")
| where FolderPath has_any ("Temp","Downloads","Desktop","AppData","Public")
| where InitiatingProcessFileName !in~ ("Teams.exe","OneDrive.exe","BackupAgent.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1 — What was archived? (0–10 min)**
What is in the archive? Can you identify file names from process command line arguments?
Is this staging financial records, source code, client data?

**Step 2 — Exfiltration imminent (10–20 min)**
Run GEN-EF-001 and GEN-CC-001 on the same device — is exfiltration already in progress?
Check outbound connections from the staging device.

**Step 3 — Scope of data (20–35 min)**
What files were added to the archive? Run DeviceFileEvents to see what was accessed before the archive was created.

---

## Response Actions
- [ ] Isolate the device if exfiltration is imminent or confirmed
- [ ] Preserve the archive file as forensic evidence (don't delete)
- [ ] Identify all files that were archived — scope the data exposure
- [ ] Block outbound connections from the device at the firewall

## References - [MITRE T1074](https://attack.mitre.org/techniques/T1074/)
