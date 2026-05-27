# GEN-CC-004 — C2: Ingress Tool Transfer (Payload Download)

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CC-004` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | T1105 — Ingress Tool Transfer |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` · `DeviceFileEvents` · `DeviceNetworkEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

A native OS tool (certutil, bitsadmin, PowerShell DownloadString/DownloadFile, curl, wget, mshta) downloads a file from an external URL. This is the delivery mechanism for second-stage payloads — the attacker uses LOLBins to pull down malware after initial access, avoiding storing the payload in the phishing attachment.

---

## Microsoft Sentinel KQL

```kql
// GEN-CC-004 | Frequency: 5m | Lookback: 5m
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where (
    // certutil download
    (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-urlcache","-f","http","ftp"))
    // bitsadmin download
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ("/transfer","/download","http","ftp"))
    // PowerShell download
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any (
        "DownloadFile","DownloadString","DownloadData","Invoke-WebRequest",
        "iwr ","curl ","wget ","Start-BitsTransfer","New-Object Net.WebClient","WebClient"
    ) and ProcessCommandLine has_any ("http://","https://","ftp://"))
    // mshta remote HTA
    or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http://","https://","ftp://"))
    // curl/wget (native Windows 10+ or installed)
    or (FileName in~ ("curl.exe","wget.exe") and ProcessCommandLine has_any ("http","ftp") and ProcessCommandLine has_any ("-o ","-O","--output"))
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, SHA256
| extend AlertTitle = strcat("Ingress Tool Transfer via ", FileName)
// Extract download URL
| extend DownloadURL = extract(@"(https?://[^\s]+)", 0, ProcessCommandLine)
```

---

## Investigation Guide

**Step 1 — Extract and submit URL (0–5 min)**
Pull the `DownloadURL` from the command line. Submit to VirusTotal immediately.

**Step 2 — What was downloaded? (5–15 min)**
```kql
DeviceFileEvents | where DeviceName == "<DEVICE>" | where Timestamp >= ago(30m)
| where InitiatingProcessFileName in~ ("certutil.exe","bitsadmin.exe","powershell.exe","curl.exe","wget.exe")
| project Timestamp, FileName, FolderPath, SHA256, ActionType
```
Submit the downloaded file hash to VirusTotal.

**Step 3 — Was the payload executed? (15–25 min)**
Check for child process spawned from the download location.

---

## Response Actions
- [ ] Block the download URL and hosting domain
- [ ] Quarantine or delete the downloaded payload
- [ ] If payload executed: full compromise investigation

## References - [MITRE T1105](https://attack.mitre.org/techniques/T1105/)
