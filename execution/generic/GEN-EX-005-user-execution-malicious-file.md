# GEN-EX-005 — Execution: User Execution of Malicious File / ISO / LNK

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-EX-005` |
| **MITRE Tactic** | Execution |
| **MITRE Technique** | T1204.002 — User Execution: Malicious File |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` · `DeviceFileEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Detects users executing suspicious file types delivered via email or download: ISO/IMG disk images (used to bypass Mark of the Web), LNK shortcut files executing LOLBins, HTML Application (HTA) files, and OneNote file macro execution. These techniques emerged as primary delivery mechanisms after Microsoft blocked Office macros from internet-sourced files in 2022.

---

## Microsoft Sentinel KQL

```kql
// GEN-EX-005 | Frequency: 5m | Lookback: 5m
// Detection A: ISO/IMG mounted and executes payload
let ISOExecution = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where InitiatingProcessFolderPath has_any (":\\", "volume{")  // Mounted volume path
    | where FolderPath has_any ("AppData","Temp","Downloads","Desktop")
    | where InitiatingProcessFileName in~ (
        "explorer.exe","cmd.exe","powershell.exe","wscript.exe",
        "cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe"
    )
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
        InitiatingProcessFolderPath, SHA256
    | extend DetectionType = "ISO_Execution"
);
// Detection B: LNK/shortcut executing LOLBin
let LNKExecution = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where InitiatingProcessFileName =~ "explorer.exe"
    | where FileName in~ (
        "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
        "mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe"
    )
    | where ProcessCommandLine has_any (
        "-EncodedCommand","-enc ","IEX","DownloadString",
        "WebClient","FromBase64String","hidden"
    )
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
    | extend DetectionType = "LNK_LOLBin"
);
// Detection C: OneNote spawning suspicious process
let OneNoteExec = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(5m)
    | where InitiatingProcessFileName =~ "ONENOTE.EXE"
    | where FileName in~ (
        "cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe"
    )
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
    | extend DetectionType = "OneNote_Macro"
);
ISOExecution | union LNKExecution | union OneNoteExec
| extend AlertTitle = strcat("Malicious File Execution: ", DetectionType)
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-EX-005 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where InitiatingProcessFileName in~ ("ONENOTE.EXE","mshta.exe","wscript.exe")
    and FileName in~ ("cmd.exe","powershell.exe","cscript.exe","regsvr32.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
```

---

## Investigation Guide
**Step 1:** Identify the parent file type — ISO, LNK, OneNote, HTA.
**Step 2:** Decode any PowerShell command (see GEN-EX-001 procedure).
**Step 3:** Check network connections and file writes from the spawned process.
**Step 4:** Run GEN-IA-005 email check — was this delivered by phishing link?

## Response Actions
- [ ] Isolate device
- [ ] Block file hash in MDE custom indicators
- [ ] Block sender domain if email-delivered
- [ ] Enable ASR rule: Block JavaScript or VBScript from launching downloaded executable content

## References - [MITRE T1204.002](https://attack.mitre.org/techniques/T1204/002/)
