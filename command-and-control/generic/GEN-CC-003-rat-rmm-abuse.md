# GEN-CC-003 — C2: Legitimate Remote Access Tool / RMM Abuse

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CC-003` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | T1219 — Remote Access Software |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceProcessEvents` · `DeviceNetworkEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

A legitimate remote access or RMM tool — AnyDesk, ScreenConnect (ConnectWise), TeamViewer, Atera, Splashtop, PDQ, NinjaRMM, Fleetdeck, Twingate — installed or executed without going through the approved IT management process. Attackers and BEC operators increasingly abuse these tools as they are trusted by AV/EDR and blend with legitimate IT activity. Also covers tools dropped by phishing payloads that appear as legitimate software.

---

## Microsoft Sentinel KQL

```kql
// GEN-CC-003 | Frequency: 5m | Lookback: 15m
let ApprovedRMM = (_GetWatchlist('ApprovedRMMTools') | project SearchKey);  // Populate with approved tool names/hashes
let RMMTools = dynamic([
    "anydesk.exe","AnyDesk.exe",
    "ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe",
    "TeamViewer.exe","TeamViewer_Service.exe","tv_w32.exe","tv_x64.exe",
    "atera_agent.exe","AteraAgent.exe",
    "splashtop.exe","SRService.exe",
    "fleetdeck-agent.exe","fleetdeck.exe",
    "NinjaRMMAgent.exe","ninjarmm.exe",
    "pdq_agent.exe","PDQDeployRunner.exe",
    "ultraviewer.exe","UltraViewer_Desktop.exe",
    "zoho_assist.exe","ZohoAssist.exe",
    "rustdesk.exe","RustDesk.exe",
    "meshagent.exe","MeshCentral.exe"
]);
DeviceProcessEvents
| where TimeGenerated >= ago(15m)
| where FileName in~ (RMMTools)
| where not(SHA256 in (ApprovedRMM))  // Not pre-approved hash
| where FolderPath !has_any ("Program Files","ProgramData\\APPROVED_RMM")
    or InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath,
    ProcessCommandLine, SHA256, InitiatingProcessFileName
| extend AlertTitle = strcat("Unapproved RMM Tool: ", FileName, " on ", DeviceName)
| extend RiskNote = "Legitimate RMM tools used as C2 — verify with IT if this was authorised"
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-CC-003 | Run: Every hour
let RMM = dynamic(["anydesk.exe","ScreenConnect","TeamViewer","atera_agent","splashtop","rustdesk","meshagent"]);
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where FileName has_any (RMM)
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
    or FolderPath has_any ("Temp","AppData","Downloads","Desktop","Public")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, SHA256
```

---

## Investigation Guide

**Step 1 — IT approval check (0–10 min)**
Was this RMM tool installed by the IT team? Is there an ITSM ticket?
Contact the device owner's manager — are they expecting a remote support session?

**Step 2 — Installation vector (10–20 min)**
Was the RMM tool dropped by a phishing payload? Check for prior GEN-IA-001 / GEN-EX-001 alerts.
Was it installed from a temp or download directory? = attacker-dropped.

**Step 3 — Active session check (20–30 min)**
Is the RMM tool currently running with an active session?
Kill the process immediately if not authorised.

---

## Response Actions
- [ ] Kill the RMM process via MDE Live Response
- [ ] Block the RMM tool's C2 domains/IPs in MDE custom indicators
- [ ] If deployed by phishing: full GEN-IA-001 investigation
- [ ] Populate `ApprovedRMMTools` watchlist with authorised tool hashes for future baseline

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| IT team remotely troubleshooting via approved RMM | Add approved tool SHA256 hashes to `ApprovedRMMTools` watchlist |

## References - [MITRE T1219](https://attack.mitre.org/techniques/T1219/)
