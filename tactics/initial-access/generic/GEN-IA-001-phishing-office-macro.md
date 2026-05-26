# GEN-IA-001 — Phishing: Office Macro Spawns Child Process

| Field | Value |
|-------|-------|
| Rule ID | GEN-IA-001 |
| Tactic | Initial Access |
| Technique | T1566.001 — Spearphishing Attachment |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceProcessEvents` (MDE) |

## Description
Office application (Word, Excel, PowerPoint) opens an email attachment and spawns a suspicious child process — a high-fidelity indicator of macro payload execution.

---

## Microsoft Sentinel KQL
```kql
// GEN-IA-001 | Frequency: 5m | Lookback: 5m
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","MSACCESS.EXE","ONENOTE.EXE")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe","bitsadmin.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
```
**Sentinel Settings:** Frequency `5m` · Lookback `5m` · Threshold `> 0` · Entity: Device, Account · Playbook: `PB-ISOLATE-HOST`

---

## Defender XDR — Advanced Hunting
```kql
// GEN-IA-001 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","MSACCESS.EXE","ONENOTE.EXE")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
```
**Custom Detection:** Severity `High` · Category `InitialAccess` · Entities: Device, User

---

## Defender for Endpoint — MDE Response
```kql
// MDE Live Response — run on the device to pull process tree
DeviceProcessEvents
| where DeviceId == "<DEVICE_ID>"
| where Timestamp >= ago(2h)
| project Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```
**MDE Action:** Isolate device immediately via MDE portal → Device page → Isolate device

---

## Defender for Office 365 — Correlate Email
```kql
// Find the originating phishing email
EmailAttachmentInfo
| where Timestamp >= ago(24h)
| where FileName endswith ".docm" or FileName endswith ".xlsm" or FileName endswith ".doc" or FileName endswith ".xls"
| join kind=inner (
    EmailEvents | where Timestamp >= ago(24h)
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction
) on NetworkMessageId
| where DeliveryAction != "Blocked"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, FileName, SHA256
```

---

## Investigation Guide

**Step 1 — Triage (< 5 min)**
1. Note device, user, parent Office process, and child command line.
2. Does command line contain `-EncodedCommand`, `IEX`, `DownloadString`, or a URL? → High confidence malicious.
3. Is device currently isolated? If not, isolate now.

**Step 2 — Email Source (5–15 min)**
Run the Defender for Office 365 query above. Block the sender domain in Exchange/MDO.

**Step 3 — Process Tree (15–25 min)**
Run the MDE Live Response query. Trace: Office → child → grandchild → network connections.

**Step 4 — Network Check (25–35 min)**
```kql
DeviceNetworkEvents
| where DeviceName == "<DEVICE>"
| where Timestamp >= ago(1h)
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
```

**Step 5 — Lateral Movement Check (35–50 min)**
```kql
DeviceLogonEvents
| where DeviceName == "<DEVICE>"
| where Timestamp >= ago(2h)
| where LogonType in ("Network","RemoteInteractive")
| project Timestamp, RemoteDeviceName, AccountName, LogonType
```

---

## Response Actions
- [ ] **Isolate device** — MDE portal
- [ ] **Block sender domain** — MDO / Exchange
- [ ] **Block attachment hash** — MDE custom indicators
- [ ] **Revoke user sessions** — Entra ID
- [ ] **Search other recipients** — same attachment hash across org
- [ ] **Submit to sandbox** — Defender Threat Intelligence
- [ ] **Open P1 incident ticket** — tag `PHISHING-MACRO`

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Signed corporate macros running helper scripts | Add process hash to GEN-IA-001-Exclusions watchlist |
| RMM tool launched by Office integration | Exclude by signed process hash only |

## References
- [MITRE T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [MDE: Device isolation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/respond-machine-alerts)
