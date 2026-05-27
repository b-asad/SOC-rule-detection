# SEC-MFG-IA-001 — Manufacturing: Phishing Targeting Engineering and OT Staff

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-MFG-IA-001` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1566.001 — Spearphishing Attachment |
| **Sector** | **Manufacturing** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 · Defender XDR · Defender for Endpoint |
| **Log Source** | `EmailEvents` · `EmailAttachmentInfo` · `DeviceProcessEvents` (MDE) |
| **Sector Context** | Manufacturing plants, engineering teams, OT operators, production managers, supply chain |
| **Created** | May 2026 |

---

## Description

Phishing campaigns targeting manufacturing engineers and OT operators use industry-specific lures: fake vendor invoices, AutoCAD drawing requests, PLC firmware update notifications, HSE compliance documents, and equipment maintenance manuals. Compromising an engineering account is the first step toward OT network pivoting (see SEC-MFG-LM-001) and production disruption.

Nation-state actors (VOLTZITE, Sandworm, APT33) use spearphishing against manufacturing staff as a primary OT access vector. Engineering workstations typically have access to SCADA/HMI engineering software and OT network segments.

**NIS2 applies** to manufacturing organisations operating critical infrastructure — significant cyber incidents require NCSC notification within 24 hours.

---

## Microsoft Sentinel KQL

```kql
// SEC-MFG-IA-001 | Frequency: 5m | Lookback: 1h
let MfgPhishKeywords = dynamic([
    "AutoCAD","SolidWorks","PLC","SCADA","HMI","firmware update",
    "maintenance schedule","HSE compliance","COSHH","ISO 9001","audit",
    "supplier invoice","purchase order","delivery note","RFQ","quotation",
    "equipment manual","calibration certificate","safety data sheet"
]);
let OTStaffPatterns = dynamic([
    "engineer","operations","maintenance","plant","production","ot","scada",
    "automation","process","manufacturing","quality","supervisor"
]);
// Detection 1: Phishing email to engineering/OT staff
let PhishToEngineering = (
    EmailEvents
    | where TimeGenerated >= ago(1h)
    | where DeliveryAction != "Blocked"
    | where ThreatTypes != ""
    | where Subject has_any (MfgPhishKeywords)
        or RecipientEmailAddress has_any (OTStaffPatterns)
    | project TimeGenerated, RecipientEmailAddress, SenderFromAddress,
        SenderFromDomain, Subject, ThreatTypes, AttachmentCount, NetworkMessageId
    | extend DetectionType = "PhishingToEngineeringStaff"
);
// Detection 2: Office macro execution on engineering workstation
let MacroOnEngHost = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(1h)
    | where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE")
    | where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")
    | where DeviceName has_any ("eng","ot","plc","scada","hmi","plant","mfg","production","ops","auto")
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
    | extend DetectionType = "MacroOnEngineeringHost"
);
PhishToEngineering | union MacroOnEngHost
| extend AlertTitle = strcat("Manufacturing Phishing: ", DetectionType)
| extend OTRisk = "Engineering account compromise may enable OT network pivot — see SEC-MFG-LM-001"
| extend NIS2Note = "NIS2 applies if organisation is critical manufacturing infrastructure"
```

---

## Defender for Office 365

```kql
// Find all engineering recipients of the same phishing campaign
EmailAttachmentInfo
| where Timestamp >= ago(24h) | where SHA256 == "<ATTACHMENT_SHA256>"
| join kind=inner (
    EmailEvents | where Timestamp >= ago(24h) | where DeliveryAction != "Blocked"
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject
) on NetworkMessageId
| where RecipientEmailAddress has_any ("engineer","plant","production","ot","operations")
| distinct RecipientEmailAddress, SenderFromAddress, Subject
```

---

## Defender for Endpoint

```kql
// Process tree on the engineering workstation
DeviceProcessEvents
| where DeviceName == "<ENGINEERING_DEVICE>"
| where Timestamp between (ago(2h) .. now())
| project Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine,
    AccountName, FolderPath, SHA256
| order by Timestamp asc
```

```kql
// Network connections from engineering host post-infection
DeviceNetworkEvents
| where DeviceName == "<ENGINEERING_DEVICE>"
| where Timestamp between (ago(2h) .. now())
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","wscript.exe")
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, BytesSent
```

---

## Investigation Guide

**Step 1 — OT access assessment (0–5 min)**
What OT systems does the affected engineering account have access to?
- PLC programming software (RSLogix, TIA Portal, Studio 5000)?
- SCADA/HMI engineering access?
- OT network segments?

If yes: notify OT Security team and plant manager SIMULTANEOUSLY with device isolation.

**Step 2 — Device isolation (0–5 min, parallel)**
Isolate the engineering workstation via MDE. Verify isolation does not disrupt any live OT communications (confirm with plant engineer before isolating OT-connected devices).

**Step 3 — Campaign scope (5–20 min)**
Run the MDO campaign query — how many engineering staff received the same phishing email?

**Step 4 — C2 and lateral movement check (20–40 min)**
Run the network connections query. Has the device made connections to OT network ranges?
```kql
DeviceNetworkEvents
| where DeviceName == "<ENGINEERING_DEVICE>" | where Timestamp >= ago(2h)
| where RemoteIP has_any (_GetWatchlist('OTNetworkRanges') | project SearchKey)
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
```
If OT network connections found: escalate to SEC-MFG-LM-001 procedure immediately.

---

## Response Actions

**Immediate**
- [ ] Isolate engineering workstation (confirm with plant engineer before isolating OT-connected devices)
- [ ] Notify OT Security team and Plant Manager
- [ ] Block sender domain in MDO
- [ ] Revoke OT network access for the compromised engineering account

**Within 1 Hour**
- [ ] Search for C2 connections to OT network from the device
- [ ] Check all other engineering staff for the same phishing email — run campaign scope query
- [ ] Submit payload to sandbox for IOC extraction
- [ ] Issue security awareness alert to engineering team

**Regulatory**
- [ ] NIS2: If OT systems confirmed reached — report to NCSC within 24h

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Legitimate vendor sending CAD files or technical documentation | Verify sender domain with vendor contact by phone; add approved vendor domains to allowed list |
| AutoCAD or SolidWorks launching helper processes | Add specific signed CAD application child process patterns to exclusions watchlist |

## References
- [MITRE T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [NCSC: OT security guidance](https://www.ncsc.gov.uk/collection/operational-technology)
- [NIS2 Directive Article 23](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555)
