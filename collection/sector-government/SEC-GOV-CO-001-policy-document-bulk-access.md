# SEC-GOV-CO-001 — Government: Bulk Policy Document / Classified Material Access

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-GOV-CO-001` |
| **MITRE Tactic** | Collection |
| **MITRE Technique** | T1213 — Data from Information Repositories |
| **Sector** | **Government** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender for Endpoint |
| **Log Source** | `OfficeActivity` (M365 UAL) · `CloudAppEvents` (MCAS) · `AuditLogs` |
| **Sector Context** | Central government departments, Cabinet Office, FCDO, MoD, NDPBs |
| **Created** | May 2026 |

---

## Description

Bulk access to or download of policy documents, ministerial briefings, cabinet papers, diplomatic cables, or classified material from government SharePoint, document management systems, or secure repositories. Nation-state espionage actors (APT29/Cozy Bear, APT28/Fancy Bear, APT40) prioritise government document repositories for intelligence on policy positions, defence strategies, diplomatic communications, and forthcoming government decisions.

Insider threats — civil servants preparing to leave for lobbying roles, contractors with overly broad access, or politically motivated leakers — are also significant vectors. The Official Secrets Act 1989 applies to unauthorised disclosure of certain government information.

---

## Microsoft Sentinel KQL

```kql
// SEC-GOV-CO-001 | Frequency: 15m | Lookback: 1h
let GovSensitiveKeywords = dynamic([
    "OFFICIAL-SENSITIVE","OFFICIAL SENSITIVE","SECRET","TOP SECRET",
    "policy","briefing","cabinet","minister","strategy","classified",
    "restricted","diplomatic","intelligence","defence","national security",
    "No10","Downing","COBR","JIC","NSC","FCDO","FCO"
]);
// Detection 1: Bulk download from government document repositories
let BulkDownload = (
    OfficeActivity
    | where TimeGenerated >= ago(1h)
    | where Operation in ("FileDownloaded","FileCopied","FileAccessed","SearchQueryPerformed")
    | where SourceFileName has_any (GovSensitiveKeywords)
        or Site_Url has_any ("policy","cabinet","minister","briefing","strategy","restricted","classified","nsc","jic","fcdo","mod.uk")
    | summarize
        FileCount    = count(),
        UniqueFiles  = dcount(SourceFileName),
        FileSample   = make_set(SourceFileName, 10),
        FirstAccess  = min(TimeGenerated),
        LastAccess   = max(TimeGenerated)
        by UserId, ClientIP, UserAgent
    | where FileCount > 10
    | extend DetectionType = "BulkPolicyDocumentAccess"
);
// Detection 2: Sensitive document shared externally or anonymous link created
let ExternalShare = (
    OfficeActivity
    | where TimeGenerated >= ago(1h)
    | where Operation in ("AnonymousLinkCreated","SharingInvitationCreated","SharingSet")
    | where SourceFileName has_any (GovSensitiveKeywords)
        or Site_Url has_any ("policy","cabinet","minister","strategy","restricted")
    | project TimeGenerated, UserId, ClientIP, Operation, SourceFileName, Site_Url
    | extend DetectionType = "SensitiveDocumentSharedExternally"
);
BulkDownload | union ExternalShare
| extend AlertTitle = strcat("Gov Document Collection: ", DetectionType, " by ", UserId)
| extend SecurityNote = "Assess under Official Secrets Act 1989 if classified material involved"
| extend NCSObligation = "Report to NCSC if nation-state attribution suspected"
| order by FileCount desc
```

---

## Defender for Cloud Apps — MCAS Sensitivity Label Monitoring

```kql
// Monitor access to files labelled OFFICIAL-SENSITIVE or above
CloudAppEvents
| where Timestamp >= ago(1h)
| where ActionType in ("FileDownloaded","FileAccessed","FileCopied")
| where tostring(AdditionalFields.SensitivityLabelName) has_any (
    "OFFICIAL-SENSITIVE","SECRET","TOP SECRET","Classified","Restricted"
)
| summarize Count=count(), Files=make_set(tostring(AdditionalFields.FileName),10)
    by AccountUpn, AppName, IPAddress, CountryCode
| where Count > 5
| extend AlertTitle = strcat("Classified Document Access: ", Count, " files by ", AccountUpn)
```

---

## Defender for Endpoint — Post-Download Activity

```kql
// Was document collection staged for exfiltration?
DeviceFileEvents
| where DeviceName == "<DEVICE_FROM_ALERT>"
| where Timestamp between (ago(4h) .. now())
| where ActionType in ("FileCopied","FileCreated")
| where FileName has_any (".zip",".7z",".rar",".tar",".gz")
| where FolderPath has_any ("Temp","Downloads","Desktop","AppData","USB","Removable")
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, AccountName
```

```kql
// Check for USB/removable media usage (common physical exfiltration method in government)
DeviceEvents
| where DeviceName == "<DEVICE_FROM_ALERT>"
| where Timestamp >= ago(24h)
| where ActionType in ("UsbDriveMount","RemovableMediaMount","PnpDeviceConnected")
| project Timestamp, DeviceName, AccountName, AdditionalFields
```

---

## Investigation Guide

**Step 1 — Access legitimacy (0–10 min)**
Is this user's role consistent with needing these documents?
Contact the user's line manager by phone — do not email (email may be monitored if nation-state compromise).
Is the user currently on notice, under investigation, or has access recently been expanded?

**Step 2 — Document sensitivity (10–25 min)**
What classification level are the accessed documents?
- OFFICIAL: standard investigation
- OFFICIAL-SENSITIVE: escalate to Head of Security
- SECRET or above: escalate to SIRO, DSO, and potentially NCSC immediately

**Step 3 — Exfiltration check (25–40 min)**
Run the staging and USB queries above. Was data archived or transferred to removable media?
Check outbound network traffic from the device for uploads to external services.

**Step 4 — Attribution indicators (40–60 min)**
Is the access pattern consistent with a human browsing (random intervals, varied file types) or automated tool (regular intervals, systematic coverage)?
Automated/systematic = higher likelihood of compromised account or insider tool use.
Submit IOCs (source IP, user agent, access patterns) to NCSC.

---

## Response Actions

**Immediate**
- [ ] Suspend the user's SharePoint/document system access pending investigation
- [ ] Notify Departmental Security Officer (DSO) and SIRO immediately
- [ ] Do NOT alert the user — this may be an ongoing insider threat or nation-state operation

**Within 1 Hour**
- [ ] Preserve all access logs (SharePoint audit, MDE telemetry, network logs)
- [ ] Check for exfiltration indicators (uploads, USB usage, printing)
- [ ] Brief Head of Department (not via the affected user's communication channels)

**Regulatory**
- [ ] Report to NCSC via [report.ncsc.gov.uk](https://report.ncsc.gov.uk) if nation-state indicators
- [ ] Notify Cabinet Office if classified documents are involved
- [ ] Consider Official Secrets Act referral if SECRET or above material accessed without need

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Senior analyst conducting policy research across multiple documents | Verify with line manager; access patterns should show reading behaviour not systematic bulk download |
| Legitimate document migration during system refresh | IT migration accounts should have specific service account identities — exclude by account name with CISO approval |

## References
- [MITRE T1213](https://attack.mitre.org/techniques/T1213/)
- [NCSC: Insider threat guidance](https://www.ncsc.gov.uk/collection/insider-threat)
- [Official Secrets Act 1989](https://www.legislation.gov.uk/ukpga/1989/6/contents)
