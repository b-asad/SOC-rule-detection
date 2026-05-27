# SEC-LEG-EF-001 — Legal: Client Privileged Data Exfiltration

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-LEG-EF-001` |
| **MITRE Tactic** | Exfiltration |
| **MITRE Technique** | T1048 — Exfiltration Over Alternative Protocol |
| **Sector** | **Legal** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender for Endpoint |
| **Log Source** | `OfficeActivity` (M365 UAL) · `DeviceNetworkEvents` (MDE) · `CloudAppEvents` (MCAS) |
| **Sector Context** | Law firms, barristers chambers, in-house legal teams, legal process outsourcing |
| **Created** | May 2026 |

---

## Description

Detects potential exfiltration of legally privileged client data from law firm document management systems, SharePoint, or email. Legal firms hold some of the most commercially sensitive data — M&A transaction details, litigation strategies, client confidential communications — making them high-value targets for corporate espionage, nation-state actors, and disgruntled employees.

**Legal privilege** means disclosure may constitute contempt of court. The SRA Code of Conduct requires law firms to protect client confidentiality. UK GDPR applies to client personal data.

---

## Microsoft Sentinel KQL

```kql
// SEC-LEG-EF-001 | Frequency: 15m | Lookback: 1h | Threshold: > 0
let LegalKeywords = dynamic([
    "privileged","confidential","without prejudice","legal advice",
    "litigation","settlement","claim","instruction","matter",
    "client","contract","agreement","merger","acquisition",
    "counsel","barrister","solicitor","advice","legal opinion"
]);
let DMSPaths = dynamic([
    "iManage","NetDocuments","Worldox","OpenText","FileSite",
    "Matter","Client File","Legal","Privileged","Confidential"
]);
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in (
    "FileDownloaded","FileCopied","FileAccessed",
    "SharingInvitationCreated","AnonymousLinkCreated"
)
| where SourceFileName has_any (LegalKeywords)
    or Site_Url has_any (DMSPaths)
    or SourceFileName has_any ("confidential","privileged","without prejudice","settlement")
| summarize
    FileCount   = count(),
    UniqueFiles = dcount(SourceFileName),
    FileSample  = make_set(SourceFileName, 10),
    FirstEvent  = min(TimeGenerated),
    LastEvent   = max(TimeGenerated)
    by UserId, ClientIP, UserAgent
| where FileCount > 10
| extend IsExternal = (ClientIP !startswith "10." and ClientIP !startswith "192.168.")
| extend AlertTitle = strcat("Bulk Legal Document Download by ", UserId)
| extend PrivilegeRisk = "Legal professional privilege may be breached if documents shared with unauthorised parties"
| extend SRAObligation = "SRA Code 6.3: Notify client if confidentiality breach confirmed"
| order by FileCount desc
```

---

## Investigation Guide

**Step 1 — Employee and Matter Context (< 10 min)**
Is this fee earner working on these matters? Check the practice management system.
Is the employee on notice, under investigation, or about to join a competing firm?
Contact the managing partner (not the employee).

**Step 2 — Matter Sensitivity (10–25 min)**
What client matters do the downloaded files relate to?
- Live M&A transactions → market-sensitive information
- Active litigation → prejudice to proceedings
- Criminal defence files → serious privilege obligations

**Step 3 — External Destination (25–40 min)**
Did the files go to a personal email, cloud storage, or USB?
```kql
DeviceNetworkEvents | where AccountName contains "<USERNAME>" | where Timestamp >= ago(2h)
| where RemoteUrl has_any ("gmail","dropbox","wetransfer","outlook.com") and not(RemoteUrl has "<FIRM_DOMAIN>")
| project Timestamp, RemoteUrl, BytesSent, InitiatingProcessFileName
```

---

## Response Actions
**Immediate**
- [ ] Revoke document management system access
- [ ] Block personal cloud storage at proxy
- [ ] Notify Managing Partner, COLP (Compliance Officer for Legal Practice), and COFA

**Regulatory**
- [ ] SRA: Notify if client confidentiality breached (SRA Transparency Rules)
- [ ] ICO: Notify if client personal data exfiltrated (UK GDPR 72h)
- [ ] Client notification: Consider whether affected clients must be notified under professional obligations

## References
- [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
- [SRA: Confidentiality guidance](https://www.sra.org.uk/solicitors/guidance/confidentiality/)
- [ICO: Legal sector data protection](https://ico.org.uk/for-organisations/guide-to-data-protection/)
