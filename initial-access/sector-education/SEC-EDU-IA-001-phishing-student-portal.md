# SEC-EDU-IA-001 — Education: Phishing Targeting Students and Academic Staff

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-EDU-IA-001` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1566.001 — Spearphishing Attachment |
| **Sector** | **Education** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Office 365 · Defender XDR · Defender for Endpoint |
| **Log Source** | `EmailEvents` · `EmailAttachmentInfo` · `DeviceProcessEvents` (MDE) |
| **Sector Context** | Universities, colleges, sixth forms, academies, research institutions |
| **Created** | May 2026 |

---

## Description

Phishing campaigns targeting education sector staff and students exploit time pressure, lack of security training, and the volume of routine administrative emails (enrolment, results, IT notifications). Common themes: fake student loan notifications, IT password expiry warnings, exam results links, library fine notices, bursary/scholarship offers, and HR payroll updates.

Ransomware groups (LockBit, Rhysida, Medusa) specifically time attacks around exam periods, enrolment windows, and academic year end — when institutions cannot afford downtime and are most likely to pay. A single phishing click can result in ransomware encrypting student records, research data, and VLE systems (see SEC-EDU-IM-001).

---

## Microsoft Sentinel KQL

```kql
// SEC-EDU-IA-001 | Frequency: 5m | Lookback: 1h
let EduPhishKeywords = dynamic([
    "student loan","financial aid","bursary","scholarship","UCAS","enrolment",
    "exam result","library fine","IT password","tuition fee","student finance",
    "payroll update","HMRC refund","council tax","NUS","student union",
    "verify your account","your account has been suspended","action required"
]);
// Detection 1: Phishing email delivered to education addresses
let PhishEmail = (
    EmailEvents
    | where TimeGenerated >= ago(1h)
    | where DeliveryAction != "Blocked"
    | where ThreatTypes != ""
    | where RecipientEmailAddress has_any (".ac.uk",".edu")
        or Subject has_any (EduPhishKeywords)
    | project TimeGenerated, RecipientEmailAddress, SenderFromAddress,
        SenderFromDomain, Subject, ThreatTypes, DeliveryAction, NetworkMessageId
    | extend DetectionType = "PhishingEmailDelivered"
);
// Detection 2: Office macro execution on education host (post-click)
let MacroExec = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(1h)
    | where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","ONENOTE.EXE")
    | where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")
    | where DeviceName has_any ("student","staff","lecture","lab","library","desktop","laptop","edu")
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
    | extend DetectionType = "MacroExecutionOnEduHost"
);
PhishEmail | union MacroExec
| extend AlertTitle = strcat("Education Phishing: ", DetectionType)
| extend JISCObligation = "Notify JISC if significant phishing campaign targeting the institution"
```

---

## Defender for Office 365

```kql
// Find all recipients of the same phishing email across the institution
EmailAttachmentInfo
| where Timestamp >= ago(24h)
| where SHA256 == "<ATTACHMENT_SHA256_FROM_ALERT>"
| join kind=inner (
    EmailEvents | where Timestamp >= ago(24h) | where DeliveryAction != "Blocked"
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject
) on NetworkMessageId
| distinct RecipientEmailAddress, SenderFromAddress, Subject
// Contact each recipient — check their device for macro execution
```

```kql
// Check if URL in phishing email was clicked
UrlClickEvents
| where Timestamp >= ago(24h)
| where AccountUpn has_any (".ac.uk",".edu")
| where ThreatTypes != ""
| project Timestamp, AccountUpn, Url, ActionType, ThreatTypes, IPAddress
| order by Timestamp desc
```

---

## Defender for Endpoint

```kql
// Process tree from device where phishing was executed
DeviceProcessEvents
| where DeviceName == "<DEVICE_FROM_ALERT>"
| where Timestamp between (ago(2h) .. now())
| project Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine,
    AccountName, FolderPath, SHA256
| order by Timestamp asc
```

```kql
// Network connections made after phishing execution
DeviceNetworkEvents
| where DeviceName == "<DEVICE_FROM_ALERT>"
| where Timestamp between (ago(2h) .. now())
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, BytesSent
```

---

## Investigation Guide

**Step 1 — Triage (0–5 min)**
Is this a delivered phishing email, a macro execution, or both?
- Email only: identify all recipients and warn them before they click
- Macro execution: isolate the device — this is already a compromise

**Step 2 — Campaign scope (5–20 min)**
Run the MDO recipient query above. How many students/staff received the same email?
Prepare a warning communication for IT to send to all affected recipients immediately.

**Step 3 — Clicked/executed check (20–35 min)**
Run the URL click events query. For any clicks, check the device for macro execution or credential entry.
For any macro execution found: follow GEN-IA-001 full investigation procedure.

**Step 4 — Research system impact assessment (35–60 min)**
Was the phishing successful on an account with access to research data, student records, or financial systems?
If research account: notify Research IT — potential data loss or ransomware precursor.

---

## Response Actions

**Immediate**
- [ ] Block sender domain and sender IP in MDO
- [ ] Soft-delete the phishing email from all recipient mailboxes: MDO → Threat Explorer → Take action
- [ ] For any device with macro execution: isolate via MDE
- [ ] Notify IT Security team and issue institution-wide phishing warning

**Within 1 Hour**
- [ ] Reset passwords for any accounts that clicked the link or executed the macro
- [ ] Submit attachment/URL to Microsoft Defender TI for detonation report
- [ ] Block C2 IPs and domains identified in payload
- [ ] Notify JISC Cyber Security if campaign is widespread

**Regulatory**
- [ ] If student or staff personal data was accessed: notify DPO — assess ICO notification (72h)

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Legitimate IT password reset campaign using similar subject | Verify sender domain is official IT; add to `InternalEmailDomains` watchlist |
| Student Union marketing emails flagged | Add SU domain to trusted senders list |

## References
- [MITRE T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [JISC: Phishing guidance for education](https://www.jisc.ac.uk/guides/phishing)
