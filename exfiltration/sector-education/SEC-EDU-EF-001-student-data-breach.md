# SEC-EDU-EF-001 — Education: Student PII Exfiltration

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-EDU-EF-001` |
| **MITRE Tactic** | Exfiltration |
| **MITRE Technique** | T1048 — Exfiltration Over Alternative Protocol |
| **Sector** | **Education** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender for Endpoint |
| **Log Source** | `CommonSecurityLog` (Firewall) · `CloudAppEvents` (MCAS) · `DeviceNetworkEvents` (MDE) |
| **Sector Context** | Student Information Systems (SITS, Banner, Unit-e), SRS databases, HR systems |
| **Created** | May 2026 |

---

## Description

Exfiltration of student personal data — name, date of birth, address, National Insurance number, academic records, financial aid details, health disclosures — to external services. Education institutions hold large volumes of student PII and are subject to UK GDPR. Confirmed breach of student personal data requires ICO notification within 72 hours and may require direct notification to affected students.

Common exfiltration paths: personal cloud storage, web-based file transfer services, personal email. Common vectors: compromised staff accounts, insider threat from departing staff, and post-ransomware attacker data staging.

---

## Microsoft Sentinel KQL

```kql
// SEC-EDU-EF-001 | Frequency: 15m | Lookback: 1h
let PersonalCloudServices = dynamic([
    "dropbox.com","wetransfer.com","drive.google.com","mega.nz",
    "box.com","mediafire.com","sendspace.com","onedrive.live.com",
    "icloud.com","files.fm","gofile.io","transfer.sh"
]);
// Detection 1: Upload to personal cloud from education host
let CloudUpload = (
    CommonSecurityLog
    | where TimeGenerated >= ago(1h)
    | where DeviceAction !in ("deny","block","drop")
    | where DestinationHostName has_any (PersonalCloudServices)
    | where SentBytes > 2000000  // > 2MB — typical for student record exports
    | project TimeGenerated, SourceIP, DeviceName, DestinationHostName, SentBytes
    | extend DetectionType = "PersonalCloudUpload"
);
// Detection 2: MDE process writing student data files then making external connection
let StagingAndExfil = (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(1h)
    | where RemoteUrl has_any (PersonalCloudServices)
    | where BytesSent > 1000000
    | project TimeGenerated, DeviceName, AccountName, RemoteUrl, BytesSent, InitiatingProcessFileName
    | extend DetectionType = "MDE-ExternalUpload"
);
CloudUpload | union StagingAndExfil
| extend AlertTitle = strcat("Student Data Exfiltration to ", DestinationHostName)
| extend GDPRObligation = "UK GDPR Article 33: Notify ICO within 72h if student personal data confirmed exfiltrated"
```

---

## Defender for Cloud Apps

Enable MCAS anomaly policy: **Unusual file download** and configure file policy:
- Filter: File label = Sensitive or Confidential AND shared externally
- Alert: High severity
- Governance: Revoke external sharing links

```kql
// MCAS audit: who uploaded to external services in the last 7 days
CloudAppEvents
| where Timestamp >= ago(7d)
| where ActionType in ("FileUploaded","FileShared","FileDownloaded")
| where AppName has_any ("Dropbox","Google Drive","Box","OneDrive Personal","WeTransfer")
| summarize Count=count(), Files=make_set(tostring(AdditionalFields.FileName),10)
    by AccountUpn, AppName, IPAddress
| order by Count desc
```

---

## Defender for Endpoint — Staging Investigation

```kql
// Was data staged locally before exfiltration?
DeviceFileEvents
| where DeviceName == "<DEVICE_FROM_ALERT>"
| where Timestamp between (ago(4h) .. now())
| where FileName has_any (".csv",".xlsx",".zip",".tar",".7z",".rar")
| where FolderPath has_any ("Temp","Downloads","Desktop","AppData")
| project Timestamp, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

```kql
// What process initiated the upload?
DeviceNetworkEvents
| where DeviceName == "<DEVICE_FROM_ALERT>"
| where RemoteUrl has_any ("dropbox","wetransfer","drive.google","mega.nz")
| where Timestamp >= ago(2h)
| project Timestamp, RemoteUrl, BytesSent, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

---

## Investigation Guide

**Step 1 — Data sensitivity (0–10 min)**
What was uploaded? Review the file name, size, and source path.
- Student records CSV / database export → highest severity
- Research data → assess for export control obligations
- Administrative files → lower severity but still investigate

**Step 2 — Account context (10–20 min)**
Who initiated the upload? Is this:
- A staff member on notice or leaving the institution?
- A student in a dispute or disciplinary process?
- An account that was recently compromised (check SEC-EDU-CA-001 alerts)?

**Step 3 — Volume assessment (20–35 min)**
How many student records were in the exported file?
Run the staging investigation query — was data aggregated before uploading?

**Step 4 — Regulatory assessment (35–50 min)**
If student personal data confirmed:
- UK GDPR Article 33: ICO notification required within 72 hours
- UK GDPR Article 34: Direct notification to affected students may be required if high risk
- JISC: Notify for sector-level awareness

---

## Response Actions

**Immediate**
- [ ] Block personal cloud storage domains at network egress (proxy/firewall)
- [ ] Suspend the offending account pending investigation
- [ ] Notify IT Security Director and Data Protection Officer

**Within 1 Hour**
- [ ] Identify what student records were in the exfiltrated files
- [ ] Count affected individuals — required for ICO notification
- [ ] Preserve all evidence: file access logs, network logs, device forensics

**Regulatory (time-critical)**
- [ ] Notify ICO within 72h of becoming aware: [ico.org.uk/report-a-breach](https://ico.org.uk/for-organisations/report-a-breach/)
- [ ] Notify affected students if high risk to their rights and freedoms (Article 34)
- [ ] Notify JISC Cyber Security team
- [ ] If research data: notify relevant funder (UKRI, Wellcome, etc.)

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Researcher uploading data to approved collaboration platform | Add approved academic collaboration platforms to allowed list — require IT approval for new platforms |
| Staff using approved institutional OneDrive (not personal) | Ensure rule filters on `onedrive.live.com` (personal) not `<tenant>.sharepoint.com` (institutional) |

## References
- [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
- [ICO: Data breach reporting](https://ico.org.uk/for-organisations/report-a-breach/)
- [JISC: Cyber security](https://www.jisc.ac.uk/cyber-security)
