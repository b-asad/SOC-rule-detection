# SEC-HC-CO-001 — Healthcare: Patient Record Mass Download

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-HC-CO-001` |
| **MITRE Technique** | T1530 — Data from Cloud Storage |
| **Sector** | Healthcare |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `OfficeActivity` · EPR Audit Logs (`EPRAuditLog_CL`) |

## Description
Mass download or export of patient records from electronic patient record (EPR) systems or SharePoint-hosted clinical data. Insider threats, compromised accounts, and nation-state actors all target patient data for identity fraud, insurance fraud, and targeted extortion. Any confirmed unauthorised bulk access is a UK GDPR / NHS DSPT reportable breach.

## Microsoft Sentinel KQL
```kql
// SEC-HC-CO-001 | Frequency: 15m | Lookback: 1h
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in ("FileDownloaded","FileCopied","AnonymousLinkCreated")
| where SourceFileName has_any ("patient","clinical","nhs","medical","care plan","referral","discharge","prescription")
    or Site_Url has_any ("patient","clinical","nhs","medical","epr","emis","systmone","tpp","vision")
| summarize FileCount=count(), UniqueFiles=dcount(SourceFileName)
    by UserId, ClientIP, UserAgent
| where FileCount > 20
| extend AlertTitle = strcat("Patient Record Bulk Download by ", UserId)
| extend CaldicottObligation = "Notify Caldicott Guardian. ICO notification if patient rights affected (72h)."
```

## Investigation Guide
**Step 1:** What is the user's clinical role? Can this volume be justified by care delivery?
**Step 2:** Were VIP/celebrity patients or staff member records accessed?
**Step 3:** Notify Caldicott Guardian and DPO — Caldicott Principle 2 (use minimum necessary).
**Step 4:** Assess ICO notification under UK GDPR Article 33.

## Response Actions
- [ ] Disable EPR access for the account pending investigation
- [ ] Notify Caldicott Guardian and Data Protection Officer
- [ ] Assess ICO notification requirement (72h)
- [ ] Complete NHS DSPT incident report

## References - [NHS Caldicott Principles](https://www.gov.uk/government/publications/the-caldicott-principles)
