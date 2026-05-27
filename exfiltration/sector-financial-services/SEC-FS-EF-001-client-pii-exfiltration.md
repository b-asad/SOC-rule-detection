# SEC-FS-EF-001 — Financial Services: Client PII Mass Exfiltration

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-FS-EF-001` |
| **MITRE Technique** | T1048 — Exfiltration Over Alternative Protocol |
| **Sector** | Financial Services |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `OfficeActivity` · `CloudAppEvents` (MCAS) |

## Description
Bulk export of client PII — account numbers, sort codes, personal financial data, KYC documentation — from financial systems. Triggers FCA GDPR obligations and potential FCA client data breach notification under PRIN 11.

## Microsoft Sentinel KQL
```kql
// SEC-FS-EF-001 | Frequency: 15m | Lookback: 1h
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in ("FileDownloaded","AnonymousLinkCreated","SharingInvitationCreated")
| where SourceFileName has_any ("client","customer","kyc","aml","account","portfolio","statement","id verification","passport","national insurance")
    or Site_Url has_any ("client","customer","kyc","crm","compliance","onboarding")
| summarize FileCount=count(), UniqueFiles=dcount(SourceFileName)
    by UserId, ClientIP
| where FileCount > 15
| extend FCAObligation = "FCA PRIN 11: Notify FCA if client data breach. UK GDPR ICO 72h."
```

## Response Actions
- [ ] Revoke access to client data repositories
- [ ] Notify Compliance Officer and Data Protection Officer
- [ ] Notify FCA under PRIN 11 if client personal data confirmed exfiltrated
- [ ] Notify ICO within 72h under UK GDPR

## References - [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
