# SEC-RET-CO-001 — Retail: Customer / Loyalty Data Mass Harvest

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-RET-CO-001` |
| **MITRE Technique** | T1530 — Data from Cloud Storage |
| **Sector** | Retail |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `OfficeActivity` · `CloudAppEvents` (MCAS) |

## Description
Mass export of customer PII, loyalty programme data, or purchase history. Retail customer databases are valuable for targeted phishing, loyalty fraud, and sale to dark web marketplaces. Under UK GDPR, any confirmed breach of customer personal data requires ICO notification within 72 hours.

## Microsoft Sentinel KQL
```kql
// SEC-RET-CO-001 | Frequency: 15m | Lookback: 1h
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in ("FileDownloaded","FileCopied","AnonymousLinkCreated")
| where SourceFileName has_any ("customer","loyalty","member","shopper","purchase","order","email list","marketing","crm","contact")
    or Site_Url has_any ("customer","crm","loyalty","ecommerce","marketing","members")
| summarize FileCount=count(), UniqueFiles=dcount(SourceFileName)
    by UserId, ClientIP
| where FileCount > 20
| extend AlertTitle = strcat("Customer Data Bulk Download by ", UserId)
| extend GDPRObligation = "UK GDPR Article 33: Notify ICO within 72h if customer PII confirmed exfiltrated"
```

## Response Actions
- [ ] Revoke access to customer data repositories
- [ ] Notify DPO and assess ICO notification (72h)
- [ ] If loyalty data: notify marketing/loyalty team — assess fraud risk
- [ ] Notify affected customers if required under UK GDPR Article 34

## References - [MITRE T1530](https://attack.mitre.org/techniques/T1530/)
