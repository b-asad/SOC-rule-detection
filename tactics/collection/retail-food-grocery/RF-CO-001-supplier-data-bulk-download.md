# RF-CO-001 — Supplier & Pricing Data Bulk Download

| Field | Value |
|-------|-------|
| Rule ID | RF-CO-001 |
| Tactic | Collection |
| Technique | T1213 — Data from Information Repositories |
| Sector | **Food & Grocery Retail** |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Cloud Apps |
| Log Source | `OfficeActivity`, `CloudAppEvents` (M365 UAL, SharePoint) |
| Retail Context | Supplier portals, pricing databases, procurement systems, contract repositories |

## Description
Mass download of supplier pricing, contract, or procurement data from SharePoint or procurement systems. Supplier pricing data in food retail is commercially sensitive — bulk download by a single user may indicate a departing employee, insider threat, or compromised account targeting competitor intelligence.

---

## Microsoft Sentinel KQL
```kql
// RF-CO-001 | Frequency: 15m | Lookback: 1h
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in ("FileDownloaded","FileCopied","FileAccessed")
| where SourceFileName has_any ("supplier","pricing","contract","tender","procurement","cost","margin","buying")
    or Site_Url has_any ("supplier","procurement","buying","contracts","pricing")
| summarize FileCount=count(), UniqueFiles=dcount(SourceFileName), Files=make_set(SourceFileName,10), First=min(TimeGenerated), Last=max(TimeGenerated)
    by UserId, ClientIP, UserAgent
| where FileCount > 20
| extend IsExternal = (ClientIP !startswith "10." and ClientIP !startswith "192.168.")
| order by FileCount desc
```

---

## Investigation Guide

**Step 1 — User Context**  
Is this user in procurement or buying? Is there a business justification?  
Is the user on notice or recently resigned? Check HR system.

**Step 2 — Data Sensitivity**  
What files were downloaded? Supplier pricing, contract terms, margin data?  
Has this data been uploaded to personal cloud storage or emailed externally?

---

## Response Actions
- [ ] Revoke SharePoint/OneDrive access to sensitive procurement libraries
- [ ] Block personal cloud storage at proxy
- [ ] Notify Procurement Director and Legal
- [ ] Preserve download logs as evidence for HR/legal proceedings

## References
- [MITRE T1213](https://attack.mitre.org/techniques/T1213/)
