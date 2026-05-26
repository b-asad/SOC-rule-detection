# RF-IM-001 — Food Safety Record Tampering

| Field | Value |
|-------|-------|
| Rule ID | RF-IM-001 |
| Tactic | Impact |
| Technique | T1565.001 — Stored Data Manipulation |
| Sector | **Food & Grocery Retail** |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel |
| Log Source | Azure SQL Audit Logs (`AzureDiagnostics`), Application Logs |
| Retail Context | Allergen DBs, batch tracking, supplier compliance, recall management |

## Description
Unauthorised modification of food safety critical records. Tampering with allergen, batch, or recall data is a **public health risk** and criminal offence under the Food Safety Act 1990 (UK). This rule detects bulk updates, off-hours modifications, or changes by accounts that do not normally modify these records.

---

## Microsoft Sentinel KQL
```kql
// RF-IM-001 | Frequency: 5m | Lookback: 15m
AzureDiagnostics
| where TimeGenerated >= ago(15m) and Category == "SQLSecurityAuditEvents"
| where action_name_s in ("UPDATE","DELETE","INSERT")
| where database_name_s has_any ("food_safety","allergen","recall","traceability","compliance","batch")
    or object_name_s has_any ("allergen","recall","batch_record","food_safety","ingredient","supplier_compliance","product_specification")
| extend IsOffHours = (datetime_part("hour",TimeGenerated) >= 22 or datetime_part("hour",TimeGenerated) < 6)
| extend IsBulk = (rows_changed_d > 10)
| extend IsExternal = (client_ip_s !startswith "10.")
| where IsOffHours or IsBulk or IsExternal
| project TimeGenerated, client_ip_s, server_principal_name_s, database_name_s, object_name_s, action_name_s, rows_changed_d, IsOffHours, IsBulk, IsExternal, statement_s
```

---

## Investigation Guide

**Step 1 — Immediate Public Health Assessment (< 5 min)**  
Identify which records were modified. Allergen or recall data on a live product?  
Contact Food Safety Manager immediately — do not wait for technical investigation.

**Step 2 — Scope of Changes**  
Run SQL audit query to get full list of modified records and their previous values.  
Are changes on products currently on sale or in the supply chain?

**Step 3 — Regulatory Notification**  
Allergen data changed on a live product → **immediate FSA notification required.**  
Batch/traceability data altered → may impair product recall capability.

---

## Response Actions
- [ ] Revert all unauthorised changes from backup
- [ ] Lock the affected database tables pending investigation
- [ ] Notify Food Safety Manager and Operations Director
- [ ] If allergen data on live products: initiate product withdrawal assessment
- [ ] Contact FSA incidents team: 020 7276 8829
- [ ] Engage legal counsel — Food Safety Act 1990 criminal liability

## References
- [MITRE T1565.001](https://attack.mitre.org/techniques/T1565/001/)
- [Food Safety Act 1990](https://www.legislation.gov.uk/ukpga/1990/16)
