# RF-IA-001 — ERP / Food Management System Off-Hours Access

| Field | Value |
|-------|-------|
| Rule ID | RF-IA-001 |
| Tactic | Initial Access |
| Technique | T1078 — Valid Accounts |
| Sector | **Food & Grocery Retail** |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Cloud Apps |
| Log Source | `SigninLogs`, `CloudAppEvents`, ERP Application Logs |
| Retail Context | SAP, Dynamics 365, Oracle SCM, food safety databases, supplier portals |

## Description
Authentication to ERP or food management systems outside approved business hours from unexpected locations. Food retailers face unique threats: supply chain manipulation, food safety record tampering, and competitor intelligence gathering. Unauthorised ERP access may constitute a **food safety incident** if allergen or recall data is at risk.

---

## Microsoft Sentinel KQL
```kql
// RF-IA-001 | Frequency: 15m | Lookback: 1h
let FoodApps = dynamic(["SAP","Dynamics 365","Oracle SCM","Infor","TraceLink","SafetyChain","Aptean","food safety","supply chain","procurement"]);
let ApprovedCountries = dynamic(["GB","IE","US"]);  // Adjust per customer
SigninLogs
| where TimeGenerated >= ago(1h) and ResultType == "0"
| where AppDisplayName has_any (FoodApps)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend Hour = datetime_part("hour", TimeGenerated)
| extend IsOffHours = (Hour >= 22 or Hour < 6)
| extend IsUnexpectedCountry = (Country !in (ApprovedCountries))
| where IsOffHours or IsUnexpectedCountry
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Country, IsOffHours, IsUnexpectedCountry, ConditionalAccessStatus
```

---

## Investigation Guide

**Step 1 — Business Justification (< 10 min)**  
Contact user's manager. Is there a legitimate business reason for this access?  
Is this account shared between multiple users (higher risk)?

**Step 2 — ERP Actions Review**  
Pull the ERP audit log for this session. Were any records modified?  
Priority: allergen data, batch records, supplier compliance, recall records.

**Step 3 — Food Safety Impact Assessment**  
If allergen or recall data was accessed or modified: **immediately notify the customer's Food Safety Manager.**  
Were any modified records for products currently on sale?

---

## Response Actions
- [ ] Revoke session, force MFA re-authentication
- [ ] Notify customer ERP Administrator to review audit trail
- [ ] If food safety records modified: notify Food Safety Manager immediately
- [ ] If allergen data on live product changed: assess product withdrawal requirement

## Regulatory Triggers (Food Retail Specific)
- FSA (UK): Report if allergen or safety data compromise confirmed — 020 7276 8829
- Trading Standards: If supplier compliance data manipulated

## References
- [MITRE T1078](https://attack.mitre.org/techniques/T1078/)
- [FSA: Reporting food incidents](https://www.food.gov.uk/business-guidance/report-a-food-incident)
