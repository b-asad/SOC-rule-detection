# GEN-IA-006 — Initial Access: Trusted Relationship / Third-Party Access Abuse

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IA-006` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1199 — Trusted Relationship |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender XDR |
| **Log Source** | `SigninLogs` · `AuditLogs` · `CloudAppEvents` (MCAS) |
| **Created** | May 2026 |

---

## Description

Detects anomalous activity from third-party vendor, contractor, or partner accounts — B2B guest users, external identities, and service accounts used for managed service access. Third-party compromise is a primary supply chain attack vector; the SolarWinds, Kaseya, and 3CX incidents all began with a trusted third party being compromised, then used to pivot into customer environments.

Indicators: guest user signing in from unexpected geography, third-party service account authenticating outside maintenance windows, new B2B guest account created and immediately accessing sensitive resources.

---

## Microsoft Sentinel KQL

```kql
// GEN-IA-006 | Frequency: 15m | Lookback: 1h
let ApprovedVendorCountries = dynamic(["GB","IE","US","IN","PL"]);
// Detection A: Vendor/guest account sign-in from unexpected geography
let VendorGeoAnomaly = (
    SigninLogs
    | where TimeGenerated >= ago(1h)
    | where ResultType == "0"
    | where UserType == "Guest" or HomeTenantId != TenantId
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | where Country !in (ApprovedVendorCountries)
    | project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName, UserType
    | extend DetectionType = "VendorGeoAnomaly"
);
// Detection B: Third-party account accessing sensitive resources outside maintenance window
let OutOfHoursVendor = (
    SigninLogs
    | where TimeGenerated >= ago(1h)
    | where ResultType == "0"
    | where UserType == "Guest" or HomeTenantId != TenantId
    | extend Hour = datetime_part("hour", TimeGenerated)
    | where Hour >= 22 or Hour <= 5  // Outside business hours — adjust per customer
    | where AppDisplayName has_any ("Azure Portal","Azure Active Directory","Microsoft Azure","Key Vault","SQL","Storage")
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, UserType
    | extend DetectionType = "VendorOutOfHoursAccessToSensitiveApp"
);
VendorGeoAnomaly | union OutOfHoursVendor
| extend AlertTitle = strcat("Third-Party Account Anomaly: ", UserPrincipalName)
```

---

## Defender for Cloud Apps

```kql
// MCAS: Third-party app accessing unusual volume of data
CloudAppEvents
| where Timestamp >= ago(1h)
| where AccountType == "Guest"
| where ActionType in ("FileDownloaded","FileAccessed","FileCopied")
| summarize Count=count(), Files=make_set(tostring(AdditionalFields.FileName),10)
    by AccountUpn, AppName, IPAddress
| where Count > 20
| extend AlertTitle = strcat("Guest Account Bulk Data Access: ", AccountUpn)
```

---

## Investigation Guide

**Step 1 — Is the vendor currently scheduled? (0–10 min)**
Check the change management system — is there an approved maintenance window for this vendor?
Contact the vendor's primary contact by phone (not email) to confirm the access.

**Step 2 — What resources were accessed? (10–25 min)**
```kql
AuditLogs | where InitiatedBy.user.userPrincipalName == "<VENDOR_UPN>"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, OperationName, Result, TargetResources | order by TimeGenerated asc
```

**Step 3 — Source IP reputation (25–35 min)**
Submit vendor's source IP to VirusTotal and Shodan. Is it consistent with their expected egress range? A VPS or residential IP from an unexpected country = likely compromised vendor account.

---

## Response Actions
- [ ] Revoke the third-party account's access temporarily pending investigation
- [ ] Contact vendor security team directly to confirm whether their account/system is compromised
- [ ] Review all actions taken by the vendor account in the last 30 days
- [ ] If vendor compromise confirmed: treat as supply chain incident — full tenant audit required

## References
- [MITRE T1199](https://attack.mitre.org/techniques/T1199/)
- [NCSC: Supply chain security](https://www.ncsc.gov.uk/collection/supply-chain-security)
