# GEN-CA-003 — Credential Access: Kerberoasting

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CA-003` |
| **MITRE Technique** | T1558.003 — Kerberoasting |
| **Sector** | Generic |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR |
| **Log Source** | `IdentityQueryEvents` (MDI) · Windows Security Event 4769 |

## Description
Kerberoasting requests RC4-encrypted Kerberos service tickets (TGS) for service accounts, then cracks the ticket offline to recover the account's NTLM hash. MDI provides the best detection via DC-level telemetry. This rule adds Sentinel-level alerting with richer context.

## Microsoft Sentinel KQL
```kql
// GEN-CA-003 | Frequency: 5m | Lookback: 5m
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID == 4769
| where TicketEncryptionType == "0x17"   // RC4-HMAC — weak, targeted by Kerberoasting
| where ServiceName !endswith "$"         // Exclude machine accounts
| summarize RequestCount=count(), UniqueServices=dcount(ServiceName), Services=make_set(ServiceName,10)
    by Account, IpAddress, bin(TimeGenerated, 1m)
| where RequestCount > 3
| extend AlertTitle = strcat("Kerberoasting: ", RequestCount, " TGS requests by ", Account)
```

## Defender for Identity — MDI Alert (Primary Detection)
Alert name: **Suspected Kerberos SPN exposure (Kerberoasting)** — ensure this is P1 in Defender XDR.
MDI provides the most reliable detection — prioritise this alert over the Sentinel KQL if MDI is deployed.

## Defender XDR — Advanced Hunting
```kql
// GEN-CA-003 | Run: Every hour
IdentityQueryEvents
| where Timestamp >= ago(1h) and QueryType == "Kerberoasting"
| project Timestamp, AccountName, DeviceName, QueryTarget, Protocol
| order by Timestamp desc
```

## Investigation Guide
**Step 1 (< 10 min):** Which account made the requests? Which service SPNs were targeted?
Prioritise: `MSSQLSvc`, `HTTP`, `cifs` — typically attached to powerful service accounts.
**Step 2 (10–20 min):** Check group membership of targeted service accounts:
```kql
IdentityDirectoryEvents | where TargetAccountUpn in ("<SERVICE_ACCOUNTS>")
| where AdditionalFields has_any ("Domain Admins","Enterprise Admins","Administrators")
| project Timestamp, TargetAccountUpn, AdditionalFields
```
If domain admin SPN targeted → Critical, escalate immediately.
**Step 3 (20–40 min):** Check for post-crack lateral movement using the service account.

## Response Actions
- [ ] Reset passwords for ALL targeted service accounts — use 30+ char random passwords
- [ ] Convert service accounts to Group Managed Service Accounts (gMSA) — auto-rotating passwords
- [ ] Remove unnecessary SPNs from high-privilege accounts
- [ ] Enforce AES-only Kerberos via GPO — disable RC4

## References - [MITRE T1558.003](https://attack.mitre.org/techniques/T1558/003/)
