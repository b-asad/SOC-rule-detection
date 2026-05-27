# GEN-CA-002 — Credential Access: Password Spraying

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CA-002` |
| **MITRE Technique** | T1110.003 — Password Spraying |
| **Sector** | Generic |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Identity · Defender for Cloud Apps |
| **Log Source** | `SigninLogs` · `AADSignInEventsBeta` · `IdentityLogonEvents` (MDI) |

## Description
A single IP attempts one or a small set of common passwords across many accounts within a short window — designed to stay below per-account lockout thresholds. Unlike brute force (many attempts against one account), spray attacks appear as normal individual login failures spread across the user population. Common pre-ransomware and BEC precursor technique.

## Microsoft Sentinel KQL
```kql
// GEN-CA-002 | Frequency: 10m | Lookback: 10m
SigninLogs
| where TimeGenerated >= ago(10m)
| where ResultType != "0"
| summarize
    FailCount     = count(),
    UniqueAccounts = dcount(UserPrincipalName),
    AccountSample  = make_set(UserPrincipalName, 5),
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated)
    by IPAddress, tostring(LocationDetails.countryOrRegion)
| where FailCount > 20 and UniqueAccounts > 5
| extend SprayRatio = round(todouble(FailCount) / todouble(UniqueAccounts), 1)
| extend AlertTitle = strcat("Password Spray from ", IPAddress, " — ", UniqueAccounts, " accounts targeted")
| order by UniqueAccounts desc
```

## Defender for Identity — MDI Alerts
MDI natively detects spray via Kerberos (Event 4771) and NTLM (Event 4776):
- Alert: **Password spray attack (Kerberos)**
- Alert: **Password spray attack (LDAP)**

Both must be configured as High severity in Defender XDR alert settings.

## Defender XDR — Advanced Hunting
```kql
// GEN-CA-002 | Run: Every hour
AADSignInEventsBeta
| where Timestamp >= ago(1h) and ErrorCode != 0
| summarize FailCount=count(), UniqueAccounts=dcount(AccountUpn)
    by IPAddress, Country
| where FailCount > 30 and UniqueAccounts > 8
| order by UniqueAccounts desc
```

## Defender for Cloud Apps
Enable anomaly policy: **Multiple failed login attempts** — sensitivity: Medium.

## Investigation Guide
**Step 1 (< 10 min):** Confirm spray pattern — low failures-per-account ratio = spray, not brute force.
**Step 2 (10–20 min):** Check for successful logins from the attacking IP:
```kql
SigninLogs | where IPAddress == "<ATTACKING_IP>" | where ResultType == "0"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, UserPrincipalName, AppDisplayName
```
Any success = compromised account. Revoke and reset immediately.

**Step 3 (20–35 min):** Check compromised accounts for BEC activity (forwarding rules, OAuth consents, bulk downloads).
**Step 4:** Search the same source IPs across all customer tenants — spray attacks typically target multiple organisations.

## Response Actions
- [ ] Block attacking IPs in Conditional Access (Named Locations → Block)
- [ ] Reset passwords for all accounts successfully authenticated from those IPs
- [ ] Force MFA for targeted accounts if not already enforced
- [ ] Alert customer — provide list of targeted and compromised accounts

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Misconfigured service account with wrong password | Single account pattern — rule threshold of 5+ accounts won't trigger |

## References - [MITRE T1110.003](https://attack.mitre.org/techniques/T1110/003/)
