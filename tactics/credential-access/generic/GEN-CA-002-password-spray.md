# GEN-CA-002 — Brute Force: Password Spraying

| Field | Value |
|-------|-------|
| Rule ID | GEN-CA-002 |
| Tactic | Credential Access |
| Technique | T1110.003 — Password Spraying |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Identity · Defender for Cloud Apps |
| Log Source | `SigninLogs`, `AADSignInEventsBeta`, `IdentityLogonEvents` |

## Description
Single password attempted across many accounts from one or a small set of source IPs within a short timeframe. Designed to avoid per-account lockout thresholds. Common pre-ransomware and BEC technique.

---

## Microsoft Sentinel KQL
```kql
// GEN-CA-002 | Frequency: 10m | Lookback: 10m
SigninLogs
| where TimeGenerated >= ago(10m)
| where ResultType != "0"
| summarize
    FailCount = count(),
    UniqueAccounts = dcount(UserPrincipalName),
    AccountList = make_set(UserPrincipalName, 10),
    UniqueApps = dcount(AppDisplayName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IPAddress, tostring(LocationDetails.countryOrRegion)
| where FailCount > 20 and UniqueAccounts > 5
| extend SprayScore = round(todouble(FailCount) / todouble(UniqueAccounts), 1)
| order by SprayScore asc  // Low ratio = spray (few attempts per account)
```

---

## Defender for Identity — MDI Alert
MDI natively detects password spraying via Kerberos (Event 4771) and NTLM (Event 4776).
- Alert name: **Password spray attack (Kerberos)**
- Alert name: **Password spray attack (LDAP)**
Ensure MDI sensors are active on all Domain Controllers.

---

## Defender XDR — Advanced Hunting
```kql
// GEN-CA-002 | Run: Every hour
AADSignInEventsBeta
| where Timestamp >= ago(1h) and ErrorCode != 0
| summarize FailCount=count(), UniqueAccounts=dcount(AccountUpn), FirstSeen=min(Timestamp) by IPAddress
| where FailCount > 30 and UniqueAccounts > 8
| order by UniqueAccounts desc
```

---

## Investigation Guide

**Step 1 — Confirm Spray Pattern (< 10 min)**  
Low failures-per-account ratio + many accounts = spray (not brute force against one account).

**Step 2 — Successful Logins from Attacking IP**
```kql
SigninLogs | where IPAddress == "<ATTACKING_IP>" | where ResultType == "0"
| project TimeGenerated, UserPrincipalName, AppDisplayName, tostring(LocationDetails.city)
```
Any success = compromised account. Immediately revoke and reset.

**Step 3 — Post-Auth BEC/Ransomware Activity**
Check compromised accounts for: email forwarding rules, OAuth grants, MFA changes, SharePoint access.

**Step 4 — Scope to Other Customers**
Search the same attacking IPs across all customer tenants — spray attacks often target multiple organisations simultaneously.

---

## Response Actions
- [ ] **Block attacking IPs** — Conditional Access + Entra ID Named Locations
- [ ] **Reset passwords** for all successfully authenticated accounts from those IPs
- [ ] **Enable MFA** if not already enforced for targeted accounts
- [ ] **Alert customer** — provide list of targeted and compromised accounts
- [ ] **Check for follow-on BEC** — financial requests, forwarding rules

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Misconfigured service account with wrong password | Single account, not spray pattern — rule won't trigger |

## References
- [MITRE T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- [MDI: Password spray detection](https://learn.microsoft.com/en-us/defender-for-identity/compromised-credentials-alerts)
