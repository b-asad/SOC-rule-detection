# GEN-IM-004 — Impact: Account Access Removal / Lockout

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IM-004` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | T1531 — Account Access Removal |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR |
| **Log Source** | `AuditLogs` · Windows Security Event 4725 / 4726 |
| **Created** | May 2026 |

---

## Description

Bulk account disabling, deletion, or password reset by a single account in a short window — attacker locking legitimate users out of systems to prevent incident response, or destructive action post-exfiltration. Particularly dangerous when targeting admin accounts.

---

## Microsoft Sentinel KQL

```kql
// GEN-IM-004 | Frequency: 5m | Lookback: 15m
// Detection A: Bulk account disable/delete via Entra ID
let AzureBulkAccountChange = (
    AuditLogs
    | where TimeGenerated >= ago(15m)
    | where OperationName in (
        "Disable account","Delete user","Reset user password",
        "Revoke all refresh tokens for user"
    )
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
    | summarize ActionCount=count(), Accounts=make_set(tostring(TargetResources[0].userPrincipalName),10)
        by Actor, OperationName
    | where ActionCount > 5
    | extend DetectionType = "BulkEntraAccountChange"
);
// Detection B: Bulk local account disable via Windows Security Events
let WinBulkDisable = (
    SecurityEvent
    | where TimeGenerated >= ago(15m)
    | where EventID in (4725, 4726)  // Account disabled / deleted
    | summarize Count=count(), Accounts=make_set(TargetUserName,10)
        by SubjectUserName, Computer
    | where Count > 5
    | extend DetectionType = "BulkLocalAccountDisable"
);
AzureBulkAccountChange | union WinBulkDisable
| extend AlertTitle = strcat("Bulk Account Lockout: ", ActionCount, " accounts by ", Actor)
```

---

## Investigation Guide

**Step 1 — Is this a response to a breach or an attacker action?**
Sometimes admins disable accounts during an incident. Confirm with IT — is there an open incident?
**Step 2 — Which accounts were disabled/deleted?** Are admin accounts targeted? If yes → attacker is locking out incident responders.
**Step 3 — Restore access via break-glass admin account.**

---

## Response Actions
- [ ] Re-enable affected accounts via break-glass / emergency admin account
- [ ] Revoke the actor's privileges if this was an attacker action
- [ ] Verify break-glass account is not compromised

## References - [MITRE T1531](https://attack.mitre.org/techniques/T1531/)
