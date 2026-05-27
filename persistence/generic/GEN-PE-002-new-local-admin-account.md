# GEN-PE-002 — Persistence: New Local Admin Account Created

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-PE-002` |
| **MITRE Technique** | T1136.001 — Create Account: Local Account |
| **Sector** | Generic |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR |
| **Log Source** | Windows Security Event 4720 / 4732 · `IdentityDirectoryEvents` (MDI) |

## Description
New local user account created and/or added to the Administrators group (Event 4732) outside of the approved provisioning workflow. Common attacker persistence mechanism to maintain access after credential rotation. Alert fires on every instance — legitimate provisioning should use domain accounts via IAM tooling, not local accounts.

## Microsoft Sentinel KQL
```kql
// GEN-PE-002 | Frequency: 5m | Lookback: 5m
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID in (4720, 4732)
| extend NewAccount = tostring(TargetUserName)
| extend Creator    = tostring(SubjectUserName)
| where Creator !in~ ("SYSTEM","NT AUTHORITY\SYSTEM")
| project TimeGenerated, Computer, Creator, NewAccount, EventID,
    Activity = iff(EventID==4720,"Account Created","Added to Admins Group")
| extend AlertTitle = strcat(Activity, ": ", NewAccount, " by ", Creator, " on ", Computer)
```

## Defender for Identity
MDI raises: **Suspicious account creation** — surfaces in Defender XDR Incidents queue.

## Defender XDR — Advanced Hunting
```kql
// GEN-PE-002 | Run: Every hour
IdentityDirectoryEvents
| where Timestamp >= ago(1h) and ActionType == "Account created"
| where TargetAccountSid !endswith "$"
| project Timestamp, AccountName, TargetAccountDisplayName, TargetAccountSid, DeviceName
```

## Investigation Guide
**Step 1:** Is the creator account a legitimate IT provisioning account? Is there an ITSM ticket?
**Step 2:** Is the new account already logging in from somewhere?
```kql
DeviceLogonEvents | where AccountName == "<NEW_ACCOUNT>" | where Timestamp >= ago(24h)
| project Timestamp, DeviceName, RemoteDeviceName, LogonType, ActionType
```
**Step 3:** What has the creator account done in the last 24h? Check AuditLogs.

## Response Actions
- [ ] Disable the new account immediately
- [ ] Investigate the creator account for further compromise
- [ ] Confirm with IT whether account creation was authorised

## References - [MITRE T1136.001](https://attack.mitre.org/techniques/T1136/001/)
