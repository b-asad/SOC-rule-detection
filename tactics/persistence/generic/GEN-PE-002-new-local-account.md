# GEN-PE-002 — Persistence: New Local Admin Account Created

| Field | Value |
|-------|-------|
| Rule ID | GEN-PE-002 |
| Tactic | Persistence |
| Technique | T1136.001 — Create Account: Local Account |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Identity · Defender XDR |
| Log Source | Windows Security Event 4720, 4728, `IdentityDirectoryEvents` |

## Description
New local user account created outside of the provisioning workflow, particularly if added to the Administrators group (Event 4732). Common attacker technique to maintain persistent access after credential rotation.

---

## Microsoft Sentinel KQL
```kql
// GEN-PE-002 | Frequency: 5m | Lookback: 5m
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID in (4720, 4732)
| extend NewAccount = tostring(TargetUserName)
| extend Creator = tostring(SubjectUserName)
| extend GroupAdded = iff(EventID==4732, tostring(TargetUserName), "")
| where Creator !in ("SYSTEM","provisioning_svc")
| project TimeGenerated, Computer, Creator, NewAccount, GroupAdded, EventID
```

---

## Defender for Identity — MDI Alert
MDI raises: **Suspicious account creation** and **Suspicious service account modification**  
These surface automatically in the Defender XDR Incidents queue.

---

## Investigation Guide

**Step 1:** Is the creator account a legitimate IT provisioning account?  
**Step 2:** Check the ITSM system — is there a ticket authorising this account creation?  
**Step 3:** What else has the creator account done in the last 24h? (check AuditLogs)  
**Step 4:** Is the new account already logging in from somewhere?

---

## Response Actions
- [ ] Disable the new account immediately
- [ ] Investigate the creator account for further compromise
- [ ] Notify customer IT team to verify if legitimate

## References
- [MITRE T1136.001](https://attack.mitre.org/techniques/T1136/001/)
