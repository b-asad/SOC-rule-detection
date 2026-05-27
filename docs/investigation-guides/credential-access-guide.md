# Credential Access — Tactic Investigation Guide

**Applicable Rules:** GEN-CA-001 · GEN-CA-002 · GEN-CA-003 · SEC-RET-CA-001 · SEC-HC-CA-001 · SEC-FS-CA-001 · SEC-GOV-CA-001 · SEC-EDU-CA-001 · SEC-MFG-CA-001 · SEC-ENRG-CA-001 · SEC-LEG-CA-001 · SEC-TECH-CA-001

---

## Triage Decision Tree

```
Credential Access alert fires
│
├── GEN-CA-001: LSASS Memory Dump?
│   └── → P1 IMMEDIATELY — Isolate device, reset ALL exposed accounts
│
├── GEN-CA-002: Password Spray?
│   ├── Any successful logins from attacking IP?
│   │   └── YES → P1 — Accounts compromised — revoke, reset, BEC check
│   └── All failures → P2 — Block IP, monitor for success
│
├── GEN-CA-003: Kerberoasting?
│   ├── Domain admin or high-privilege accounts targeted?
│   │   └── YES → P1 — Reset immediately, disable RC4, convert to gMSA
│   └── Standard accounts → P2 — Reset and investigate requester
│
├── Sector LSASS rules (SEC-RET/HC/MFG/ENRG/LEG-CA-001)?
│   └── → P1 — Sector-specific escalation + regulatory notification
│
└── SEC-TECH-CA-001: Code signing/secret access?
    └── → P1 — Revoke compromised secrets immediately
```

---

## Universal Queries

**All accounts exposed on compromised host:**
```kql
DeviceLogonEvents
| where DeviceName == "<DEVICE>" | where Timestamp between (ago(4h) .. now())
| where ActionType == "LogonSuccess"
| distinct AccountName, AccountDomain, LogonType
| extend ResetRequired = "YES — Immediate"
```

**Successful logins from attacking IP:**
```kql
SigninLogs | where IPAddress == "<ATTACKING_IP>" | where ResultType == "0"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, UserPrincipalName, AppDisplayName, tostring(LocationDetails.city)
```

**Post-compromise BEC check:**
```kql
OfficeActivity | where UserId in ("<COMPROMISED_ACCOUNTS>")
| where TimeGenerated >= ago(24h)
| where Operation in ("New-InboxRule","Set-InboxRule","Set-Mailbox","Add-MailboxPermission","FileDownloaded")
| project TimeGenerated, UserId, Operation, Parameters, ClientIP | order by TimeGenerated asc
```

**Kerberoasting — targeted account privilege check:**
```kql
IdentityQueryEvents | where Timestamp >= ago(7d) | where QueryType == "Kerberoasting"
| project Timestamp, AccountName, QueryTarget, DeviceName
```

---

## KRBTGT Reset Procedure (after domain admin compromise)

Reset KRBTGT password **twice**, minimum 24 hours apart:
```powershell
# Reset 1 — run immediately
Set-ADAccountPassword -Identity krbtgt -Reset `
    -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)$(New-Guid)" -Force)

# Wait 24 hours for replication to all DCs

# Reset 2 — invalidates all tickets including Golden Tickets
Set-ADAccountPassword -Identity krbtgt -Reset `
    -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)$(New-Guid)" -Force)
```

---

## Escalation Triggers
- LSASS dump confirmed on ANY host → P1
- Domain admin or KRBTGT exposed → P1 + CISO notification
- > 5 accounts compromised from spray → P1
- POS LSASS dump → P1 + PCI DSS acquiring bank notification
- OT/energy engineering host LSASS dump → P1 + NIS2 NCSC notification
