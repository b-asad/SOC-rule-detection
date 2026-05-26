# Credential Access — Tactic Investigation Guide

**Applicable Rules:** GEN-CA-001, GEN-CA-002, GEN-CA-003, RG-CA-001

---

## Triage Decision Tree

```
Alert fires for Credential Access
│
├── LSASS Memory Access (GEN-CA-001 / RG-CA-001)?
│   └── → P1 IMMEDIATELY — Isolate device, reset all accounts
│
├── Password Spray (GEN-CA-002)?
│   ├── Any successful logins from attacking IP?
│   │   └── Yes → P1 — Accounts compromised, revoke sessions
│   └── No → P2 — Block IP, monitor for success
│
└── Kerberoasting (GEN-CA-003)?
    ├── Were privileged service accounts targeted?
    │   └── Yes → P1 — Reset service accounts, enforce AES
    └── No → P2 — Reset targeted accounts, investigate requester
```

---

## Key KQL Queries for Credential Access Investigations

### 1. Scope of Credential Exposure
```kql
// All accounts active on a potentially compromised host
DeviceLogonEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(4h)
| where ActionType == "LogonSuccess"
| distinct AccountName, AccountDomain, LogonType
```

### 2. Post-Compromise Authentication from Stolen Credentials
```kql
// Logins from the attacking IP after credential theft
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| where TimeGenerated >= ago(24h)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, AppDisplayName, tostring(LocationDetails.city)
```

### 3. Lateral Movement Following Credential Theft
```kql
IdentityLogonEvents
| where AccountName in ("<COMPROMISED_ACCOUNTS>")
| where Timestamp >= ago(4h)
| project Timestamp, DeviceName, DestinationDeviceName, ActionType, Protocol, FailureReason
```

### 4. Data Access Post-Compromise
```kql
OfficeActivity
| where UserId == "<COMPROMISED_UPN>"
| where TimeGenerated >= ago(24h)
| where Operation in ("FileDownloaded","FileCopied","SearchQueryPerformed")
| project TimeGenerated, Operation, SourceFileName, Site_Url | order by TimeGenerated desc
```

---

## Escalation Triggers
Escalate to P1 and notify customer if:
- LSASS dump confirmed on any host
- Domain admin or service account credentials exposed
- Authentication from compromised credentials observed on new hosts
- KRBTGT account targeted (Golden Ticket risk)
- More than 5 accounts confirmed compromised from a spray attack

---

## Key Remediation Steps
1. **Immediate:** Reset all exposed account passwords — this is non-negotiable even if investigation is ongoing
2. **Kerberos:** If domain admin exposed, reset KRBTGT password twice (24–48h apart) — this invalidates all issued Kerberos tickets
3. **Service accounts:** Convert to Group Managed Service Accounts (gMSA) post-incident
4. **Preventative:** Enable Credential Guard and LSA Protection (PPL) on all endpoints
5. **Detection hardening:** Ensure MDE is reporting OpenProcessApiCall events (check Advanced Features settings)
