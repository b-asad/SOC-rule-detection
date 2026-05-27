# Initial Access — Tactic Investigation Guide

**Applicable Rules:** GEN-IA-001 · GEN-IA-002 · GEN-IA-003 · SEC-RET-IA-001 · SEC-HC-IA-001 · SEC-MFG-IA-001 · SEC-EDU-IA-001 · SEC-GOV-IA-001 · SEC-FS-IA-001 · SEC-ENRG-IA-001

---

## Triage Decision Tree

```
Initial Access alert fires
│
├── GEN-IA-001: Office Macro spawns shell?
│   └── → P1 NOW — Isolate device, decode payload, check email source
│
├── GEN-IA-002: Impossible Travel?
│   ├── MFA satisfied from BOTH locations?
│   │   └── YES → AiTM/session theft — P1 — Revoke ALL sessions immediately
│   └── NO → Credential compromise — P1 — Reset, revoke, audit post-auth activity
│
├── GEN-IA-003: Tor/Anonymiser access?
│   └── → P1 — Revoke session, audit all actions taken, check what was accessed
│
├── SEC-RET-IA-001: Magecart JS modification?
│   └── → P1 — Offline checkout page, PCI DSS breach assessment, notify acquiring bank
│
├── SEC-GOV-IA-001: Government spearphishing?
│   └── → P1 — NCSC report if nation-state suspected, DSO notification
│
├── SEC-ENRG-IA-001: SCADA external access?
│   └── → P1 IMMEDIATELY — Physical operations safety assessment first, OT team
│
└── Other sector phishing (SEC-HC/MFG/EDU-IA-001)?
    └── → P1 — Sector-specific escalation contacts + sector notification obligations
```

---

## Universal Queries

**Email source from device alert hash:**
```kql
EmailAttachmentInfo
| where Timestamp >= ago(24h) | where SHA256 == "<HASH_FROM_DEVICE_ALERT>"
| join kind=inner (EmailEvents | where Timestamp >= ago(24h)
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, SenderFromDomain, Subject, DeliveryAction, ThreatTypes
) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, FileName, SHA256, ThreatTypes
```

**Campaign blast radius:**
```kql
let Hash = "<ATTACHMENT_SHA256>";
EmailAttachmentInfo | where Timestamp >= ago(48h) | where SHA256 == Hash
| join kind=inner (EmailEvents | where Timestamp >= ago(48h) | where DeliveryAction != "Blocked"
    | project NetworkMessageId, RecipientEmailAddress) on NetworkMessageId
| distinct RecipientEmailAddress
```

**Post-authentication activity:**
```kql
AuditLogs
| where InitiatedBy.user.userPrincipalName == "<COMPROMISED_UPN>"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, OperationName, Result, TargetResources
| order by TimeGenerated asc
```

**AiTM confirmation — MFA from both locations:**
```kql
SigninLogs | where UserPrincipalName == "<UPN>" | where TimeGenerated >= ago(24h)
| extend MFAResult = tostring(AuthenticationDetails[0].authenticationStepResultDetail)
| project TimeGenerated, IPAddress, MFAResult, ConditionalAccessStatus,
    City = tostring(LocationDetails.city)
| order by TimeGenerated asc
// If MFA succeeded from BOTH attacking and legitimate IP → AiTM — treat as Critical
```

---

## Escalation Triggers
Escalate to P1 and notify customer CISO if:
- Office application spawns a shell process on any host
- MFA was satisfied from both locations in an impossible travel event (AiTM)
- Tor exit node successfully authenticated to any corporate service
- Checkout JavaScript modified outside CI/CD on PCI DSS in-scope host
- Any access to SCADA/ICS/energy management systems from unexpected source
- Government account targeted with suspected nation-state spearphishing
