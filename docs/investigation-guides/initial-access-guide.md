# Initial Access — Tactic Investigation Guide

**Applicable Rules:** GEN-IA-001, GEN-IA-002, GEN-IA-003, RG-IA-001, RF-IA-001

---

## Triage Decision Tree

```
Initial Access alert fires
│
├── Office Macro Child Process (GEN-IA-001)?
│   └── → P1 — Isolate immediately, trace process tree, check C2 connections
│
├── Impossible Travel (GEN-IA-002)?
│   ├── MFA satisfied from both locations?
│   │   └── Yes → Likely AiTM / cookie theft → P1
│   └── No → Credential compromise → P1 — Revoke, reset, investigate
│
├── Tor / Anonymiser Access (GEN-IA-003)?
│   └── → P1 — Revoke session, audit all actions taken
│
├── Magecart JS Modification (RG-IA-001)?
│   └── → P1 — Offline checkout page, PCI DSS breach assessment
│
└── ERP Off-Hours Access (RF-IA-001)?
    ├── Food safety records accessed?
    │   └── Yes → P1 — Notify Food Safety Manager immediately
    └── No → P2 — Verify business justification
```

---

## Key Queries

### Email Source Investigation (all phishing alerts)
```kql
EmailEvents | where RecipientEmailAddress == "<UPN>" | where Timestamp >= ago(24h)
| project Timestamp, SenderFromAddress, Subject, AttachmentCount, DeliveryAction
| order by Timestamp desc
```

### Identify All Affected Recipients (phishing campaign scope)
```kql
EmailAttachmentInfo | where SHA256 == "<ATTACHMENT_HASH>" | where Timestamp >= ago(24h)
| join kind=inner (EmailEvents | project NetworkMessageId, RecipientEmailAddress, DeliveryAction) on NetworkMessageId
| where DeliveryAction != "Blocked"
| distinct RecipientEmailAddress
```

### Post-Authentication Activity Review
```kql
AuditLogs | where InitiatedBy.user.userPrincipalName == "<UPN>" | where TimeGenerated >= ago(24h)
| project TimeGenerated, OperationName, Result, TargetResources | order by TimeGenerated desc
```
