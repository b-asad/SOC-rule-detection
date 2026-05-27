# GEN-PE-004 — Persistence: New Cloud Account / Privileged Role Assignment

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-PE-004` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | T1078.004 — Valid Accounts: Cloud Accounts / T1098 — Account Manipulation |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Cloud Apps |
| **Log Source** | `AuditLogs` · `CloudAppEvents` (MCAS) |
| **Created** | May 2026 |

---

## Description

New privileged Entra ID account created, or Global Admin / Privileged Role Administrator role assigned to an existing account — outside of the approved identity management workflow. Attackers use this to establish persistent privileged access that survives password resets on the initially compromised account.

Also covers new OAuth application granted admin consent, new service principal created with high permissions, and new federated identity credential added to an application (for OIDC token-based persistence).

---

## Microsoft Sentinel KQL

```kql
// GEN-PE-004 | Frequency: 5m | Lookback: 15m
let HighPrivRoles = dynamic([
    "Global Administrator","Privileged Role Administrator","Application Administrator",
    "Cloud Application Administrator","Exchange Administrator","SharePoint Administrator",
    "Security Administrator","User Administrator","Authentication Administrator",
    "Hybrid Identity Administrator"
]);
// Detection A: High-privilege role assignment
let RoleAssignment = (
    AuditLogs
    | where TimeGenerated >= ago(15m)
    | where OperationName in ("Add member to role","Add eligible member to role")
    | extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
    | extend RoleName  = tostring(TargetResources[0].modifiedProperties[1].newValue)
    | where RoleName has_any (HighPrivRoles)
    | extend AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
    | project TimeGenerated, AssignedBy, TargetUPN, RoleName, Result
    | extend DetectionType = "PrivilegedRoleAssigned"
);
// Detection B: New service principal / app registration created
let NewSPN = (
    AuditLogs
    | where TimeGenerated >= ago(15m)
    | where OperationName in ("Add service principal","Add application")
    | extend AppName   = tostring(TargetResources[0].displayName)
    | extend CreatedBy = tostring(InitiatedBy.user.userPrincipalName)
    | project TimeGenerated, CreatedBy, AppName, Result
    | extend DetectionType = "NewServicePrincipal"
);
RoleAssignment | union NewSPN
| extend AlertTitle = strcat("Cloud Persistence: ", DetectionType)
```

---

## Defender for Cloud Apps

```kql
// MCAS: Admin consent granted to new application
CloudAppEvents
| where Timestamp >= ago(1h)
| where ActionType in ("Consent to application","Add OAuth2PermissionGrant")
| extend AppName = tostring(AdditionalFields.AppName)
| extend Permissions = tostring(AdditionalFields.ConsentType)
| where Permissions == "AllPrincipals"  // Admin-level consent
| project Timestamp, AccountUpn, AppName, Permissions, IPAddress
```

---

## Investigation Guide

**Step 1 — Was this change authorised? (0–10 min)**
Is there an approved ITSM ticket for this role assignment? Contact the assigning account's manager.
Was the assigning account itself recently compromised? Run GEN-IA-002 / GEN-CA-001 checks on the assigning account.

**Step 2 — What has the new admin done? (10–25 min)**
```kql
AuditLogs | where InitiatedBy.user.userPrincipalName == "<NEW_ADMIN_UPN>"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, OperationName, Result, TargetResources | order by TimeGenerated asc
```

**Step 3 — Remove and lock down**
Revoke the unauthorised role assignment immediately. Review all changes made by the account.

---

## Response Actions
- [ ] Revoke the unauthorised role assignment
- [ ] Disable the account if it was created by the attacker
- [ ] Review all tenant-level changes made since the assignment
- [ ] Enable Privileged Identity Management (PIM) for all admin role assignments going forward

## References
- [MITRE T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [Microsoft: PIM for privileged roles](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
