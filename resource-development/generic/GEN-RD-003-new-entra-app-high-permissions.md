# GEN-RD-003 — Resource Development: Service Principal with Privileged API Permissions

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-RD-003` |
| **MITRE Tactic** | Resource Development / Persistence |
| **MITRE Technique** | T1098.003 — Account Manipulation: Additional Cloud Roles |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `AuditLogs` |
| **Created** | May 2026 |

---

## Description

A service principal (application identity) granted application-level permissions (not delegated) with Global Admin or equivalent scope. Application permissions are more dangerous than delegated because they operate without a signed-in user, run continuously in the background, and cannot be constrained by Conditional Access. An attacker controlling an app with `Mail.Read` application permission can silently read every mailbox in the tenant indefinitely.

---

## Microsoft Sentinel KQL

```kql
// GEN-RD-003 | Frequency: 15m | Lookback: 1h
let DangerousAppPerms = dynamic([
    "Mail.Read","Mail.ReadWrite","Mail.Send",
    "Files.Read.All","Files.ReadWrite.All",
    "Sites.Read.All","Sites.FullControl.All",
    "User.Read.All","User.ReadWrite.All",
    "Group.Read.All","Group.ReadWrite.All",
    "Directory.Read.All","Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All"
]);
AuditLogs
| where TimeGenerated >= ago(1h)
| where OperationName in ("Add app role assignment to service principal","Add OAuth2PermissionGrant")
| extend Actor       = tostring(InitiatedBy.user.userPrincipalName)
| extend SPName      = tostring(TargetResources[0].displayName)
| extend Permission  = tostring(AdditionalDetails[1].value)
| where Permission has_any (DangerousAppPerms)
| project TimeGenerated, Actor, SPName, Permission, OperationName, Result
| extend AlertTitle = strcat("Dangerous App Permission Granted: ", Permission, " to ", SPName)
| extend RiskNote = "Application permissions operate without a signed-in user and bypass Conditional Access"
```

---

## Investigation Guide

**Step 1 — Was this an authorised provisioning? (0–10 min)**
Is there an ITSM ticket? Contact the assigning admin.
**Step 2 — Has the SP already used these permissions?**
Check CloudAppEvents for activity from the service principal.
**Step 3 — Revoke and audit.**

---

## Response Actions
- [ ] Revoke the dangerous permission immediately
- [ ] Audit all actions performed by the service principal
- [ ] Review who provisioned the SP and when
- [ ] Require PIM approval for all application admin consent going forward

## References - [MITRE T1098.003](https://attack.mitre.org/techniques/T1098/003/)
