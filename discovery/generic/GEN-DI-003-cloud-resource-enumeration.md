# GEN-DI-003 — Discovery: Cloud Resource / Azure Tenant Enumeration

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-DI-003` |
| **MITRE Tactic** | Discovery |
| **MITRE Technique** | T1580 — Cloud Infrastructure Discovery |
| **Sector** | Generic — All Customers |
| **Severity** | **Medium** |
| **Priority** | **P2** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `AzureActivity` · `AuditLogs` · `CloudAppEvents` (MCAS) |
| **Created** | May 2026 |

---

## Description

Bulk enumeration of Azure resources, subscriptions, Entra ID objects, or M365 tenant configuration — attacker mapping the cloud environment post-compromise to identify high-value targets (storage accounts, key vaults, VMs, sensitive SharePoint sites). Tools: Azure CLI, Azure PowerShell, Stormspotter, ROADtools, AzureHound.

---

## Microsoft Sentinel KQL

```kql
// GEN-DI-003 | Frequency: 15m | Lookback: 1h
AzureActivity
| where TimeGenerated >= ago(1h)
| where OperationNameValue has_any ("list","List","get","Get","read","Read")
| where ResourceProviderValue has_any (
    "Microsoft.KeyVault","Microsoft.Storage","Microsoft.Compute",
    "Microsoft.Sql","Microsoft.Authorization","Microsoft.Network"
)
| summarize ReadCount=count(), ResourceTypes=dcount(ResourceProviderValue),
    Operations=make_set(OperationNameValue,10)
    by Caller, CallerIpAddress, SubscriptionId, bin(TimeGenerated, 15m)
| where ReadCount > 50 and ResourceTypes > 3
| extend AlertTitle = strcat("Cloud Enum: ", ReadCount, " read operations by ", Caller)
| extend Note = "High-volume read-only operations indicate tenant mapping"
```

```kql
// AuditLogs: Entra ID tenant enumeration
AuditLogs
| where TimeGenerated >= ago(1h)
| where OperationName has_any ("Get","List") and Category in ("DirectoryManagement","ApplicationManagement")
| summarize Count=count() by InitiatedBy_UPN = tostring(InitiatedBy.user.userPrincipalName),
    IPAddress = tostring(InitiatedBy.user.ipAddress), bin(TimeGenerated, 15m)
| where Count > 30
| extend AlertTitle = strcat("Entra ID Enum: ", Count, " reads by ", InitiatedBy_UPN)
```

---

## Investigation Guide

**Step 1:** Is this a legitimate cloud management activity (DevOps, cloud governance tooling)?
**Step 2:** What resources were enumerated? Key Vaults and Storage accounts are high value.
**Step 3:** Was any sensitive data or secrets accessed during the enumeration?

---

## Response Actions
- [ ] Identify the tool making the requests (Azure CLI, SDK, custom script)
- [ ] Revoke the credentials used if compromise confirmed
- [ ] Enable Azure Defender for Key Vault and Storage

## References - [MITRE T1580](https://attack.mitre.org/techniques/T1580/)
