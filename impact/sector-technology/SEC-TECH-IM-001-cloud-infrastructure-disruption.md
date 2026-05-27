# SEC-TECH-IM-001 — Technology: Cloud Infrastructure Mass Deletion / Disruption

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-TECH-IM-001` |
| **MITRE Technique** | T1485 — Data Destruction |
| **Sector** | Technology |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel |
| **Log Source** | `AzureActivity` · `CloudAppEvents` (MCAS) |

## Description
Mass deletion of Azure resources, storage blobs, VMs, or databases — indicating destructive attack or insider sabotage. Technology companies with cloud-native infrastructure face severe business continuity risk from resource deletion, particularly when backups are also targeted.

## Microsoft Sentinel KQL
```kql
// SEC-TECH-IM-001 | Frequency: 5m | Lookback: 15m
AzureActivity
| where TimeGenerated >= ago(15m)
| where OperationNameValue has_any ("delete","Delete","DELETE")
| where ActivityStatusValue == "Success"
| where ResourceProviderValue has_any (
    "Microsoft.Compute","Microsoft.Storage","Microsoft.Sql",
    "Microsoft.DBforPostgreSQL","Microsoft.DBforMySQL","Microsoft.Kubernetes",
    "Microsoft.Web","Microsoft.Network"
)
| summarize DeleteCount=count(), ResourceTypes=make_set(ResourceProviderValue,5), Resources=make_set(_ResourceId,10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 5m)
| where DeleteCount > 5
| extend AlertTitle = strcat("Cloud Resource Mass Deletion by ", Caller, " — ", DeleteCount, " resources")
| extend BusinessImpact = "Cloud infrastructure disruption — assess production service availability"
```

## Investigation Guide
**Step 1 (Immediate):** Which resources were deleted? Are production workloads affected?
**Step 2:** Is the caller a legitimate admin? Check if this matches a planned decommission task.
**Step 3:** Are Azure backups (Recovery Services vault) still intact?
**Step 4:** Begin resource restoration from backups or infrastructure-as-code.

## Response Actions
- [ ] Notify CTO and Head of Cloud Operations immediately
- [ ] Assess production service availability and customer impact
- [ ] Begin resource recovery from Azure backups / Terraform state
- [ ] Revoke the caller's credentials if unauthorised
- [ ] Notify affected customers if SLA breaches confirmed

## References - [MITRE T1485](https://attack.mitre.org/techniques/T1485/)
