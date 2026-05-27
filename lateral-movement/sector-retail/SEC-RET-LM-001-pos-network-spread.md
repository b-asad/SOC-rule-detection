# SEC-RET-LM-001 — Retail: Lateral Movement Across POS/Store Network

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-RET-LM-001` |
| **MITRE Technique** | T1550.002 — Pass the Hash |
| **Sector** | Retail |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity |
| **Log Source** | `IdentityLogonEvents` (MDI) |

## Description
NTLM lateral movement within the retail store network — particularly between POS terminals, store servers, and central office systems. Retail POS networks often have flat network architectures that allow ransomware to spread rapidly across all store terminals once initial access is gained.

## Microsoft Sentinel KQL
```kql
// SEC-RET-LM-001 | Frequency: 10m | Lookback: 10m
let POSHosts = (_GetWatchlist('POS-Hosts') | project SearchKey);
IdentityLogonEvents
| where TimeGenerated >= ago(10m)
| where ActionType == "LogonSuccess" and Protocol == "Ntlm"
| where DestinationDeviceName in~ (POSHosts)
    or DestinationDeviceName has_any ("pos","till","register","checkout","kiosk")
| where not(DeviceName in~ (POSHosts))
| project TimeGenerated, AccountName, DeviceName, DestinationDeviceName, Protocol
| extend AlertTitle = strcat("Retail POS Lateral Movement: ", DeviceName, " -> ", DestinationDeviceName)
| extend PCINote = "Attacker may be spreading toward cardholder data environment"
```

## Response Actions
- [ ] Isolate source and destination hosts
- [ ] Assess whether CDE has been reached — if yes: PCI DSS breach assessment
- [ ] Notify PCI Security Manager and acquiring bank if CHD systems reached

## References - [MITRE T1550.002](https://attack.mitre.org/techniques/T1550/002/)
