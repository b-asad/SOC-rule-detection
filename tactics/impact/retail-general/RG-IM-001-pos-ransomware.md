# RG-IM-001 — Impact: Ransomware Targeting POS / Retail Infrastructure

| Field | Value |
|-------|-------|
| Rule ID | RG-IM-001 |
| Tactic | Impact |
| Technique | T1486 — Data Encrypted for Impact |
| Sector | **Retail General** |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceProcessEvents`, `DeviceFileEvents` (MDE) |
| Retail Context | POS systems, store network, ERP, inventory management |

## Description
Ransomware deployment targeting retail infrastructure. Retail ransomware typically propagates via the store network to POS terminals, inventory systems, and ERP servers, causing store closure and significant trading losses. Shadow copy deletion (GEN-IM-001) typically precedes this alert — if both fire, treat as confirmed active ransomware outbreak.

---

## Microsoft Sentinel KQL
```kql
// RG-IM-001 | Frequency: 5m | Lookback: 5m
// Correlate with GEN-IM-001 (shadow copy deletion)
let ShadowDeleted = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(30m)
    | where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
        or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    | distinct DeviceName
);
DeviceFileEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "FileModified"
| summarize FileCount=count(), Folders=dcount(FolderPath) by DeviceName, InitiatingProcessFileName, bin(TimeGenerated,1m)
| where FileCount > 100
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","OneDrive.exe","BackupAgent.exe")
| where DeviceName in (ShadowDeleted) or FileCount > 500  // High confidence without shadow delete correlation
| extend RetailImpact = "Store operations may be impacted — assess trading continuity immediately"
```

---

## Investigation Guide

**Step 1 — Trading Impact (Immediate)**  
Has the ransomware reached POS terminals? If so, stores cannot process card payments.  
Activate BCP: can stores accept cash? Do they have offline payment fallback?  
Notify customer Operations Director alongside CISO.

**Step 2 — Blast Radius — Store Network**  
Which stores are affected? Is this contained to one store or propagating via the WAN?  
Check store network architecture — are POS VLANs isolated?

**Step 3 — Isolate and Segment**  
Isolate affected stores from the corporate network.  
Disconnect affected stores from the payment network to prevent further spread.

---

## Response Actions
- [ ] Isolate affected hosts — MDE
- [ ] Isolate affected store(s) from WAN
- [ ] Notify customer Operations Director — trading impact assessment
- [ ] Activate BCP — cash-only fallback for affected stores
- [ ] Notify acquiring bank if POS in-scope hosts are affected
- [ ] Preserve forensic evidence — patient zero identification

## References
- [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
- [NCSC: Ransomware guidance for retail](https://www.ncsc.gov.uk/ransomware/home)
