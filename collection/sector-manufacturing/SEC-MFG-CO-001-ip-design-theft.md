# SEC-MFG-CO-001 — Manufacturing: Product Design / IP Theft

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-MFG-CO-001` |
| **MITRE Technique** | T1213 — Data from Information Repositories |
| **Sector** | Manufacturing |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `OfficeActivity` · `DeviceFileEvents` (MDE) |

## Description
Mass download of product designs, CAD files, manufacturing specifications, or production processes. Manufacturing IP theft is a primary target for nation-state economic espionage and competitor intelligence gathering. CAD files, BOM (Bill of Materials), and process specifications represent significant competitive value.

## Microsoft Sentinel KQL
```kql
// SEC-MFG-CO-001 | Frequency: 15m | Lookback: 1h
let DesignExtensions = dynamic([".dwg",".dxf",".stp",".step",".iges",".catpart",".catproduct",".prt",".asm",".sldprt",".sldasm",".rfa"]);
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in ("FileDownloaded","FileCopied")
| where SourceFileName has_any (DesignExtensions)
    or Site_Url has_any ("design","cad","engineering","product","bom","specifications","r&d","prototype")
| summarize FileCount=count(), UniqueFiles=dcount(SourceFileName)
    by UserId, ClientIP
| where FileCount > 10
| extend AlertTitle = strcat("Design IP Bulk Download by ", UserId)
```

## Response Actions
- [ ] Revoke design repository access
- [ ] Notify Head of Engineering and Legal / IP Counsel
- [ ] Monitor for IP appearing in competitor products or patent filings

## References - [MITRE T1213](https://attack.mitre.org/techniques/T1213/)
