# SEC-EDU-CO-001 — Education: Research IP / Data Theft

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-EDU-CO-001` |
| **MITRE Technique** | T1213 — Data from Information Repositories |
| **Sector** | Education |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `OfficeActivity` · `DeviceFileEvents` (MDE) |

## Description
Bulk download of research data, grant applications, or intellectual property. Nation-state actors (particularly China-attributed groups) specifically target university research in defence, quantum computing, life sciences, and AI. EPSRC/UKRI-funded research may have export control implications.

## Microsoft Sentinel KQL
```kql
// SEC-EDU-CO-001 | Frequency: 15m | Lookback: 1h
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in ("FileDownloaded","FileCopied")
| where SourceFileName has_any ("research","grant","thesis","paper","dataset","lab","experiment","trial","prototype","patent","IP")
    or Site_Url has_any ("research","grants","lab","hpc","data-repository")
| summarize FileCount=count(), UniqueFiles=dcount(SourceFileName)
    by UserId, ClientIP
| where FileCount > 20
| extend AlertTitle = strcat("Research Data Bulk Download by ", UserId)
| extend ExportControlNote = "Check if data subject to export control (dual-use research)"
```

## Response Actions
- [ ] Revoke repository access
- [ ] Notify Research IT and Vice-Chancellor's office
- [ ] Check export control obligations if defence/dual-use research involved
- [ ] Notify NCSC if nation-state indicators present

## References - [MITRE T1213](https://attack.mitre.org/techniques/T1213/)
