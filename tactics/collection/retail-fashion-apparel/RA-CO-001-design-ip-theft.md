# RA-CO-001 — Design IP Theft: Fashion Collection File Exfiltration

| Field | Value |
|-------|-------|
| Rule ID | RA-CO-001 |
| Tactic | Collection |
| Technique | T1213 — Data from Information Repositories |
| Sector | **Fashion & Apparel Retail** |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Cloud Apps · Defender for Endpoint |
| Log Source | `OfficeActivity`, `CloudAppEvents`, `DeviceFileEvents` (MDE) |
| Retail Context | Design studio repositories, PLM systems, brand asset libraries, tech packs |

## Description
Mass download of fashion design files (Adobe AI/PSD, CAD, tech packs, line sheets) from design repositories by a single user. Pre-launch IP theft enables counterfeit operations and destroys a collection's commercial value. Insider threat (departing designers, contractors) and compromised accounts are the primary vectors.

---

## Microsoft Sentinel KQL
```kql
// RA-CO-001 | Frequency: 15m | Lookback: 1h
let DesignExtensions = dynamic([".ai",".psd",".eps",".indd",".cad",".dwg",".dxf",".tiff",".svg"]);
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in ("FileDownloaded","FileCopied","FileAccessed")
| where SourceFileName has_any (DesignExtensions)
    or Site_Url has_any ("design","collection","season","ss25","aw25","fw25","creative","tech-pack","linesheet","mood","runway","brand-assets")
| summarize FileCount=count(), UniqueFiles=dcount(SourceFileName), Files=make_set(SourceFileName,10), First=min(TimeGenerated), Last=max(TimeGenerated)
    by UserId, ClientIP, UserAgent
| where FileCount > 15
| extend IsExternal = (ClientIP !startswith "10." and ClientIP !startswith "192.168.")
| order by FileCount desc
```

---

## Defender for Cloud Apps — CASB Policy
Enable: **Unusual file download** anomaly policy.  
Configure label: Classify design library sites as **Sensitive** in MCAS — trigger alert on bulk download > 15 files.

---

## Investigation Guide

**Step 1 — User Context (< 10 min)**  
Is this user a designer, contractor, or agency partner?  
Is the user on notice, leaving the company, or in a dispute?  
Is the download volume within their normal 30-day pattern?

**Step 2 — Collection Sensitivity**  
Which collection's files were downloaded? Next season's unreleased designs?  
Were tech packs, costing sheets, or supplier data included?

**Step 3 — Destination of Files**
```kql
DeviceNetworkEvents | where AccountName contains "<USERNAME>" | where Timestamp >= ago(2h)
| where RemoteUrl has_any ("dropbox","wetransfer","we.tl","icloud","gdrive","airdrop")
| project Timestamp, RemoteUrl, BytesSent, InitiatingProcessFileName
```

**Step 4 — Brand Protection**  
If files confirmed exfiltrated: notify brand's IP legal team.  
Monitor counterfeit marketplaces (Alibaba, DHgate, Taobao) for early appearance.

---

## Response Actions
- [ ] Revoke access to design repositories immediately
- [ ] Block personal cloud storage at proxy
- [ ] Notify Head of Design and Legal / IP Counsel
- [ ] Preserve download logs as evidence for HR/legal proceedings
- [ ] Engage Anti-Counterfeiting Group (ACG) if exfiltration confirmed
- [ ] Consider accelerating or altering launch date for exposed collection

## References
- [MITRE T1213](https://attack.mitre.org/techniques/T1213/)
- [UK IPO: Reporting IP theft](https://www.gov.uk/report-intellectual-property-crime)
- [Anti-Counterfeiting Group](https://www.a-cg.org)
