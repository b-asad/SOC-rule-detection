# SEC-FS-CO-001 — Financial Services: Proprietary Trading Data Exfiltration

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-FS-CO-001` |
| **MITRE Tactic** | Collection |
| **MITRE Technique** | T1213 — Data from Information Repositories |
| **Sector** | **Financial Services** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender for Endpoint |
| **Log Source** | `OfficeActivity` (M365 UAL) · `CloudAppEvents` (MCAS) · `DeviceFileEvents` (MDE) |
| **Sector Context** | Investment banks, hedge funds, asset managers, trading desks, broker-dealers |
| **Created** | May 2026 |

---

## Description

Detects bulk access or download of proprietary trading data, financial models, client portfolios, or market algorithms from data repositories. Financial services firms face significant insider threat risk from employees joining competitors or nation-state actors targeting algorithmic trading strategies and client data.

**Regulatory:** FCA PRIN 11 (transparency), MAR (market abuse), UK GDPR (client personal data). Potential criminal liability under Computer Misuse Act 1990 and Financial Services and Markets Act 2000.

---

## Microsoft Sentinel KQL

```kql
// SEC-FS-CO-001 | Frequency: 15m | Lookback: 1h | Threshold: > 0
let FinancialFileTypes = dynamic([
    "xlsb","xlsm","xlsx","csv","mat",  // Financial models
    "py","r","m","ipynb",              // Quant algorithms
    "mdb","accdb","sql","db",          // Databases
    "pdf","docx"                        // Reports, term sheets
]);
let TradingKeywords = dynamic([
    "alpha","algo","strategy","portfolio","position","pnl","blotter",
    "model","backtest","quant","signal","factor","risk","exposure",
    "client","aum","nav","fund","trade","order","execution"
]);
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in ("FileDownloaded","FileCopied","FileAccessed","SharingInvitationCreated")
| where SourceFileName has_any (FinancialFileTypes)
    or Site_Url has_any (TradingKeywords)
    or SourceFileName has_any (TradingKeywords)
| summarize
    FileCount    = count(),
    UniqueFiles  = dcount(SourceFileName),
    FileSample   = make_set(SourceFileName, 10),
    FirstEvent   = min(TimeGenerated),
    LastEvent    = max(TimeGenerated)
    by UserId, ClientIP, UserAgent
| where FileCount > 15
| extend IsExternal  = (ClientIP !startswith "10." and ClientIP !startswith "192.168.")
| extend AlertTitle  = strcat("Bulk Financial Data Download by ", UserId)
| extend FCAObligation = "Potential MAR / FSMA breach. Notify Compliance immediately."
| order by FileCount desc
```

---

## Investigation Guide

**Step 1 — Employee Context (< 10 min)**
Is this employee under notice? Have they recently accepted a position at a competitor?
Check HR system. Contact line manager (not the employee). Check recent badge access and IT usage patterns.

**Step 2 — Data Sensitivity (10–25 min)**
What files were accessed?
- Algorithmic trading strategies → severe IP theft risk
- Client PII or portfolio data → UK GDPR + FCA client data breach
- Inside information → potential Market Abuse Regulation (MAR) concern

**Step 3 — Destination of Data (25–40 min)**
```kql
DeviceNetworkEvents | where AccountName contains "<USERNAME>" | where Timestamp >= ago(2h)
| where RemoteUrl has_any ("dropbox","wetransfer","gdrive","onedrive.com","box.com","sharepoint")
| where not(RemoteUrl has "<CORPORATE_DOMAIN>")
| project Timestamp, RemoteUrl, BytesSent, InitiatingProcessFileName
```

---

## Response Actions
**Immediate**
- [ ] Revoke SharePoint/OneDrive access for the employee
- [ ] Block personal cloud storage at proxy
- [ ] Notify Compliance Officer and Legal immediately
- [ ] Preserve all access logs as evidence for potential legal proceedings

**Regulatory**
- [ ] FCA: Notify if client personal data accessed (UK GDPR 72h + FCA PRIN 11)
- [ ] MAR: Notify FCA Supervision if inside information may have been accessed
- [ ] Legal hold: Do NOT delete any evidence — preserve for litigation

## References
- [MITRE T1213](https://attack.mitre.org/techniques/T1213/)
- [FCA: Data security and market abuse](https://www.fca.org.uk/firms/systems-controls/market-abuse)
- [MAR: Market Abuse Regulation](https://www.fca.org.uk/markets/market-abuse/regulation)
