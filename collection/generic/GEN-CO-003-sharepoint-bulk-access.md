# GEN-CO-003 — Collection: SharePoint / OneDrive Mass Document Access

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CO-003` |
| **MITRE Tactic** | Collection |
| **MITRE Technique** | T1213.002 — Data from Information Repositories: SharePoint |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender XDR |
| **Log Source** | `OfficeActivity` (M365 UAL) · `CloudAppEvents` (MCAS) |
| **Created** | May 2026 |

---

## Description

Single user accessing or downloading an anomalously high number of unique SharePoint/OneDrive files within a short window — consistent with automated collection or insider data theft. Threshold set above the 99th percentile for normal user behaviour (typically > 50 unique file accesses per hour).

---

## Microsoft Sentinel KQL

```kql
// GEN-CO-003 | Frequency: 15m | Lookback: 1h
OfficeActivity
| where TimeGenerated >= ago(1h)
| where Operation in (
    "FileDownloaded","FileCopied","FileAccessed",
    "FileCheckedOut","FileVersionDownloaded","PageViewed"
)
| where RecordType in ("SharePointFileOperation","OneDrive")
| summarize
    FileCount    = count(),
    UniqueFiles  = dcount(SourceFileName),
    UniqueSites  = dcount(SiteUrl),
    FileSample   = make_set(SourceFileName, 10),
    FirstEvent   = min(TimeGenerated),
    LastEvent    = max(TimeGenerated)
    by UserId, ClientIP, UserAgent
| where UniqueFiles > 50
| extend DownloadRate = round(toreal(UniqueFiles) / 60.0, 1)  // Files per minute
| extend AlertTitle = strcat("SharePoint Mass Access: ", UniqueFiles, " files by ", UserId)
| order by UniqueFiles desc
```

---

## Defender for Cloud Apps

```kql
// MCAS: Mass download with sensitivity label tracking
CloudAppEvents
| where Timestamp >= ago(1h)
| where ActionType == "FileDownloaded"
| where AppName in ("Microsoft SharePoint Online","Microsoft OneDrive for Business")
| summarize Count=count(), SensitiveFiles=countif(isnotempty(tostring(AdditionalFields.SensitivityLabelName)))
    by AccountUpn, IPAddress, AppName
| where Count > 30
| order by Count desc
```

---

## Investigation Guide

**Step 1 — User context (0–10 min)**
What is this user's role? Does their job require access to this volume of files?
Are they a departing employee? Under notice? Recent disciplinary action?

**Step 2 — What data? (10–25 min)**
Which sites and documents were accessed? Financial, HR, client, or operational data?

**Step 3 — Destination (25–40 min)**
Was the data downloaded to a local device? Check DeviceNetworkEvents for subsequent uploads to external services.

---

## Response Actions
- [ ] Revoke the user's SharePoint/OneDrive access pending investigation
- [ ] Preserve SharePoint audit logs
- [ ] Notify HR and Legal if insider threat confirmed
- [ ] Assess UK GDPR breach notification if personal data involved

## References - [MITRE T1213.002](https://attack.mitre.org/techniques/T1213/002/)
