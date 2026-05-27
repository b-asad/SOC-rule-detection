# GEN-EF-003 — Exfiltration: Transfer to Cloud Storage Account

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-EF-003` |
| **MITRE Tactic** | Exfiltration |
| **MITRE Technique** | T1537 — Transfer Data to Cloud Account |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps · Defender for Endpoint |
| **Log Source** | `DeviceNetworkEvents` (MDE) · `CloudAppEvents` (MCAS) · `CommonSecurityLog` |
| **Created** | May 2026 |

---

## Description

Significant data upload to personal or unapproved cloud storage — Dropbox, Google Drive, WeTransfer, Mega, Box, OneDrive personal, GitHub, pastebin, file.io. Covers both browser-based uploads and CLI tool usage. This is the most common exfiltration method for insider threats.

---

## Microsoft Sentinel KQL

```kql
// GEN-EF-003 | Frequency: 15m | Lookback: 1h
let PersonalCloud = dynamic([
    "dropbox.com","dropboxapi.com","content.dropboxapi.com",
    "drive.google.com","www.googleapis.com",
    "mega.nz","mega.co.nz","g.api.mega.co.nz",
    "wetransfer.com","we.tl",
    "box.com","upload.box.com",
    "onedrive.live.com","storage.live.com",
    "mediafire.com","sendspace.com","gofile.io",
    "file.io","transfer.sh","anonfiles.com",
    "raw.githubusercontent.com","gist.github.com","paste.ee","pastebin.com"
]);
DeviceNetworkEvents
| where TimeGenerated >= ago(1h)
| where RemoteUrl has_any (PersonalCloud)
| where BytesSent > 500000  // > 500KB — filter out OAuth handshakes
| summarize TotalSent=sum(BytesSent), Sessions=count(), DestDomains=make_set(RemoteUrl,5)
    by DeviceName, AccountName, InitiatingProcessFileName, bin(TimeGenerated, 15m)
| extend TotalMB = round(toreal(TotalSent) / 1048576, 1)
| where TotalSent > 1000000  // > 1MB total
| extend AlertTitle = strcat(TotalMB, "MB uploaded to cloud storage from ", DeviceName)
| order by TotalSent desc
```

---

## Defender for Cloud Apps

```kql
// MCAS: Detect uploads to unsanctioned cloud storage
CloudAppEvents
| where Timestamp >= ago(1h)
| where ActionType in ("FileUploaded","FileSynced")
| where AppName in ("Dropbox","Google Drive","Box","WeTransfer","Mega","OneDrive Personal")
| summarize FileCount=count(), TotalBytes=sum(todouble(AdditionalFields.FileSize))
    by AccountUpn, AppName, IPAddress
| where TotalBytes > 5000000  // > 5MB
| order by TotalBytes desc
```

---

## Investigation Guide

**Step 1:** Identify the uploading user and device. Is this a departing employee?
**Step 2:** What was uploaded? Check device file events for what was staged before the upload.
**Step 3:** Can the uploaded content be recovered? Some cloud storage providers cooperate with legal holds.

---

## Response Actions
- [ ] Block personal cloud storage services at network egress (proxy/firewall)
- [ ] Suspend account access
- [ ] Notify HR and Legal — preserve evidence for proceedings
- [ ] Assess data sensitivity and breach notification obligations

## References - [MITRE T1537](https://attack.mitre.org/techniques/T1537/)
