# SEC-GOV-IM-001 — Government: Public Website Defacement / Content Injection

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-GOV-IM-001` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | T1491.002 — Defacement: External Defacement |
| **Sector** | **Government** |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceFileEvents` (MDE) · `AzureDiagnostics` (WAF / App Gateway) |
| **Sector Context** | Central government departments, local authorities, NDPBs, arm's-length bodies, public sector web portals |
| **Created** | May 2026 |

---

## Description

Modification of public-facing government website content outside of an approved deployment pipeline — a strong indicator of defacement by hacktivists, nation-state actors, or opportunistic attackers. Government websites are high-profile targets for political messaging, propaganda, disinformation campaigns, and public confidence attacks.

Defacement precursors include: web shell upload, CMS admin account compromise, and CDN/DNS manipulation. NCSC should be notified for any confirmed government website defacement.

---

## Microsoft Sentinel KQL

```kql
// SEC-GOV-IM-001 | Frequency: 5m | Lookback: 5m
// Detection 1: Web content files modified outside CI/CD pipeline on web server
let WebContentFiles = (
    DeviceFileEvents
    | where TimeGenerated >= ago(5m)
    | where FileName has_any (".html",".htm",".php",".aspx",".js",".css",".json")
    | where FolderPath has_any (
        "wwwroot","inetpub","htdocs","public_html","webroot",
        "gov.uk","www","web","site","portal","public"
    )
    | where ActionType in ("FileCreated","FileModified")
    | where InitiatingProcessFileName !in~ (
        "w3wp.exe","iis","httpd","nginx","apache","deploy_agent",
        "git","node","npm","TeamCity","Jenkins","octopus","azure-pipelines"
    )
    | project TimeGenerated, DeviceName, FileName, FolderPath,
        SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
    | extend DetectionType = "WebContentModified"
);
// Detection 2: Web shell upload — executable script in web-accessible path
let WebShellUpload = (
    DeviceFileEvents
    | where TimeGenerated >= ago(5m)
    | where FileName has_any (".php",".aspx",".asp",".jsp",".cfm",".shtml")
    | where FolderPath has_any ("wwwroot","inetpub","htdocs","public_html","upload","files","images","assets")
    | where ActionType == "FileCreated"
    | where InitiatingProcessFileName !in~ ("w3wp.exe","httpd","nginx","deploy_agent","git")
    | project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
    | extend DetectionType = "WebShellUploaded"
    | extend Note = "Web shell gives attacker persistent server access — Critical escalation if confirmed"
);
WebContentFiles | union WebShellUpload
| extend AlertTitle = strcat("Gov Website Defacement Indicator: ", FileName, " on ", DeviceName)
| extend NCSObligation = "Report to NCSC via report.ncsc.gov.uk for any confirmed government website defacement"
| extend CommsNote = "Notify Communications team — prepare public statement if defacement is visible"
```

---

## Defender for Endpoint — Web Server Investigation

```kql
// What process modified or created the suspicious web file?
DeviceProcessEvents
| where DeviceName == "<WEB_SERVER_FROM_ALERT>"
| where Timestamp between (ago(4h) .. now())
| where ProcessCommandLine has_any (
    "upload","wget","curl","PowerShell","certutil","bitsadmin","ftp",
    "<script","eval(","base64","shell_exec","system(","passthru"
)
| project Timestamp, FileName, ProcessCommandLine, AccountName, SHA256, FolderPath
| order by Timestamp asc
```

```kql
// Check for recent logins to the web server from unexpected sources
DeviceLogonEvents
| where DeviceName == "<WEB_SERVER_FROM_ALERT>"
| where Timestamp between (ago(24h) .. now())
| where ActionType == "LogonSuccess"
| where LogonType in ("Network","RemoteInteractive")
| project Timestamp, AccountName, RemoteIP, RemoteDeviceName, LogonType
| order by Timestamp asc
```

```kql
// Check WAF logs for exploit attempts before the defacement
AzureDiagnostics
| where TimeGenerated >= ago(24h)
| where Category in ("ApplicationGatewayFirewallLog","ApplicationGatewayAccessLog")
| where serverRouted_s contains "<WEB_SERVER_IP>"
| where action_s == "Blocked" or tostring(details_message_s) has "injection"
| project TimeGenerated, clientIP_s, requestUri_s, action_s, details_message_s
| order by TimeGenerated asc
```

---

## Investigation Guide

**Step 1 — Confirm defacement (0–5 min)**
Is the defacement already visible on the public website? Take a screenshot immediately — this is evidence.
Notify Communications / Press team now — they need to prepare a response statement.

**Step 2 — Initial access vector (5–20 min)**
How did the attacker modify the file?
- Web shell (see DetectionType = WebShellUploaded) → server is fully compromised
- Compromised deployment account → check all recent deployments
- CMS admin account compromise → check CMS admin login logs
- FTP/SFTP access → check FTP server logs

**Step 3 — Scope of compromise (20–40 min)**
If a web shell was uploaded: the attacker has interactive access to the server. Run the web server process investigation query. What commands have been run via the web shell?

If CMS compromise: what pages were modified? Were any data collection forms tampered with?

**Step 4 — Remediation sequencing (40–60 min)**
1. Offline the website (show maintenance page)
2. Restore clean content from last known-good deployment
3. Remove any web shells found
4. Rotate all deployment credentials, FTP passwords, and CMS admin accounts
5. Review WAF rules for gaps that allowed the attack

---

## Response Actions

**Immediate**
- [ ] Take the affected web server offline or replace with maintenance page
- [ ] Take screenshot evidence of the defacement
- [ ] Notify Communications / Press team — prepare public statement
- [ ] Notify Departmental Security Officer (DSO) and SIRO

**Within 1 Hour**
- [ ] Remove defaced content — restore from last known-good deployment
- [ ] Remove any web shells found on the server
- [ ] Rotate all web server and CMS credentials
- [ ] Report to NCSC via [report.ncsc.gov.uk](https://report.ncsc.gov.uk)

**Post-Incident**
- [ ] Full web server forensic review before bringing back online
- [ ] Implement deployment-only write permissions — no web server should have writable web roots via interactive sessions
- [ ] Enable WAF in Prevention mode and review ruleset
- [ ] Post-incident review — publish timeline and remediation for internal record

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Authorised emergency content update by authorised developer | Require all changes via CI/CD — no manual file writes to production web root |
| CMS auto-saving drafts or cache files | Add CMS process name (e.g., `w3wp.exe`) to exclusion list — verify against specific web content paths |

## References
- [MITRE T1491.002](https://attack.mitre.org/techniques/T1491/002/)
- [NCSC: Website security guidance](https://www.ncsc.gov.uk/guidance/website-security)
- [NCSC: Report a cyber incident](https://report.ncsc.gov.uk)
