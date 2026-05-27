# GEN-PE-003 — Persistence: Web Shell Installed on Web Server

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-PE-003` |
| **MITRE Tactic** | Persistence |
| **MITRE Technique** | T1505.003 — Server Software Component: Web Shell |
| **Sector** | Generic — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceFileEvents` · `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

A web-accessible script file (`.php`, `.aspx`, `.asp`, `.jsp`) written to a web-accessible path by the web server process or an unexpected account. Web shells give attackers persistent, interactive access to a compromised server via HTTP(S) — bypassing firewalls and VPNs entirely. Used extensively by nation-state actors (APT28, APT40) and ransomware groups as a persistent foothold.

This is a **zero-tolerance** rule — web shells must never be legitimately written by web server processes.

---

## Microsoft Sentinel KQL

```kql
// GEN-PE-003 | Frequency: 5m | Lookback: 5m | Threshold: > 0 — Zero Tolerance
DeviceFileEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "FileCreated"
| where FileName has_any (".php",".aspx",".asp",".jsp",".cfm",".shtml",".ashx",".asmx",".axd")
| where FolderPath has_any (
    "wwwroot","inetpub","htdocs","public_html","webroot","web","www",
    "upload","uploads","files","images","assets","static","media","content"
)
| where InitiatingProcessFileName in~ (
    "w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","tomcat.exe","java.exe",
    "apache.exe","lighttpd.exe"
)
    or FolderPath has_any ("upload","uploads","user-content","media")  // Upload directory = high risk
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessAccountName
| extend AlertTitle = strcat("Web Shell Installed: ", FileName, " in ", FolderPath)
| extend Severity = "Critical"
| extend Note = "Web shells must never be written by web server processes. No exceptions."
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-PE-003 | Run: Every hour
DeviceFileEvents
| where Timestamp >= ago(1h)
| where ActionType == "FileCreated"
| where FileName has_any (".php",".aspx",".asp",".jsp",".cfm")
| where FolderPath has_any ("wwwroot","inetpub","htdocs","public_html","upload","uploads")
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","java.exe")
    or InitiatingProcessAccountName has_any ("iusr","network service","www-data","apache")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

---

## Defender for Endpoint — Web Shell Usage Detection

```kql
// Detect commands executed via the web shell (web server spawning shells)
DeviceProcessEvents
| where DeviceName == "<WEB_SERVER>"
| where Timestamp between (ago(2h) .. now())
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","java.exe")
| where FileName in~ ("cmd.exe","powershell.exe","sh","bash","whoami.exe","net.exe","ipconfig.exe","id")
| project Timestamp, FileName, ProcessCommandLine, AccountName, SHA256
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1 — Submit hash immediately (0–5 min)**
Submit the web shell SHA256 to VirusTotal. Is it a known web shell family (China Chopper, WSO, b374k, Weevely, ASPXSpy)?

**Step 2 — How long has it been there? (5–15 min)**
Check the file creation timestamp. Has it been there for days or weeks? This determines the window of potential attacker activity.

**Step 3 — Commands executed via the shell (15–30 min)**
Run the "web shell usage" query above. What commands did the attacker run? What data did they access? What did they install?

**Step 4 — Lateral movement from the web server (30–60 min)**
Check for internal network connections, credential theft, and data staging from the web server.

---

## Response Actions
- [ ] Take web server offline — isolate immediately
- [ ] Delete the web shell file
- [ ] Preserve the file and logs as forensic evidence before deletion
- [ ] Audit all commands executed via the web shell
- [ ] Rotate all credentials accessible from the web server
- [ ] Full forensic review before returning server to service

## References
- [MITRE T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [CISA: Web shell malware guidance](https://www.cisa.gov/resources-tools/resources/web-shell-malware)
