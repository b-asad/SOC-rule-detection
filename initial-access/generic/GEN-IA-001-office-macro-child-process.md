# GEN-IA-001 — Office Macro Child Process Spawn

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IA-001` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1566.001 — Spearphishing Attachment |
| **Sector** | **Generic** — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint · Defender for Office 365 |
| **Log Source** | `DeviceProcessEvents` (MDE) · `EmailAttachmentInfo` (MDO) |
| **Created** | May 2026 |
| **Review Date** | August 2026 |

---

## Description

Detects when a Microsoft Office application (Word, Excel, PowerPoint, Access, OneNote) opens an email attachment and spawns a suspicious child process — `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, or similar LOLBins. This is a high-fidelity indicator that a malicious macro or embedded object has executed a payload from a phishing attachment.

This rule applies to **every customer regardless of sector**. All major ransomware families (LockBit, BlackCat, Clop), commodity RATs (AsyncRAT, Agent Tesla), and APT implants use this exact delivery mechanism. The Defender for Office 365 correlation query traces the alert back to the originating phishing email without leaving Defender XDR.

---

## Microsoft Sentinel KQL

```kql
// ───────────────────────────────────────────────────────────────
// GEN-IA-001 | Office Macro Spawns Suspicious Child Process
// Frequency: 5m | Lookback: 5m | Threshold: > 0
// Entity: Device → DeviceName | Account → AccountName
// Playbook: PB-ISOLATE-HOST
// ───────────────────────────────────────────────────────────────
let OfficeApps = dynamic([
    "WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE",
    "MSACCESS.EXE","MSPUB.EXE","ONENOTE.EXE"
]);
let SuspiciousChildren = dynamic([
    "cmd.exe","powershell.exe","pwsh.exe","wscript.exe",
    "cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe",
    "certutil.exe","bitsadmin.exe","wmic.exe","msiexec.exe",
    "installutil.exe","schtasks.exe","at.exe"
]);
let Exclusions = (_GetWatchlist('GEN-IA-001-Exclusions') | project SearchKey);
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where InitiatingProcessFileName in~ (OfficeApps)
| where FileName in~ (SuspiciousChildren)
| where not(InitiatingProcessSHA256 in (Exclusions))
| project
    TimeGenerated,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    FileName,
    ProcessCommandLine,
    SHA256,
    FolderPath,
    InitiatingProcessParentFileName
| extend AlertTitle = strcat("Office Macro Spawned ", FileName, " on ", DeviceName)
| extend MitreTechnique = "T1566.001"
```

**Sentinel Settings:** Frequency `5m` · Lookback `5m` · Threshold `> 0` · Playbook: `PB-ISOLATE-HOST`

---

## Defender XDR — Advanced Hunting

```kql
// ───────────────────────────────────────────────────────────────
// GEN-IA-001 | Defender XDR Custom Detection
// Run: Every hour | Severity: High | Category: InitialAccess
// Entities: Device → DeviceName, User → AccountName
// ───────────────────────────────────────────────────────────────
let OfficeApps = dynamic([
    "WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","MSACCESS.EXE","ONENOTE.EXE"
]);
let SuspiciousChildren = dynamic([
    "cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe","bitsadmin.exe",
    "wmic.exe","msiexec.exe","installutil.exe","schtasks.exe"
]);
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where InitiatingProcessFileName in~ (OfficeApps)
| where FileName in~ (SuspiciousChildren)
| project
    Timestamp, DeviceName, DeviceId, AccountName, AccountDomain,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256,
    FileName, ProcessCommandLine, SHA256, FolderPath
| order by Timestamp desc
```

---

## Defender for Endpoint — MDE Queries

**Full process tree from the compromised host:**
```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(2h) .. now())
| project
    Timestamp,
    InitiatingProcessParentFileName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    AccountName,
    FolderPath,
    SHA256
| order by Timestamp asc
```

**Network connections spawned during the attack:**
```kql
DeviceNetworkEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(2h) .. now())
| where InitiatingProcessFileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","mshta.exe",
    "regsvr32.exe","rundll32.exe","certutil.exe"
)
| project
    Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine,
    RemoteIP, RemoteUrl, RemotePort, ActionType
| order by Timestamp asc
```

**Files dropped to disk during the attack:**
```kql
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(2h) .. now())
| where InitiatingProcessFileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","mshta.exe"
)
| where FolderPath has_any ("Temp","AppData","ProgramData","Desktop","Downloads")
| project Timestamp, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

**Persistence created during the attack:**
```kql
DeviceRegistryEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(2h) .. now())
| where RegistryKey has_any (
    "CurrentVersion\\Run","CurrentVersion\\RunOnce",
    "CurrentVersion\\Services","Winlogon"
)
| where ActionType in ("RegistryKeyCreated","RegistryValueSet")
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

**MDE Live Response — run directly on the isolated device:**
```
# List all running processes
processes

# Show active network connections
connections

# Collect suspicious file for analysis (replace path)
getfile "C:\Users\<USER>\AppData\Local\Temp\<SUSPICIOUS_FILE>"

# Run antivirus scan on device
run av_scan
```

**ASR Rule (enable in Block mode to prevent attack before detection):**
- Rule: Block Office apps from creating child processes
- GUID: `d4f940ab-401b-4efc-aadc-ad5f3c50688a`
- Mode: **Block** (start with Audit mode for 14 days)

---

## Defender for Office 365 — Email Source

**Find the originating phishing email:**
```kql
EmailAttachmentInfo
| where Timestamp >= ago(24h)
| where SHA256 == "<ATTACHMENT_SHA256_FROM_ALERT>"
| join kind=inner (
    EmailEvents
    | where Timestamp >= ago(24h)
    | project
        NetworkMessageId, RecipientEmailAddress, SenderFromAddress,
        SenderFromDomain, Subject, DeliveryAction, ThreatTypes
) on NetworkMessageId
| project
    Timestamp, RecipientEmailAddress, SenderFromAddress,
    SenderFromDomain, Subject, FileName, SHA256, DeliveryAction, ThreatTypes
```

**Find all other campaign recipients — scope the blast radius:**
```kql
let PhishHash = "<ATTACHMENT_SHA256>";
EmailAttachmentInfo
| where Timestamp >= ago(48h)
| where SHA256 == PhishHash
| join kind=inner (
    EmailEvents
    | where Timestamp >= ago(48h)
    | where DeliveryAction != "Blocked"
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress
) on NetworkMessageId
| distinct RecipientEmailAddress, SenderFromAddress
```

**Check if any URLs in the email were clicked:**
```kql
UrlClickEvents
| where Timestamp >= ago(24h)
| where AccountUpn == "<AFFECTED_USER_UPN>"
| project Timestamp, Url, ActionType, ThreatTypes, AccountUpn
```

---

## Investigation Guide

### Step 1 — Immediate Triage (0–5 minutes)
**Isolate the device NOW — before reading further.**

1. MDE portal → Device inventory → search device name → **Isolate device**
2. Record: device name, user account, parent Office app, child process and full command line
3. Is the command line encoded? (contains `-EncodedCommand`, `FromBase64String`) → decode immediately (see Step 2)
4. Is the user a privileged account (IT admin, finance, C-suite)? → escalate to SOC Manager immediately
5. Notify on-call Senior Analyst and open P1 incident ticket

### Step 2 — Decode the Payload (5–15 minutes)

If PowerShell with encoded command:
```powershell
# Decode on analyst workstation — NOT on customer device
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String("PASTE_BASE64_HERE")
)
```
Or use CyberChef: From Base64 → Decode Text (UTF-16LE).

In the decoded content, identify:
- Download URLs → submit to VirusTotal immediately
- File paths → check DeviceFileEvents for dropped files
- Persistence commands → check registry and scheduled tasks
- Credential harvesting → treat as GEN-CA-001 LSASS threat

### Step 3 — Email Campaign Scope (15–25 minutes)

Run both MDO queries above. For every additional recipient found:
- Run `DeviceProcessEvents` query on their device for the same Office → child process pattern
- If found: add device to isolation queue and expand the incident

### Step 4 — C2 and Network (25–40 minutes)

Run the MDE network connections query. For each external IP/domain:
1. VirusTotal → AlienVault OTX → Shodan → AbuseIPDB reputation check
2. WHOIS: domain age < 30 days = high confidence malicious
3. Add to MDE custom indicators (Block) and Sentinel TI watchlist
4. Search the same C2 across ALL customer environments in Sentinel

### Step 5 — Lateral Movement (40–60 minutes)

```kql
DeviceLogonEvents
| where Timestamp between (ago(4h) .. now())
| where DeviceName == "<DEVICE_NAME>" or RemoteDeviceName == "<DEVICE_NAME>"
| where LogonType in ("Network","RemoteInteractive","CachedInteractive")
| project Timestamp, AccountName, DeviceName, RemoteDeviceName, LogonType, ActionType
| order by Timestamp asc
```

If lateral movement detected: expand isolation scope to all connected devices.

---

## Response Actions

**Immediate (P1 — within 15 minutes)**
- [ ] Isolate device — MDE portal
- [ ] Notify customer primary security contact by phone
- [ ] Block sender domain — MDO / Exchange Online
- [ ] Block attachment SHA256 — MDE custom indicators
- [ ] Revoke user sessions — Entra ID portal
- [ ] Open P1 incident ticket — tag `PHISHING-MACRO-P1`

**Within 1 Hour**
- [ ] Search all campaign recipients and check their devices
- [ ] Block all identified C2 IPs/domains — MDE indicators + Sentinel watchlist
- [ ] Submit attachment to sandbox — Defender TI or any.run
- [ ] Collect memory dump via MDE Live Response (before any reboot)
- [ ] Check and remove any persistence established (scheduled tasks, run keys, services)

**Recovery**
- [ ] Rebuild host from clean image
- [ ] Reset user password + force MFA re-enrolment
- [ ] Review and revoke all OAuth consents granted by the compromised account
- [ ] Post-incident review within 5 business days

---

## False Positives

| Scenario | Evidence | Mitigation |
|----------|---------|-----------|
| Signed corporate macro launching a helper script | `InitiatingProcessSHA256` matches a known and approved template hash | Add specific SHA256 to `GEN-IA-001-Exclusions` watchlist — get written approval from SOC Manager |
| RMM agent launched via Office integration | Child process is a signed binary from an approved vendor folder | Exclude by signed process path AND hash — never by name alone |
| Legitimate PDF conversion tool (Office plugin) | Vendor-signed binary, consistent across all users, same path | Add vendor certificate hash to approved list after security review |

---

## Tuning Guidance

- All exclusions live in the `GEN-IA-001-Exclusions` Sentinel watchlist — never hardcode in the query
- If FP rate is high: the correct fix is blocking unsigned macros via Group Policy (`VBAWarnings = 4`) rather than suppressing this alert
- Enable ASR rule `d4f940ab` in Block mode — this prevents the process spawn before detection fires
- Consider enabling **Protected View** enforcement for all documents from the internet in Office Trust Center settings

---

## References

- [MITRE T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [Microsoft: Internet macro block policy](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked)
- [ASR rules reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [MDE: Live Response](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/live-response)
