# GEN-CA-001 — OS Credential Dumping: LSASS Memory Access

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CA-001` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Sector** | **Generic** — All Customers |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint · Defender for Identity |
| **Log Source** | `DeviceEvents` (MDE) — ActionType: OpenProcessApiCall · `IdentityLogonEvents` (MDI) |
| **Created** | May 2026 |
| **Review Date** | August 2026 |

---

## Description

Detects any process opening the LSASS process (`lsass.exe`) with `PROCESS_VM_READ`, `PROCESS_ALL_ACCESS`, or equivalent access rights. LSASS holds plaintext passwords (via WDigest if enabled), NTLM hashes, and Kerberos tickets for all accounts with active sessions on the host. A successful LSASS dump gives an attacker credentials for every user logged into the machine.

Common tools that trigger this rule: **Mimikatz** (`sekurlsa::logonpasswords`), **ProcDump** (`procdump.exe -ma lsass.exe`), **comsvcs.dll** (`rundll32 comsvcs.dll MiniDump`), **Task Manager** manual dump, **Cobalt Strike** `hashdump`, and custom shellcode loaders.

This rule must **never be suppressed or have its threshold raised**. Every true positive represents a credential breach affecting all accounts with sessions on the host.

---

## Microsoft Sentinel KQL

```kql
// ───────────────────────────────────────────────────────────────
// GEN-CA-001 | LSASS Memory Access — Credential Dump Attempt
// Frequency: 5m | Lookback: 5m | Threshold: > 0
// Entity: Device → DeviceName | Account → AccountName
// Playbook: PB-ISOLATE-AND-RESET-CREDENTIALS
// ───────────────────────────────────────────────────────────────
let ApprovedProcesses = dynamic([
    "MsMpEng.exe",          // Windows Defender Antivirus
    "SenseCE.exe",          // MDE Sense — Cyber Entities
    "MsSense.exe",          // MDE Sense — main sensor
    "csrss.exe",            // Client Server Runtime
    "wininit.exe",          // Windows Initialization
    "lsm.exe",              // Local Session Manager
    "svchost.exe",          // Service Host (only if path is System32)
    "AzureADConnectAuthenticationAgentService.exe"  // Entra Connect agent
]);
DeviceEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (ApprovedProcesses))
| where AdditionalFields has_any (
    "PROCESS_VM_READ",
    "PROCESS_ALL_ACCESS",
    "0x1010",   // PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    "0x1fffff", // PROCESS_ALL_ACCESS
    "0x1f3fff", // PROCESS_ALL_ACCESS variant
    "0x1038"    // PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE
)
| project
    TimeGenerated,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    InitiatingProcessParentFileName,
    AdditionalFields
| extend AlertTitle = strcat("LSASS Memory Access by ", InitiatingProcessFileName, " on ", DeviceName)
| extend MitreTechnique = "T1003.001"
| extend Severity = "Critical"
| extend ImpactStatement = "All accounts with active sessions on this host are at risk of credential compromise"
```

**Sentinel Settings:** Frequency `5m` · Lookback `5m` · Threshold `> 0` · Playbook: `PB-ISOLATE-AND-RESET-CREDENTIALS`

> ⚠️ **Policy:** This rule must never have its threshold raised above 0 and must never be suppressed. Any suppression requires written approval from the SOC Manager and customer CISO and is valid for a maximum of 4 hours.

---

## Defender XDR — Advanced Hunting

```kql
// ───────────────────────────────────────────────────────────────
// GEN-CA-001 | LSASS Access — Defender XDR Custom Detection
// Run: Every hour | Category: CredentialAccess | Severity: High
// Entities: Device → DeviceName, User → AccountName
// ───────────────────────────────────────────────────────────────
let ApprovedProcesses = dynamic([
    "MsMpEng.exe","SenseCE.exe","MsSense.exe","csrss.exe",
    "wininit.exe","lsm.exe"
]);
DeviceEvents
| where Timestamp >= ago(1h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (ApprovedProcesses))
| where AdditionalFields has_any ("PROCESS_VM_READ","PROCESS_ALL_ACCESS","0x1010","0x1fffff")
| project
    Timestamp,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## Defender for Endpoint — MDE Queries

**Identify the dump tool and method:**
```kql
// Identify LSASS dump tool commands (run in Defender XDR → Hunting)
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(2h) .. now())
| where ProcessCommandLine has_any (
    "lsass", "procdump", "comsvcs", "MiniDump",
    "sekurlsa", "logonpasswords", "Out-Minidump",
    "lsadump", "dcsync", "wce.exe", "fgdump"
)
| project Timestamp, FileName, ProcessCommandLine, AccountName, SHA256, FolderPath
| order by Timestamp asc
```

**Find the LSASS dump file on disk:**
```kql
// A dump file on disk means credentials are ALREADY captured
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(2h) .. now())
| where FileName endswith ".dmp"
    or (FolderPath has_any ("lsass","Temp","AppData","Desktop") and FileName endswith ".dmp")
| project Timestamp, FileName, FolderPath, SHA256, ActionType, InitiatingProcessFileName
```

**Scope of credential exposure — all accounts on the host:**
```kql
// Every account in this list must have their password reset
DeviceLogonEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (ago(4h) .. now())
| where ActionType == "LogonSuccess"
| distinct AccountName, AccountDomain, LogonType
| extend ResetRequired = "YES — Immediate password reset required"
```

**Check for lateral movement using dumped credentials:**
```kql
// Authentication from this device to other hosts after the dump time
DeviceLogonEvents
| where Timestamp between ("<DUMP_TIME>" .. now())
| where DeviceName == "<DEVICE_NAME>"
| where LogonType == "Network"
| project Timestamp, AccountName, RemoteDeviceName, RemoteIP, ActionType
| order by Timestamp asc
```

**MDE Native Alerts — ensure these are NOT suppressed:**
- `Suspicious access to LSASS service`
- `Credential dumping attempt`
- `Possible credential dumping tool detected (Mimikatz)`
- `LSASS credential theft blocked` (when Credential Guard is active)

**Enable LSA Protection (PPL) via MDE Security Settings:**
- MDE → Configuration management → Endpoint security policies → Account protection
- Enable: `Credential Guard` and `Local Security Authority (LSA) protection`

---

## Defender for Identity — MDI

MDI independently detects LSASS access via its sensor on domain controllers and servers. Look for these MDI alerts in the Defender XDR Incidents queue:

| MDI Alert | Correlation | Action |
|-----------|------------|--------|
| **Suspected credential theft tool (LSASS)** | Direct correlation with GEN-CA-001 | Auto-merge into same incident |
| **Suspected DCSync attack** | Follow-on after LSASS dump | Treat as Critical escalation |
| **Pass-the-Hash** | Use of dumped NTLM hash | See GEN-LM-001 |
| **Pass-the-Ticket** | Use of dumped Kerberos ticket | See GEN-LM-002 |

---

## Investigation Guide

### Step 1 — Immediate Action (0–5 minutes)
**Do not wait to investigate. Isolate the device NOW.**

1. MDE portal → Device inventory → `<DEVICE_NAME>` → **Isolate device**
2. Record: initiating process name, command line, folder path, and SHA256 hash
3. Submit the SHA256 hash to VirusTotal immediately — is it a known tool?
4. Is the process running from `%TEMP%`, `%APPDATA%`, `C:\ProgramData`, or `C:\Users`? → Almost certainly malicious
5. Is the process digitally signed? By whom? (An unsigned process accessing LSASS is extremely high confidence)
6. Notify SOC Manager and open P1 incident ticket

### Step 2 — Identify the Dump Method (5–15 minutes)

Run the "dump tool" query above. Common patterns:

| Command Line Pattern | Tool | Confidence |
|---------------------|------|-----------|
| `procdump -ma lsass.exe` | Sysinternals ProcDump (abused) | High |
| `rundll32 comsvcs.dll MiniDump <PID>` | LOLBin — comsvcs.dll | Critical |
| `sekurlsa::logonpasswords` | Mimikatz | Critical |
| `Task Manager dump of lsass.exe` | Manual dump via Task Manager | High |
| PowerShell `Out-Minidump` | PowerSploit module | Critical |

If a `.dmp` file was created on disk (run the file events query) — credentials are **already captured**. Treat as full credential breach immediately.

### Step 3 — Scope of Credential Exposure (15–30 minutes)

Run the "scope of exposure" query above. For every account returned:

1. **Immediately reset the password** — do not wait for investigation completion
2. For domain admin accounts: treat as Critical escalation — KRBTGT reset may be required
3. For service accounts: rotate service account passwords in all applications using them
4. Notify the customer of the full list of exposed accounts

### Step 4 — Lateral Movement (30–60 minutes)

Run the "lateral movement" query above. For every remote device connection:
- Was NTLM used (Pass-the-Hash)?
- Was Kerberos used (Pass-the-Ticket)?
- Isolate any destination devices where successful authentication occurred

```kql
// Correlate with MDI IdentityLogonEvents for full lateral movement picture
IdentityLogonEvents
| where AccountName in ("<LIST_OF_EXPOSED_ACCOUNTS>")
| where Timestamp >= "<DUMP_TIME>"
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, Protocol, ActionType
| order by Timestamp asc
```

---

## Response Actions

**Immediate (P1 — within 15 minutes)**
- [ ] **Isolate device** — MDE portal
- [ ] **Reset ALL passwords** for every account with an active session on the host
- [ ] **Disable the initiating account** — the account running the dump tool — in Entra ID
- [ ] **Purge Kerberos tickets** on all affected hosts: run `klist purge` via Live Response
- [ ] **Notify customer CISO** — this is a credential breach affecting potentially multiple accounts
- [ ] **Open P1 incident ticket** — tag `CRED-DUMP-LSASS`, `P1`

**Within 1 Hour**
- [ ] Force MFA re-enrolment for all affected accounts
- [ ] Revoke all active sessions for affected accounts across M365 and Entra ID
- [ ] Check for and remove any persistence (scheduled tasks, services, registry run keys) on the host
- [ ] Search for lateral movement from the host — isolate any destination devices
- [ ] If domain admin credentials were exposed: **reset KRBTGT password twice** (first reset now, second reset 24 hours later)

**Recovery**
- [ ] Rebuild the compromised host from a clean image — do not restore from a backup made after the compromise
- [ ] Enable **Credential Guard** on the rebuilt host
- [ ] Enable **LSA Protection (PPL)** on all endpoints via MDE policy
- [ ] Disable WDigest authentication via Group Policy (`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0`)
- [ ] Post-incident review within 5 business days

---

## False Positives

| Scenario | Evidence | Mitigation |
|----------|---------|-----------|
| Windows Defender Antivirus (MsMpEng.exe) | Pre-excluded in the approved list — verify hash matches Microsoft's known-good | Confirm hash via MDE signed binary lookup before re-excluding |
| MDE Sense process (SenseCE.exe / MsSense.exe) | Pre-excluded — verify the hash matches the installed MDE version | Do not re-add if hash doesn't match — may indicate sensor spoofing |
| Authorised penetration test | Pentest scope document, written approval, date/time window | Suppress only during the confirmed pentest window — document with approver name and expiry |
| Azure AD Connect agent | `AzureADConnectAuthenticationAgentService.exe` — pre-excluded | Verify service account and path match expected installation |

---

## Tuning Guidance

- Keep the `ApprovedProcesses` list as short as possible — every addition is a potential blind spot
- Enable **Credential Guard** on all Windows 10/11 and Server 2016+ endpoints — this makes LSASS dumping ineffective for extracting plaintext passwords and Kerberos TGTs
- Enable **LSA Protection (PPL)** — this blocks all non-PPL processes from accessing LSASS memory and will cause MDE to raise `LSASS credential theft blocked` for attempts
- If the environment has PPL enabled, this rule becomes a detection for PPL bypass attempts (even rarer and higher confidence)

---

## References

- [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft: Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Microsoft: LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [MDI: LSASS credential theft alert](https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts#suspected-credential-theft-tool-used-lsass-read-external-id-2065)
