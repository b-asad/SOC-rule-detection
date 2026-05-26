# GEN-CA-001 — OS Credential Dumping: LSASS Memory

| Field | Value |
|-------|-------|
| Rule ID | GEN-CA-001 |
| Tactic | Credential Access |
| Technique | T1003.001 — LSASS Memory |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceEvents` (MDE) — ActionType: OpenProcessApiCall |

## Description
A process opens LSASS with VM_READ or FULL_ACCESS rights, allowing extraction of NTLM hashes, Kerberos tickets, and plaintext credentials. Used by Mimikatz, ProcDump, comsvcs.dll, and Task Manager dump. Any confirmed LSASS access from a non-approved process is a P1 incident.

---

## Microsoft Sentinel KQL
```kql
// GEN-CA-001 | Frequency: 5m | Lookback: 5m
let Approved = dynamic(["MsMpEng.exe","SenseCE.exe","csrss.exe","wininit.exe","lsm.exe","AzureADConnectAuthenticationAgentService.exe"]);
DeviceEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (Approved))
| where AdditionalFields has_any ("PROCESS_VM_READ","PROCESS_ALL_ACCESS","0x1010","0x1fffff","0x1038")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessFolderPath, AdditionalFields
```
**Sentinel Settings:** Frequency `5m` · Lookback `5m` · Threshold `> 0` · Playbook: `PB-ISOLATE-AND-RESET-CREDS`

---

## Defender XDR — Advanced Hunting
```kql
// GEN-CA-001 | Run: Every hour
let Approved = dynamic(["MsMpEng.exe","SenseCE.exe","csrss.exe","wininit.exe","lsm.exe"]);
DeviceEvents
| where Timestamp >= ago(1h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (Approved))
| where AdditionalFields has_any ("PROCESS_VM_READ","PROCESS_ALL_ACCESS")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

---

## Defender for Endpoint — MDE Alert Tuning
MDE natively alerts on LSASS access. Ensure these native alert categories are **not suppressed**:
- `Suspicious access to LSASS service`
- `Credential dumping attempt`
- `Possible credential dumping tool detected`

For MDE Live Response investigation:
```kql
// Run on device — full process chain
DeviceProcessEvents
| where DeviceId == "<DEVICE_ID>" | where Timestamp >= ago(2h)
| project Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName, FolderPath
| order by Timestamp asc
```

---

## Defender for Identity — MDI Alerts
Defender for Identity independently detects:
- **Suspected credential theft tool (LSASS)** — maps to this rule
- **Suspected DCSync attack** — correlate with GEN-CA-003

Ensure MDI is deployed on all Domain Controllers and the MDI sensor is active. MDI alerts appear in the Defender XDR Incidents queue alongside MDE alerts.

---

## Investigation Guide

**Step 1 — Immediate Triage (< 5 min)**  
Do not delay isolation. This is always P1.
1. What process accessed LSASS? Is it a known tool name (`procdump`, `mimikatz`, `malsvc`)?
2. Is the process running from `%TEMP%`, `%APPDATA%`, `C:\ProgramData`?
3. Is it signed? What is the vendor?
4. Initiate device isolation via MDE in parallel.

**Step 2 — Confirm Dump Method (5–15 min)**
```kql
// Common LSASS dump command patterns
DeviceProcessEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(2h)
| where ProcessCommandLine has_any ("lsass","procdump","comsvcs","MiniDump","sekurlsa","logonpasswords","Out-Minidump")
| project Timestamp, FileName, ProcessCommandLine, AccountName, SHA256
```

**Step 3 — Dump File Written to Disk (15–25 min)**
```kql
DeviceFileEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(2h)
| where FileName endswith ".dmp" or FolderPath has_any ("lsass","Temp","AppData")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, SHA256
```
If `.dmp` file found → credentials already captured. Assume full credential compromise.

**Step 4 — Scope of Exposed Accounts (25–40 min)**
```kql
DeviceLogonEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(4h)
| where ActionType == "LogonSuccess"
| distinct AccountName, AccountDomain, LogonType
```
Every account in this list must have its password reset immediately.

**Step 5 — Post-Dump Lateral Movement (40–60 min)**
```kql
IdentityLogonEvents
| where Timestamp >= ago(2h)
| where DeviceName == "<DEVICE>" or DestinationDeviceName == "<DEVICE>"
| project Timestamp, AccountName, ActionType, DeviceName, DestinationDeviceName, Protocol
```

---

## Response Actions
- [ ] **Isolate device** — MDE
- [ ] **Reset ALL account passwords** with sessions on the host
- [ ] **Disable the initiating account** in Entra ID
- [ ] **Purge Kerberos tickets** on all affected hosts: `klist purge`
- [ ] **Check for persistence** — scheduled tasks, services, registry run keys
- [ ] **If domain admin exposed:** reset KRBTGT password twice (72h apart)
- [ ] **Enable Credential Guard** and LSA Protection on rebuild
- [ ] **Open P1 incident** — tag `CRED-DUMP-LSASS`

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Windows Defender / MDE Sense accessing LSASS | Pre-approved in exclusion list — verify hash vs Microsoft known-good |
| Authorised pentest | Suppress only during confirmed pentest window with written approval |

## References
- [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft: Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
