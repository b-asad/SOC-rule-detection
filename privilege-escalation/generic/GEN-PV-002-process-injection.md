# GEN-PV-002 — Privilege Escalation / Defense Evasion: Process Injection

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-PV-002` |
| **MITRE Tactic** | Privilege Escalation / Defense Evasion |
| **MITRE Technique** | T1055 — Process Injection |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceEvents` (MDE) — ActionType: CreateRemoteThread, ProcessInjection |
| **Created** | May 2026 |

---

## Description

A process creates a remote thread in another process — the primary mechanism for process injection (T1055). Used by Cobalt Strike, Metasploit, and custom implants to inject shellcode into legitimate processes (svchost.exe, explorer.exe, lsass.exe) to evade detection and inherit the target process's privileges and security context.

MDE captures `CreateRemoteThread` events. Injecting into `lsass.exe` also constitutes a credential access attempt (GEN-CA-001 correlation).

---

## Microsoft Sentinel KQL

```kql
// GEN-PV-002 | Frequency: 5m | Lookback: 5m
let SuspiciousSources = dynamic([
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe",
    "regsvr32.exe","rundll32.exe","msiexec.exe","notepad.exe","calc.exe"
]);
let HighValueTargets = dynamic([
    "lsass.exe","svchost.exe","explorer.exe","winlogon.exe","csrss.exe",
    "taskhost.exe","taskhostw.exe","dllhost.exe","mmc.exe","searchindexer.exe"
]);
DeviceEvents
| where TimeGenerated >= ago(5m)
| where ActionType in ("CreateRemoteThread","WriteProcessMemory","ProcessInjection")
| where InitiatingProcessFileName in~ (SuspiciousSources)
| where FileName in~ (HighValueTargets)
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256,
    FileName, AdditionalFields
| extend AlertTitle = strcat("Process Injection: ", InitiatingProcessFileName, " → ", FileName)
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-PV-002 | Run: Every hour
DeviceEvents
| where Timestamp >= ago(1h)
| where ActionType == "CreateRemoteThread"
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe","SenseCE.exe","AzureADConnectAuthenticationAgentService.exe",
    "svchost.exe","services.exe","wininit.exe"
)
| where FileName in~ ("lsass.exe","svchost.exe","explorer.exe","winlogon.exe","csrss.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName,
    InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1 — Confirm injection (0–10 min)**
Is the source process expected to create remote threads? A non-system utility injecting into `svchost.exe` = high confidence malicious.
Submit source process hash to VirusTotal — is it a known Cobalt Strike beacon or RAT?

**Step 2 — Target process (10–20 min)**
If injecting into `lsass.exe`: run GEN-CA-001 (LSASS) investigation — credential theft is the goal.
If injecting into `svchost.exe` or `explorer.exe`: attacker is hiding inside a trusted process.

**Step 3 — Memory forensics**
Collect memory dump via MDE Live Response before isolating — the injected shellcode only exists in memory.

---

## Response Actions
- [ ] Isolate device — MDE
- [ ] Collect memory dump before reboot (forensic evidence)
- [ ] If lsass.exe targeted: run GEN-CA-001 procedure — reset all exposed account passwords
- [ ] Submit source process hash to VirusTotal

## References - [MITRE T1055](https://attack.mitre.org/techniques/T1055/)
