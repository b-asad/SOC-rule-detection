# GEN-PV-003 — Privilege Escalation: Access Token Manipulation

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-PV-003` |
| **MITRE Tactic** | Privilege Escalation / Defense Evasion |
| **MITRE Technique** | T1134 — Access Token Manipulation |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceEvents` (MDE) · Windows Security Event 4624 (LogonType 9) |
| **Created** | May 2026 |

---

## Description

Process spawned with a different security token (RunAs, CreateProcessWithToken, ImpersonateLoggedOnUser) from a suspicious parent — indicates token impersonation or theft. Cobalt Strike's `make_token` and `steal_token` commands, Incognito, and custom tools use this to operate under another user's identity without their credentials.

Logon Type 9 (NewCredentials) in Windows Security events indicates a process has acquired a new token — commonly used by pass-the-hash variants and token manipulation tools.

---

## Microsoft Sentinel KQL

```kql
// GEN-PV-003 | Frequency: 5m | Lookback: 5m
// Detection A: Logon Type 9 (NewCredentials) from unexpected source
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID == 4624
| where LogonType == 9  // NewCredentials — token manipulation
| where ProcessName has_any ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","rundll32.exe")
    or CallerProcessName has_any ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","rundll32.exe")
| where SubjectUserName !in~ ("SYSTEM","NETWORK SERVICE","LOCAL SERVICE")
| project TimeGenerated, Computer, SubjectUserName, TargetUserName, LogonType,
    ProcessName, CallerProcessName, IpAddress
| extend AlertTitle = strcat("Token Manipulation: ", SubjectUserName, " → ", TargetUserName)
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-PV-003 | Run: Every hour
DeviceLogonEvents
| where Timestamp >= ago(1h)
| where LogonType == "NewCredentials"  // Type 9
| where InitiatingProcessFileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","mshta.exe","rundll32.exe","regsvr32.exe"
)
| project Timestamp, DeviceName, AccountName, LogonType, InitiatingProcessFileName,
    InitiatingProcessCommandLine, RemoteIP
| order by Timestamp desc
```

---

## Investigation Guide

**Step 1:** Who was impersonated? Is it a more privileged account (Domain Admin)?
**Step 2:** What process performed the impersonation? Is it a known tool?
**Step 3:** What did the process do AFTER gaining the new token?
**Step 4:** Correlate with GEN-CA-001 — was LSASS dumped to obtain tokens?

---

## Response Actions
- [ ] Isolate device
- [ ] Reset the password of the impersonated account
- [ ] Check what was accessed with the elevated token

## References - [MITRE T1134](https://attack.mitre.org/techniques/T1134/)
