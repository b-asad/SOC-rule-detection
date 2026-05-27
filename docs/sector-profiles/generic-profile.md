# Sector Profile — Generic (All Customers)

## Overview

The Generic rule set forms the baseline deployed to **every customer** regardless of sector. It covers the core MITRE ATT&CK techniques used across all threat actor categories — from commodity ransomware to nation-state APTs. Sector-specific rules are deployed on top of this baseline, not instead of it.

## Generic Rule Set Coverage

| Tactic | Rule | Technique |
|--------|------|-----------|
| Initial Access | GEN-IA-001 — Office Macro Child Process | T1566.001 |
| Initial Access | GEN-IA-002 — Impossible Travel | T1078 |
| Initial Access | GEN-IA-003 — Tor/Anonymiser Access | T1133 |
| Execution | GEN-EX-001 — Suspicious PowerShell | T1059.001 |
| Execution | GEN-EX-002 — WMI Child Process | T1047 |
| Persistence | GEN-PE-001 — Registry Run Key | T1547.001 |
| Persistence | GEN-PE-002 — New Local Admin Account | T1136.001 |
| Privilege Escalation | GEN-PV-001 — UAC Bypass | T1548.002 |
| Defense Evasion | GEN-DE-001 — Defender Disabled | T1562.001 |
| Defense Evasion | GEN-DE-002 — Event Log Cleared | T1070.001 |
| Credential Access | GEN-CA-001 — LSASS Memory Dump | T1003.001 |
| Credential Access | GEN-CA-002 — Password Spray | T1110.003 |
| Credential Access | GEN-CA-003 — Kerberoasting | T1558.003 |
| Discovery | GEN-DI-001 — Internal Network Scan | T1046 |
| Lateral Movement | GEN-LM-001 — Pass-the-Hash | T1550.002 |
| Lateral Movement | GEN-LM-002 — RDP Lateral Movement | T1021.001 |
| Collection | GEN-CO-001 — Email Forwarding Rule | T1114.003 |
| Exfiltration | GEN-EF-001 — Abnormal Outbound Volume | T1048 |
| C2 | GEN-CC-001 — C2 Beaconing | T1071.001 |
| C2 | GEN-CC-002 — DNS Tunnelling / DGA | T1071.004 |
| Impact | GEN-IM-001 — Shadow Copy Deletion | T1490 |
| Impact | GEN-IM-002 — Mass File Encryption | T1486 |

## Zero Tolerance Rules

These generic rules must **never be suppressed** and their thresholds must **never be raised**:

| Rule | Why Zero Tolerance |
|------|-------------------|
| GEN-IM-001 | Ransomware precursor — every second counts |
| GEN-DE-001 | AV disabled before malware deployment |
| GEN-CA-001 | Credential breach — full domain at risk |
| GEN-DE-002 | Evidence destruction — active compromise underway |

## Deployment Requirements

**Log sources required for full generic rule coverage:**

| Log Source | Sentinel Table | Validates With |
|-----------|--------------|----------------|
| MDE Device Process Events | `DeviceProcessEvents` | `DeviceProcessEvents \| take 1` |
| MDE Device File Events | `DeviceFileEvents` | `DeviceFileEvents \| take 1` |
| MDE Device Network Events | `DeviceNetworkEvents` | `DeviceNetworkEvents \| take 1` |
| MDE Device Registry Events | `DeviceRegistryEvents` | `DeviceRegistryEvents \| take 1` |
| MDE Device Events (LSASS) | `DeviceEvents` | `DeviceEvents \| take 1` |
| Entra ID Sign-in Logs | `SigninLogs` | `SigninLogs \| take 1` |
| MDI Identity Logon Events | `IdentityLogonEvents` | `IdentityLogonEvents \| take 1` |
| DNS Events | `DnsEvents` | `DnsEvents \| take 1` |
| Firewall/Proxy Logs | `CommonSecurityLog` | `CommonSecurityLog \| take 1` |
| M365 UAL | `OfficeActivity` | `OfficeActivity \| take 1` |
| Windows Security Events | `SecurityEvent` | `SecurityEvent \| take 1` |
