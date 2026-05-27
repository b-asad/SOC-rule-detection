# GEN-LM-004 — Lateral Movement: WinRM / PowerShell Remoting

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-LM-004` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | T1021.006 — Windows Remote Management |
| **Sector** | Generic — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceLogonEvents` (MDE) · Windows Event 4624 (LogonType 3) |
| **Created** | May 2026 |

---

## Description

PowerShell Remoting / WinRM connections (ports 5985, 5986) from a workstation or non-management host to another internal host — used by attackers for fileless lateral movement without dropping binaries. More stealthy than RDP as it leaves fewer artifacts. Commonly used with Impacket's evil-winrm and native PowerShell `Enter-PSSession` / `Invoke-Command`.

---

## Microsoft Sentinel KQL

```kql
// GEN-LM-004 | Frequency: 15m | Lookback: 15m
let BaselineWinRM = (
    DeviceLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where LogonType == "Network" and RemotePort in (5985, 5986)
    | distinct AccountName, DeviceName, RemoteDeviceName
);
DeviceLogonEvents
| where TimeGenerated >= ago(15m)
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
// WinRM connections from connecting device
| join kind=inner (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(15m)
    | where RemotePort in (5985, 5986)
    | where ActionType == "ConnectionSuccess"
    | project DeviceName, RemoteDeviceName = RemoteIP, WinRMPort = RemotePort, Timestamp
) on DeviceName
| join kind=leftanti BaselineWinRM on AccountName, DeviceName, RemoteDeviceName
| project TimeGenerated, AccountName, DeviceName, RemoteDeviceName, LogonType
| extend AlertTitle = strcat("WinRM Lateral Movement: ", DeviceName, " → ", RemoteDeviceName)
```

---

## Response Actions
- [ ] Isolate both devices
- [ ] Check for commands executed via the WinRM session
- [ ] Restrict WinRM to management hosts only via GPO

## References - [MITRE T1021.006](https://attack.mitre.org/techniques/T1021/006/)
