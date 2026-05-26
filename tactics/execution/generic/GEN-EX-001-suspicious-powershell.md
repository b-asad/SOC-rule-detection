# GEN-EX-001 — Execution: Suspicious PowerShell with Encoded/Download Cradle

| Field | Value |
|-------|-------|
| Rule ID | GEN-EX-001 |
| Tactic | Execution |
| Technique | T1059.001 — PowerShell |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceProcessEvents` (MDE) |

## Description
PowerShell launched with encoded commands, download cradles (IEX/DownloadString), or execution policy bypass flags. Consistently one of the most common execution vectors across ransomware, APT, and commodity malware campaigns.

---

## Microsoft Sentinel KQL
```kql
// GEN-EX-001 | Frequency: 5m | Lookback: 5m
DeviceProcessEvents
| where TimeGenerated >= ago(5m)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-EncodedCommand","-enc ","-e ","IEX","Invoke-Expression","DownloadString","DownloadFile","WebClient","Net.WebClient","-ExecutionPolicy Bypass","-ep bypass","hidden","WindowStyle Hidden","FromBase64String","[Convert]::")
| where not(InitiatingProcessFileName in~ ("devenv.exe","msbuild.exe","AzureAD.exe"))
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, FolderPath
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-EX-001 | Run: Every hour
DeviceProcessEvents
| where Timestamp >= ago(1h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-EncodedCommand","-enc ","IEX","Invoke-Expression","DownloadString","WebClient","FromBase64String","-ExecutionPolicy Bypass","WindowStyle Hidden")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

---

## Defender for Endpoint — Script Content Inspection
MDE captures PowerShell script block logging content in `DeviceEvents`:
```kql
DeviceEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(2h)
| where ActionType == "PowerShellCommand"
| project Timestamp, AdditionalFields, InitiatingProcessFileName
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1 — Decode the Command (< 10 min)**
If `-EncodedCommand` is present, decode the base64:
```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<BASE64_HERE>"))
```
Or use CyberChef: From Base64 → Decode text (UTF-16LE).

**Step 2 — Identify Payload Source**
Is there a URL in the decoded command? Submit to VirusTotal. Block the domain.

**Step 3 — Child Process and Network Connections**
```kql
DeviceProcessEvents | where InitiatingProcessFileName =~ "powershell.exe" | where DeviceName == "<DEVICE>"
| where Timestamp >= ago(30m) | project Timestamp, FileName, ProcessCommandLine | order by Timestamp asc
```
```kql
DeviceNetworkEvents | where InitiatingProcessFileName =~ "powershell.exe" | where DeviceName == "<DEVICE>"
| where Timestamp >= ago(30m) | project Timestamp, RemoteIP, RemoteUrl, RemotePort
```

---

## Response Actions
- [ ] Kill the PowerShell process via MDE Live Response
- [ ] Block identified download URL and C2 IP
- [ ] Quarantine any dropped binaries (SHA256 block in MDE custom indicators)
- [ ] Review for persistence established during the session

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| IT automation / RMM scripts (Intune, Endpoint Manager) | Allowlist by signed process hash and parent process |
| Azure Arc / management agents | Exclude by process folder path (signed paths only) |

## References
- [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)
