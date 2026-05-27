# Microsoft Defender for Endpoint — Configuration Guide

## Required Advanced Features

MDE portal → Settings → Endpoints → Advanced features — enable all:
- [x] Endpoint detection and response
- [x] Automated Investigation and Remediation
- [x] Live Response for servers
- [x] Live Response unsigned script execution (for investigation scripts)
- [x] Custom network indicators
- [x] **Tamper protection** ← critical for GEN-DE-001
- [x] **Controlled folder access** ← critical for GEN-IM-002
- [x] Block at first sight
- [x] Network protection (Block mode)

---

## Attack Surface Reduction Rules — Deploy Before Analytics Rules

Enable in **Audit** mode for 14 days, then switch to **Block** mode:

| ASR Rule | GUID | Protects Against |
|---------|------|----------------|
| Block Office apps from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | GEN-IA-001 |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | GEN-EX-001 |
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` | GEN-CA-001 |
| Block process creations from PSExec and WMI | `d1e49aac-8f56-4280-b9ba-993a6d77406c` | GEN-EX-002 |
| Block untrusted/unsigned processes from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | All execution rules |
| Block Office communication apps from creating child processes | `26190899-1602-49e8-8b27-eb1d0a1ce869` | GEN-IA-001 |

---

## Device Tagging — Required for Sector Rules

Tag devices in MDE Device inventory to enable sector-specific rule watchlists:

| Tag | Sector Rule | Devices to Tag |
|-----|-------------|---------------|
| `POS` | SEC-RET-CA-001, SEC-RET-EF-001 | All POS terminals |
| `ClinicalHost` | SEC-HC-IM-001, SEC-HC-LM-001 | EPR, PACS, pharmacy, ward terminals |
| `OTEngineering` | SEC-MFG-CA-001 | OT engineering workstations |
| `TradingHost` | SEC-FS-LM-001 | Trading platform servers |
| `EnergySystem` | SEC-ENRG-CA-001, SEC-ENRG-IM-001 | EMS, SCADA, historian hosts |
| `RestrictedGov` | SEC-GOV-LM-001 | Restricted/classified government systems |
| `LegalDMS` | SEC-LEG-CA-001, SEC-LEG-IM-001 | DMS, matter management servers |

Apply tags: MDE portal → Device inventory → Select device → Manage tags

---

## Live Response Investigation Script Library

Upload these scripts to MDE Live Response library for analyst use:

```powershell
# collect-process-list.ps1
Get-Process | Select-Object Name, Id, Path, Company, CPU | ConvertTo-Json

# check-persistence.ps1
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | ConvertTo-Json
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | ConvertTo-Json
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath | ConvertTo-Json

# check-network.ps1
Get-NetTCPConnection -State Established | 
    Where-Object {$_.RemoteAddress -notmatch "^(10\.|192\.168\.|127\.|::1)"} |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    ConvertTo-Json
```
