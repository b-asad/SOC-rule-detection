# RG-CA-001 — POS Credential Theft: LSASS Access on Payment Host

| Field | Value |
|-------|-------|
| Rule ID | RG-CA-001 |
| Tactic | Credential Access |
| Technique | T1003.001 — LSASS Memory |
| Sector | **Retail General** |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DeviceEvents` (MDE) |
| Retail Context | POS terminals, payment processing hosts, CDE servers |

## Description
LSASS memory access on a host tagged as POS or payment infrastructure. POS systems are a primary retail attack target — credential theft enables lateral movement into the payment network and may expose card track data. This is a **PCI DSS breach event** requiring mandatory card brand notification within 24 hours if confirmed.

---

## Microsoft Sentinel KQL
```kql
// RG-CA-001 | Frequency: 5m | Lookback: 5m
// Prereq: Populate 'POS-Hosts' watchlist with POS device names / IDs
let POSHosts = (_GetWatchlist('POS-Hosts') | project SearchKey);
let Approved = dynamic(["MsMpEng.exe","SenseCE.exe","csrss.exe","wininit.exe"]);
DeviceEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (Approved))
| where DeviceName in~ (POSHosts)
    or DeviceName has_any ("pos","till","register","payment","checkout","kiosk","eftpos")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| extend PCIAlert = "Mandatory card brand notification within 24h if confirmed"
```

---

## Investigation Guide

**Step 1 — PCI DSS Triage (< 5 min)**  
Identify: store location, terminal number, was it processing payments at time of event?  
Notify: customer PCI Security Manager and SOC Manager simultaneously.  
Do NOT reboot — memory forensics may be required.

**Step 2 — POS Malware Indicators (5–20 min)**
```kql
DeviceProcessEvents | where DeviceName == "<POS_DEVICE>" | where Timestamp >= ago(24h)
| where ProcessCommandLine has_any ("track","card","swipe","magnetic","backoff","alina","dexter","vskimmer")
| project Timestamp, FileName, ProcessCommandLine, SHA256
```

**Step 3 — Card Brand Notification Decision**  
Was the terminal P2PE-enabled? → Card data encrypted at entry → lower risk.  
No P2PE + LSASS dump confirmed → mandatory notification to Visa/Mastercard.

---

## Response Actions
- [ ] Remove terminal from production immediately
- [ ] Notify customer Payment Security Manager by phone
- [ ] Notify acquiring bank if breach confirmed
- [ ] Engage PCI Forensic Investigator (PFI) if required
- [ ] Notify Visa / Mastercard within 24h of confirmed breach
- [ ] Assess GDPR cardholder notification obligations

## References
- [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [PCI DSS v4.0 Requirement 12.10](https://www.pcisecuritystandards.org)
