# SEC-RET-CA-001 — Retail: POS System Credential Theft / LSASS Access

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-RET-CA-001` |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1003.001 — LSASS Memory |
| **Sector** | **Retail** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceEvents` (MDE) |
| **Sector Context** | POS terminals, payment processing servers, CDE hosts, self-checkout kiosks |
| **Created** | May 2026 |

---

## Description

Detects LSASS memory access on hosts identified as Point-of-Sale terminals or payment infrastructure. POS environments are a primary target in retail due to the payment card data processed. Successful credential theft from a POS host enables lateral movement within the payment network and may expose card track data in memory.

This is a **PCI DSS breach event** — mandatory notification to acquiring bank and card brands (Visa, Mastercard) within 24 hours if cardholder data exposure is confirmed.

---

## Microsoft Sentinel KQL

```kql
// SEC-RET-CA-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
let POSHosts = (_GetWatchlist('POS-Hosts') | project SearchKey);
let Approved = dynamic(["MsMpEng.exe","SenseCE.exe","csrss.exe","wininit.exe"]);
DeviceEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (Approved))
| where DeviceName in~ (POSHosts)
    or DeviceName has_any ("pos","till","register","payment","checkout","kiosk","eftpos","pinpad")
| project
    TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessFolderPath, InitiatingProcessSHA256
| extend AlertTitle = strcat("POS LSASS Access — PCI DSS Breach Event: ", DeviceName)
| extend PCIRequirement = "PCI DSS 12.10.5: Notify acquiring bank and card brands within 24h if CHD exposed"
| extend ImmediateAction = "Remove terminal from production. Do not reboot. Notify PCI Security Manager."
```

---

## Investigation Guide

**Step 1 — PCI DSS Triage (< 5 min)**
1. Identify store location and terminal number from the device name/asset register
2. Was this terminal actively processing card payments at the time of the alert?
3. Is this terminal P2PE-encrypted at the hardware level? (If yes, card data is protected even if memory is dumped)
4. Notify customer PCI Security Manager and acquiring bank contact simultaneously with investigation

**Step 2 — POS Malware Indicators (5–20 min)**
```kql
DeviceProcessEvents
| where DeviceName == "<POS_DEVICE>"
| where Timestamp >= ago(24h)
| where ProcessCommandLine has_any ("track","card","swipe","magnetic","backoff","alina","dexter","vskimmer","GratefulPOS","PoSeidon")
| project Timestamp, FileName, ProcessCommandLine, SHA256
```

**Step 3 — Network Reach to Payment Infrastructure (20–40 min)**
```kql
DeviceNetworkEvents
| where DeviceName == "<POS_DEVICE>"
| where Timestamp >= ago(24h)
| where RemotePort in (1433, 3306, 443, 8443)
| where not(RemoteIP has_any ("10.10.","192.168.1."))  // Exclude expected local payment VLAN
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```

---

## Response Actions
**Immediate**
- [ ] Remove terminal from production — stop all card processing on this terminal
- [ ] Do NOT reboot — preserve volatile memory for forensics
- [ ] Notify customer PCI Security Manager by phone
- [ ] Notify acquiring bank

**PCI DSS Required**
- [ ] Notify Visa/Mastercard within 24h of confirmed CHD exposure
- [ ] Engage PCI Forensic Investigator (PFI) if required by card brands
- [ ] Assess cardholder notification requirements under UK GDPR

## References
- [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org)
- [Visa CDRP](https://usa.visa.com/support/small-business/security-compliance.html)
