# SEC-RET-EF-001 — Retail: Payment Card Data Exfiltration

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-RET-EF-001` |
| **MITRE Technique** | T1041 — Exfiltration Over C2 Channel |
| **Sector** | Retail |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `CommonSecurityLog` (Firewall/Proxy) · `DeviceNetworkEvents` (MDE) |

## Description
Outbound data transfer from a POS terminal or payment processing host to an unknown external IP/domain — likely exfiltration of captured card track data. POS malware (RAM scrapers) collect track data from memory and exfiltrate in batches. Immediate PCI DSS breach notification obligations apply.

## Microsoft Sentinel KQL
```kql
// SEC-RET-EF-001 | Frequency: 5m | Lookback: 15m
let POSHosts = (_GetWatchlist('POS-Hosts') | project SearchKey);
CommonSecurityLog
| where TimeGenerated >= ago(15m)
| where DeviceAction !in ("deny","block","drop")
| where SourceIP has_any (POSHosts)
    or DeviceName has_any ("pos","till","register","checkout","kiosk","eftpos")
| where DestinationIP !startswith "10." and DestinationIP !startswith "192.168."
| where DestinationHostName !has_any ("microsoft.com","windowsupdate.com","verifone.com","ingenico.com","visa.com","mastercard.com")
| project TimeGenerated, SourceIP, DestinationIP, DestinationHostName, SentBytes, DeviceName
| extend AlertTitle = strcat("POS Data Exfiltration to ", DestinationHostName)
| extend PCIObligation = "MANDATORY: Notify acquiring bank and Visa/Mastercard within 24h of confirmed CHD breach"
```

## Response Actions
- [ ] Block destination IP/domain at firewall
- [ ] Remove POS terminal from production immediately
- [ ] Notify PCI Security Manager and acquiring bank (24h window)
- [ ] Engage PCI Forensic Investigator (PFI) if card brands require

## References - [MITRE T1041](https://attack.mitre.org/techniques/T1041/)
