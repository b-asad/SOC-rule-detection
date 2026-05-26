# GEN-CC-002 — C2 over DNS: DNS Tunnelling / DGA

| Field | Value |
|-------|-------|
| Rule ID | GEN-CC-002 |
| Tactic | Command and Control |
| Technique | T1071.004 · T1568.002 — DNS / DGA |
| Severity | **High** | Priority | **P1** |
| MS Tools | Sentinel · Defender XDR · Defender for Endpoint |
| Log Source | `DnsEvents`, `AzureDiagnostics` (DNS), `DeviceNetworkEvents` |

## Description
Two variants: (1) DNS tunnelling — high-entropy or abnormally long subdomain queries used to exfiltrate data or receive C2 commands; (2) DGA — algorithmically generated domain names queried by malware to locate C2 infrastructure.

---

## Microsoft Sentinel KQL — DNS Tunnelling
```kql
// GEN-CC-002a | Frequency: 15m | Lookback: 1h
DnsEvents
| where TimeGenerated >= ago(1h)
| where SubType == "LookupQuery"
| extend SubLen = strlen(tostring(split(Name,".",[0])))
| extend Entropy = log2(toreal(countof(Name,"a")+countof(Name,"b")+countof(Name,"c")+countof(Name,"d")+countof(Name,"e")))  // Simplified; use threat intel enrichment for full entropy
| where SubLen > 50 or Name has_any ("*TXT*","*NULL*")
| summarize QueryCount=count(), UniqueDomains=dcount(Name), SampleDomains=make_set(Name,5) by ClientIP, Computer
| where QueryCount > 100 or UniqueDomains > 20
```

---

## Microsoft Sentinel KQL — DGA Detection
```kql
// GEN-CC-002b | Frequency: 15m | Lookback: 1h
// Requires MDTI or ThreatIntelligenceIndicator table with DGA IOCs
DnsEvents
| where TimeGenerated >= ago(1h)
| join kind=inner (ThreatIntelligenceIndicator | where Active==true and IndicatorType=="DomainName") on $left.Name==$right.DomainName
| project TimeGenerated, ClientIP, Name, Description, ThreatType, ExpirationDateTime
```

---

## Defender XDR — Advanced Hunting
```kql
// GEN-CC-002 | Run: Every hour
DeviceNetworkEvents
| where Timestamp >= ago(1h) and ActionType == "DnsQueryResponse"
| extend QueryLen = strlen(RemoteUrl)
| where QueryLen > 50 or RemoteUrl has "xn--"
| summarize Count=count(), Domains=make_set(RemoteUrl,5) by DeviceName, InitiatingProcessFileName
| where Count > 50
| order by Count desc
```

---

## Defender for Endpoint — DNS Query Investigation
```kql
DeviceNetworkEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(2h)
| where ActionType == "DnsQueryResponse"
| project Timestamp, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1:** Review the queried domains — do they appear random/high-entropy? Long subdomain?  
**Step 2:** Identify the process making DNS queries — is it unexpected for this host type?  
**Step 3:** Calculate total data volume encoded in DNS queries (average 63 bytes per label × query count).  
**Step 4:** Block the parent domain at the firewall and in Sentinel TI watchlist.

---

## Response Actions
- [ ] Block identified C2 domain/parent domain — firewall + DNS sinkhole
- [ ] Isolate host if confirmed tunnelling
- [ ] Collect full DNS query log for host for forensic analysis
- [ ] Search same domain across all customer environments

## References
- [MITRE T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE T1568.002](https://attack.mitre.org/techniques/T1568/002/)
