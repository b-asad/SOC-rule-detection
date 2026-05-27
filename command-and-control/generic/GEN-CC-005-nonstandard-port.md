# GEN-CC-005 — C2: Communication on Non-Standard Port

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CC-005` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | T1571 — Non-Standard Port |
| **Sector** | Generic — All Customers |
| **Severity** | **Medium** |
| **Priority** | **P2** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceNetworkEvents` (MDE) · `CommonSecurityLog` (Firewall) |
| **Created** | May 2026 |

---

## Description

Outbound connection from a workstation to an external IP on an unusual port — not 80, 443, or other standard application ports. Attackers use non-standard ports to evade firewall rules and blend into less-scrutinised traffic. Common C2 ports: 4444 (Metasploit default), 8888, 1234, 31337, 4545, 6666, 7777.

---

## Microsoft Sentinel KQL

```kql
// GEN-CC-005 | Frequency: 15m | Lookback: 1h
let StandardPorts = dynamic([80,443,8080,8443,53,25,587,465,110,995,143,993,21,22,23,3389,445,3306,5432,1433,27017]);
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where DeviceAction !in ("deny","block","drop")
| where DestinationPort !in (StandardPorts)
| where DestinationIP !startswith "10." and DestinationIP !startswith "192.168."
    and DestinationIP !startswith "172."
| where DestinationPort between (1024 .. 65535)  // Ephemeral / non-well-known
| summarize ConnCount=count(), DistinctPorts=dcount(DestinationPort)
    by SourceIP, DestinationIP, DeviceName
| where ConnCount > 5
// Flag known malicious default ports
| extend KnownBadPort = iff(DestinationPort in (dynamic([4444,4445,31337,8888,9001,9030,6666,7777,1234])), true, false)
| extend AlertTitle = strcat("Non-Standard Port C2: ", SourceIP, " → ", DestinationIP)
| order by KnownBadPort desc, ConnCount desc
```

---

## Response Actions
- [ ] Submit destination IP to VirusTotal and Shodan
- [ ] Block destination IP if confirmed malicious
- [ ] Identify the process making the connection (MDE DeviceNetworkEvents)

## References - [MITRE T1571](https://attack.mitre.org/techniques/T1571/)
