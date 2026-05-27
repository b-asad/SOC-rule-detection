# GEN-RC-001 — Reconnaissance: Active Scanning of External Infrastructure

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-RC-001` |
| **MITRE Tactic** | Reconnaissance |
| **MITRE Technique** | T1595 — Active Scanning |
| **Sector** | Generic — All Customers |
| **Severity** | **Medium** |
| **Priority** | **P2** |
| **MS Tools** | Sentinel |
| **Log Source** | `AzureDiagnostics` (WAF) · `CommonSecurityLog` (Firewall/IPS) |
| **Created** | May 2026 |

---

## Description

Detects systematic scanning of external-facing infrastructure — sequential port scans, vulnerability scanner signatures (Nmap, Masscan, Shodan crawlers, Nuclei), and automated CVE probing against web applications. While individual scans are common background noise, sustained scanning from a single source targeting a specific organisation often precedes an exploitation attempt within hours or days.

This rule provides early warning for operationalising a threat response before an exploit lands.

---

## Microsoft Sentinel KQL

```kql
// GEN-RC-001 | Frequency: 15m | Lookback: 1h
// Detection A: WAF detecting scanner fingerprints against customer's perimeter
AzureDiagnostics
| where TimeGenerated >= ago(1h)
| where Category in ("ApplicationGatewayFirewallLog","ApplicationGatewayAccessLog","FrontdoorWebApplicationFirewallLog")
| where action_s in ("Blocked","Detected")
| where details_message_s has_any (
    "nmap","masscan","shodan","nuclei","nikto","sqlmap","dirb","gobuster",
    "zgrab","zmap","metasploit","hydra","burp suite","nessus","openvas",
    "scanner","vulnerability scanner","wpscan"
)
    or ruleSetType_s has_any ("Microsoft_BotManagerRuleSet","Microsoft_DefaultRuleSet")
| summarize ScanCount=count(), TargetPaths=make_set(requestUri_s,10), 
    Rules=make_set(ruleId_s,10)
    by clientIp_s, hostname_s, bin(TimeGenerated, 15m)
| where ScanCount > 20
| extend AlertTitle = strcat("Active Scanning: ", ScanCount, " probes from ", clientIp_s)
```

```kql
// Detection B: Firewall/IPS detecting port scan signatures
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where Activity has_any ("portscan","port scan","Port Scan","TCP SYN","SYN Flood","Nmap","Scanner")
    or DeviceEventClassID has_any ("portscan","probe")
| summarize ScanCount=count(), UniqueDestPorts=dcount(DestinationPort)
    by SourceIP, DestinationIP, DeviceVendor
| where ScanCount > 50 or UniqueDestPorts > 20
| extend AlertTitle = strcat("Port Scan from ", SourceIP)
```

---

## Defender for Cloud — Defender CSPM

Enable Microsoft Defender for Cloud's external attack surface assessment for continuous exposure monitoring.

---

## Investigation Guide

**Step 1 — Threat intelligence (0–10 min)**
Submit the scanning IP to VirusTotal, Shodan, and AbuseIPDB. Is this a known scanner? A threat actor infrastructure IP? A commercial scan service?

**Step 2 — What are they targeting? (10–20 min)**
What paths and ports are being probed? Are they targeting a specific CVE (e.g., scanning for `/actuator/health` = Spring Boot, `/wp-admin` = WordPress)?

**Step 3 — Patch assessment (20–40 min)**
If scanning for a specific CVE: is your environment patched against it? If not, this scan may be followed by an exploitation attempt — escalate patch priority.

---

## Response Actions
- [ ] Block persistent, high-volume scanning IPs at WAF
- [ ] If targeted CVE scanning: escalate patching of that vulnerability immediately
- [ ] Enable WAF in Prevention mode if in Detection mode
- [ ] Add scanning IP to Sentinel TI watchlist for correlation

## References
- [MITRE T1595](https://attack.mitre.org/techniques/T1595/)
- [CISA: Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
