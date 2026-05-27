# GEN-CC-001 — Command and Control: C2 Beaconing Pattern

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CC-001` |
| **MITRE Tactic** | Command and Control |
| **MITRE Technique** | T1071.001 — Application Layer Protocol: Web Protocols |
| **Sector** | **Generic** — All Customers |
| **Severity** | **High** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `CommonSecurityLog` (Firewall/Proxy) · `DeviceNetworkEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Detects periodic outbound HTTP/HTTPS connections from a single host to the same external IP or domain with a consistent interval and low jitter — the statistical signature of C2 beaconing. Malware uses a fixed sleep timer between C2 check-ins, producing a connection interval with very low standard deviation. Legitimate applications have naturally variable timing.

This rule uses a **beacon score** (0–100): higher scores indicate more consistent timing and higher confidence in beaconing behaviour. Scores above 85 should be treated as near-certain beaconing.

---

## Microsoft Sentinel KQL

```kql
// GEN-CC-001 | Frequency: 15m | Lookback: 2h | Threshold: > 0
// Beacon score 0-100: higher = more consistent = higher confidence C2
let Exclusions = dynamic([
    "microsoft.com","windowsupdate.com","office.com","live.com",
    "azure.com","office365.com","microsoftonline.com","azure-automation.net",
    "google.com","gstatic.com","googleapis.com","googleusercontent.com",
    "akamai.com","akamaiedge.net","cloudflare.com","fastly.net",
    "amazonaws.com","s3.amazonaws.com",
    "apple.com","icloud.com","symantec.com","digicert.com",
    "zoom.us","zoomgov.com","webex.com","teams.microsoft.com"
]);
CommonSecurityLog
| where TimeGenerated >= ago(2h)
| where DeviceAction !in ("deny","block","drop","reset","DENY","BLOCK")
| where DestinationPort in (80, 443, 8080, 8443, 4443)
| where not(DestinationHostName has_any (Exclusions))
| where not(DestinationIP has_any ("10.","172.16.","172.17.","172.18.","172.19.",
    "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.",
    "172.28.","172.29.","172.30.","172.31.","192.168."))
| project TimeGenerated, SourceIP, DestinationIP, DestinationHostName, DestinationPort, DeviceName
| sort by SourceIP asc, DestinationIP asc, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1)
| extend PrevSrc  = prev(SourceIP, 1)
| extend PrevDst  = prev(DestinationIP, 1)
| where SourceIP == PrevSrc and DestinationIP == PrevDst
| extend IntervalSeconds = datetime_diff('second', TimeGenerated, PrevTime)
| where IntervalSeconds between (30 .. 3600)  // 30s–60min beacon range
| summarize
    ConnectionCount  = count(),
    AvgIntervalSec   = avg(IntervalSeconds),
    StdDevSec        = stdev(IntervalSeconds),
    MinInterval      = min(IntervalSeconds),
    MaxInterval      = max(IntervalSeconds),
    FirstConnection  = min(TimeGenerated),
    LastConnection   = max(TimeGenerated)
    by SourceIP, DestinationIP, DestinationHostName, DestinationPort, DeviceName
| where ConnectionCount >= 10
| where StdDevSec <= 30
| extend BeaconScore = round(100.0 - (StdDevSec / AvgIntervalSec * 100), 1)
| extend BeaconScore = iff(BeaconScore < 0, 0.0, BeaconScore)
| extend AlertTitle = strcat("C2 Beaconing: ", SourceIP, " → ", DestinationIP, " (score: ", BeaconScore, ")")
| extend Severity = iff(BeaconScore >= 85, "Critical", "High")
| order by BeaconScore desc
```

---

## Defender XDR — Advanced Hunting

```kql
// GEN-CC-001 | Run: Every hour | Category: CommandAndControl | Severity: High
let Excl = dynamic([
    "microsoft.com","windowsupdate.com","office.com","azure.com",
    "google.com","cloudflare.com","akamai.com","amazonaws.com","zoom.us"
]);
DeviceNetworkEvents
| where Timestamp >= ago(2h)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (80,443,8080,8443,4443)
| where not(RemoteUrl has_any (Excl))
| where not(RemoteIP has_any ("10.","192.168.","172.16."))
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| serialize
| extend PrevTime = prev(Timestamp,1), PrevDev=prev(DeviceName,1), PrevDst=prev(RemoteIP,1)
| where DeviceName==PrevDev and RemoteIP==PrevDst
| extend IntervalSec = datetime_diff('second',Timestamp,PrevTime)
| where IntervalSec between (30 .. 3600)
| summarize
    Count=count(), AvgInt=avg(IntervalSec), StdDev=stdev(IntervalSec),
    Processes=make_set(InitiatingProcessFileName,5), First=min(Timestamp), Last=max(Timestamp)
    by DeviceName, DeviceId, RemoteIP, RemoteUrl, RemotePort
| where Count >= 8 and StdDev <= 30
| extend BeaconScore = round(100.0 - (StdDev/AvgInt*100), 1)
| order by BeaconScore desc
```

---

## Defender for Endpoint — Process Investigation

```kql
// Identify which process is making the beaconing connections
DeviceNetworkEvents
| where DeviceName == "<DEVICE_NAME>"
| where RemoteIP == "<C2_IP_FROM_ALERT>"
| where Timestamp >= ago(2h)
| project
    Timestamp,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    InitiatingProcessParentFileName,
    RemoteUrl,
    RemotePort,
    ActionType
| order by Timestamp asc
```

```kql
// Check if the beaconing process has written any files (payload download)
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where InitiatingProcessFileName == "<BEACONING_PROCESS>"
| where Timestamp >= ago(2h)
| project Timestamp, FileName, FolderPath, SHA256, ActionType
| order by Timestamp asc
```

---

## Investigation Guide

**Step 1 — Threat Intelligence (< 10 min)**
Submit the destination IP and domain to:
- [VirusTotal](https://virustotal.com) — malicious rating and community comments
- [Shodan](https://shodan.io) — what services is the IP running? Common C2 ports open?
- [AbuseIPDB](https://abuseipdb.com) — recent abuse reports
- [AlienVault OTX](https://otx.alienvault.com) — known threat actor IOC?

Note the domain registration date — newly registered domains (< 30 days) hosting C2 is very common.

Check TLS certificate: self-signed certificate or Let's Encrypt on a residential IP = high confidence C2.

**Step 2 — Process Identification (10–25 min)**
Run the "process investigation" query. Suspicious indicators:
- Process running from `%TEMP%`, `%APPDATA%`, `%PROGRAMDATA%`, `C:\Users\<user>\` (not standard app paths)
- Process is **unsigned** or signed by an unfamiliar/suspicious vendor
- Process name mimics a legitimate binary (e.g., `svchos1.exe`, `svch0st.exe`, `iexplore.exe` from wrong path)
- Parent process is `cmd.exe`, `powershell.exe`, or an Office application (delivery chain indicator)

**Step 3 — Traffic Content Analysis (25–40 min)**
```kql
// If proxy logs are available, check HTTP request/response details
CommonSecurityLog
| where TimeGenerated >= ago(2h)
| where SourceIP == "<SOURCE_IP>" and DestinationIP == "<C2_IP>"
| project TimeGenerated, RequestURL, RequestMethod, RequestContext, BytesSent, BytesReceived, UserAgent
| order by TimeGenerated asc
```

C2 traffic indicators:
- Consistent URI pattern (same path on every connection = check-in endpoint)
- Very small response (a few bytes) = C2 acknowledgement/no tasking
- POST with encoded body = tasking being sent to implant
- Unusual or fake User-Agent strings

**Step 4 — Persistence and Scope (40–60 min)**
```kql
// Check for persistence on the beaconing device
DeviceRegistryEvents
| where DeviceName == "<DEVICE_NAME>" | where Timestamp >= ago(24h)
| where RegistryKey has_any ("CurrentVersion\\Run","Services","Scheduled","Winlogon")
| where ActionType in ("RegistryKeyCreated","RegistryValueSet")
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

Search the same C2 IP/domain across ALL customer environments:
```kql
// Multi-customer hunt — is the same C2 present elsewhere?
CommonSecurityLog
| where DestinationIP == "<C2_IP>"
| where TimeGenerated >= ago(7d)
| distinct DeviceName, SourceIP, TimeGenerated
```

---

## Response Actions
**Immediate**
- [ ] Block C2 IP and domain — MDE custom indicators (Block + Alert) + firewall + Sentinel TI watchlist
- [ ] Isolate device if beaconing process confirmed malicious
- [ ] Submit process hash to Microsoft Defender Threat Intelligence sandbox

**Short-term**
- [ ] Run full malware scan on the affected device
- [ ] Check for persistence mechanisms installed by the beaconing process
- [ ] Conduct memory forensics if process evades disk-based detection (fileless malware)
- [ ] Search the same C2 across all customer environments

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| NTP time synchronisation (port 123) | Already filtered by port — NTP is not included |
| Telemetry agents (Splunk forwarder, Datadog agent) sending heartbeats | Add known agent destination IP/domain to the Exclusions list |
| Video conferencing heartbeats (Teams, Zoom, Webex) | Pre-excluded in the Exclusions list — add any not covered |
| Software update checkers | Add known update server domains to Exclusions list |

## References
- [MITRE T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [Microsoft: Advanced Hunting for beaconing](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)
