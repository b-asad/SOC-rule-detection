# GEN-CC-002 — C2: DNS Tunnelling / DGA

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-CC-002` |
| **MITRE Technique** | T1071.004 / T1568.002 — DNS / DGA |
| **Sector** | Generic |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DnsEvents` · `DeviceNetworkEvents` (MDE) |

## Description
DNS tunnelling encodes C2 traffic or exfiltrated data inside DNS queries using abnormally long, high-entropy subdomains. DGA malware algorithmically generates hundreds of domain names per day to locate C2 infrastructure, producing a characteristic pattern of failed DNS resolutions for random-looking domains. Both techniques bypass firewall controls that only inspect HTTP/HTTPS.

## Microsoft Sentinel KQL
```kql
// GEN-CC-002 | Frequency: 15m | Lookback: 1h
let TrustedDomains = dynamic([
    "microsoft.com","windows.com","office.com","azure.com","google.com",
    "amazonaws.com","akamai.com","cloudflare.com","digicert.com"
]);
// Detection A: Long subdomain queries (DNS tunnelling)
let Tunnelling = (
    DnsEvents
    | where TimeGenerated >= ago(1h)
    | where SubType == "LookupQuery"
    | where not(Name has_any (TrustedDomains))
    | extend SubdomainLen = strlen(tostring(split(Name, ".", 0)))
    | where SubdomainLen > 40
    | summarize QueryCount=count(), UniqueDomains=dcount(Name), SampleDomains=make_set(Name,5)
        by ClientIP, Computer
    | where QueryCount > 30 or SubdomainLen > 60
    | extend DetectionType = "DNS_Tunnelling"
);
// Detection B: High-volume failed resolutions (DGA)
let DGA = (
    DnsEvents
    | where TimeGenerated >= ago(1h)
    | where ResultCode != 0  // NXDOMAIN / failed resolution
    | where not(Name has_any (TrustedDomains))
    | summarize FailCount=count(), UniqueDomains=dcount(Name), SampleDomains=make_set(Name,5)
        by ClientIP, Computer
    | where FailCount > 100 and UniqueDomains > 50
    | extend DetectionType = "DGA_Pattern"
);
Tunnelling | union DGA
| extend AlertTitle = strcat(DetectionType, " from ", Computer)
```

## Defender XDR — Advanced Hunting
```kql
// GEN-CC-002 | Run: Every hour
DeviceNetworkEvents
| where Timestamp >= ago(1h) and ActionType == "DnsQueryResponse"
| extend DomainLen = strlen(RemoteUrl)
| where DomainLen > 50 or RemoteUrl matches regex @"[a-z0-9]{20,}\."
| summarize Count=count(), Domains=make_set(RemoteUrl,5)
    by DeviceName, InitiatingProcessFileName
| where Count > 30
| order by Count desc
```

## Defender for Endpoint
```kql
// Identify the process making tunnelling DNS queries
DeviceNetworkEvents
| where DeviceName == "<DEVICE>" | where Timestamp >= ago(2h)
| where ActionType == "DnsQueryResponse"
| where strlen(RemoteUrl) > 40
| project Timestamp, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp asc
```

## Investigation Guide
**Step 1 (< 10 min):** Submit the queried parent domain to VirusTotal/OTX. Check WHOIS registration age.
**Step 2 (10–20 min):** Identify the process making DNS queries (MDE query above). Is it unsigned or from a suspicious path?
**Step 3 (20–35 min):** Estimate data volume: count queries × average payload per query (≈50–60 bytes/label).
**Step 4 (35–50 min):** Check for the same parent domain across all customer environments.

## Response Actions
- [ ] Block the parent domain at firewall and DNS sinkhole
- [ ] Isolate device if process confirmed malicious
- [ ] Submit IOCs to Sentinel TI watchlist

## References
- [MITRE T1071.004](https://attack.mitre.org/techniques/T1071/004/) | [MITRE T1568.002](https://attack.mitre.org/techniques/T1568/002/)
