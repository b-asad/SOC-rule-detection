# SEC-ENRG-IA-001 — Energy & Utilities: Unauthorised External Access to SCADA/ICS

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-ENRG-IA-001` |
| **MITRE Tactic** | Initial Access |
| **MITRE Technique** | T1133 — External Remote Services |
| **Sector** | **Energy & Utilities** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR |
| **Log Source** | `CommonSecurityLog` (Firewall/VPN) · `SigninLogs` (Entra ID) · OT Firewall Logs |
| **Sector Context** | Power generation, electricity distribution, water/wastewater, gas networks, nuclear facilities |
| **Created** | May 2026 |

---

## Description

Detects external remote access to SCADA, ICS, or energy management systems from unexpected sources — including Tor exit nodes, anonymous proxies, malicious IP ranges, or geographies outside the operator's approved access list. Energy infrastructure is a primary target for nation-state actors (VOLTZITE/Volt Typhoon, Sandworm) seeking to pre-position for physical disruption of critical national infrastructure.

**Regulatory:** NIS2 — 24-hour report to NCSC. CNI organisations must report to sector regulator (Ofgem for energy, Ofwat for water). NCSC CAF compliance required.

---

## Microsoft Sentinel KQL

```kql
// SEC-ENRG-IA-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
let ApprovedCountries = dynamic(["GB","IE"]);  // Adjust for customer — UK energy operators should have very limited approved access geographies
let OTAssets = (_GetWatchlist('OTAssets') | project SearchKey);
let TorNodes = (_GetWatchlist('TorExitNodes') | project SearchKey);
// Detection 1: External access to OT/SCADA systems from unapproved geography
let GeoAnomaly = (
    SigninLogs
    | where TimeGenerated >= ago(5m)
    | where ResultType == "0"
    | where AppDisplayName has_any ("SCADA","HMI","OT","IAMS","energy","substation","DMS","EMS","ADMS")
        or TargetResources has_any (OTAssets)
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | where Country !in (ApprovedCountries)
    | project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName
    | extend DetectionType = "UnexpectedGeoAccess"
);
// Detection 2: Tor or anonymous proxy access to energy systems
let TorAccess = (
    CommonSecurityLog
    | where TimeGenerated >= ago(5m)
    | where DeviceAction !in ("deny","block","drop")
    | where DestinationHostName has_any (OTAssets)
        or DestinationPort in (502, 4840, 44818, 20000, 102)
    | where SourceIP in (TorNodes)
    | project TimeGenerated, SourceIP, DestinationIP, DestinationHostName, DestinationPort
    | extend DetectionType = "TorAccessToOT"
);
GeoAnomaly | union TorAccess
| extend AlertTitle = strcat("CRITICAL: Unauthorised Access to Energy/OT System")
| extend CNIRisk = "Critical National Infrastructure at risk. Physical disruption possible."
| extend NIS2Obligation = "Report to NCSC within 24h. Notify sector regulator (Ofgem/Ofwat)."
```

---

## Investigation Guide

**Step 1 — Physical Safety Assessment (Immediate)**
Which OT/SCADA system was accessed?
- Distribution Management System (DMS) → power distribution control
- Energy Management System (EMS) → generation dispatch
- SCADA for water/wastewater → water supply control
- Substation automation → transmission control

If access was to a control system: immediately notify the Control Room Engineer and escalate to physical operations team.

**Step 2 — Access Source (< 10 min)**
Submit source IP to VirusTotal, Shodan, and AbuseIPDB.
Check WHOIS: is this a known nation-state infrastructure provider?
If Tor: this is a near-certain malicious access attempt.

**Step 3 — Actions Taken (10–30 min)**
What commands or changes were made during the session?
Review SCADA/HMI audit logs immediately.
Were any setpoints changed? Were any devices taken offline? Were any alarms suppressed?

---

## Response Actions
**Immediate**
- [ ] Terminate the remote session immediately
- [ ] Lock out the account and revoke all tokens
- [ ] Notify Control Room and physical operations team
- [ ] Place OT systems in manual control mode if integrity is uncertain

**Regulatory**
- [ ] Report to NCSC within 24h (NIS2)
- [ ] Notify Ofgem/Ofwat/ONR as applicable
- [ ] Report to CPNI (Centre for Protection of National Infrastructure) for CNI guidance
- [ ] Consider reporting to CISA if US parent company involved

## References
- [MITRE T1133](https://attack.mitre.org/techniques/T1133/)
- [NCSC: OT/ICS security](https://www.ncsc.gov.uk/collection/operational-technology)
- [CISA: ICS advisories](https://www.cisa.gov/uscert/ics)
- [NIS2 Directive](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022L2555)
