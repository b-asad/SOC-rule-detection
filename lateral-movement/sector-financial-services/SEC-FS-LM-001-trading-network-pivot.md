# SEC-FS-LM-001 — Financial Services: Lateral Movement into Trading Network

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-FS-LM-001` |
| **MITRE Tactic** | Lateral Movement |
| **MITRE Technique** | T1550.002 — Pass the Hash / T1021.001 — RDP |
| **Sector** | **Financial Services** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Identity · Defender XDR · Defender for Endpoint |
| **Log Source** | `IdentityLogonEvents` (MDI) · `DeviceLogonEvents` (MDE) · Firewall logs |
| **Sector Context** | Investment banks, hedge funds, broker-dealers, asset managers, payment firms |
| **Created** | May 2026 |

---

## Description

Detects lateral movement from standard IT network hosts into trading network, order management systems (OMS), or financial market infrastructure. Network segmentation between IT and trading environments is a core control for financial services firms under FCA SYSC, DORA, and PCI DSS. Any pivot across this boundary must be treated as Critical.

Threat actors targeting financial services firms (FIN7, Carbanak, Lazarus Group) specifically seek to reach trading platforms to place fraudulent orders, exfiltrate client portfolios, or disrupt market operations. Even brief unauthorised access to an OMS can constitute a MAR (Market Abuse Regulation) event requiring FCA notification.

---

## Microsoft Sentinel KQL

```kql
// SEC-FS-LM-001 | Frequency: 5m | Lookback: 5m
let TradingHosts = (_GetWatchlist('TradingNetworkHosts') | project SearchKey);
let ITHosts      = (_GetWatchlist('ITNetworkHosts') | project SearchKey);
// Detection 1: NTLM auth from IT host to trading host
let NTLMPivot = (
    IdentityLogonEvents
    | where TimeGenerated >= ago(5m)
    | where ActionType == "LogonSuccess"
    | where Protocol in ("Ntlm","Kerberos")
    | where DestinationDeviceName in~ (TradingHosts)
        or DestinationDeviceName has_any (
            "trading","bloomberg","murex","fidessa","calypso","flexcube",
            "temenos","finastra","misys","finacle","oms","fix-gateway",
            "settlement","clearing","prime-brokerage"
        )
    | where not(DeviceName in~ (TradingHosts))
    | project TimeGenerated, AccountName, AccountDomain,
        DeviceName, DestinationDeviceName, Protocol, LogonType
    | extend DetectionType = "IT-to-Trading-NTLM"
);
// Detection 2: RDP from IT workstation to trading server
let RDPPivot = (
    DeviceLogonEvents
    | where TimeGenerated >= ago(5m)
    | where LogonType == "RemoteInteractive"
    | where ActionType == "LogonSuccess"
    | where RemoteDeviceName in~ (TradingHosts)
        or RemoteDeviceName has_any ("trading","bloomberg","oms","fix","settlement")
    | where not(DeviceName in~ (TradingHosts))
    | project TimeGenerated, AccountName, DeviceName, RemoteDeviceName, LogonType
    | extend DetectionType = "IT-to-Trading-RDP"
);
NTLMPivot | union RDPPivot
| extend AlertTitle = strcat("Trading Network Pivot: ", DeviceName, " → ", DestinationDeviceName)
| extend MARRisk = "Unauthorised trading system access may constitute MAR breach — notify Compliance"
| extend DORAObligation = "DORA Art.19: Notify FCA/PRA within 4h if trading operations impacted"
```

---

## Defender for Identity — MDI Lateral Movement Alerts

MDI will raise alerts when NTLM is used from an anomalous source host. Ensure these are correlated with this rule in Defender XDR:
- **Pass-the-Hash attack** — when hash from IT host is used to authenticate to trading system
- **Suspicious service creation** — if attacker installs persistence on trading server
- **Remote code execution attempt** — if attacker runs commands on trading host

---

## Defender XDR — Advanced Hunting

```kql
// SEC-FS-LM-001 | Run: Every hour
let TradingHosts = (_GetWatchlist('TradingNetworkHosts') | project SearchKey);
IdentityLogonEvents
| where Timestamp >= ago(1h)
| where ActionType == "LogonSuccess"
| where Protocol in ("Ntlm","Kerberos","Rdp")
| where DestinationDeviceName in~ (TradingHosts)
    or DestinationDeviceName has_any ("trading","bloomberg","murex","fidessa","fix","oms")
| join kind=leftanti (
    IdentityLogonEvents
    | where Timestamp between (ago(30d)..ago(1d))
    | distinct DeviceName, DestinationDeviceName, AccountName
) on DeviceName, DestinationDeviceName, AccountName
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, Protocol
| order by Timestamp desc
```

---

## Defender for Endpoint — Post-Pivot Investigation

```kql
// What did the attacker do on the trading system after gaining access?
DeviceProcessEvents
| where DeviceName == "<TRADING_HOST_FROM_ALERT>"
| where Timestamp >= "<PIVOT_TIME>"
| where AccountName == "<PIVOTING_ACCOUNT>"
| project Timestamp, FileName, ProcessCommandLine, AccountName, FolderPath, SHA256
| order by Timestamp asc
```

```kql
// Were any orders placed, modified, or cancelled after the pivot?
// This requires trading platform audit log integration — query varies by OMS vendor
// Example for Bloomberg SSEOMS or Fidessa OMS audit log forwarded to Sentinel:
TradingAuditLog_CL
| where TimeGenerated >= "<PIVOT_TIME>"
| where UserID_s == "<PIVOTING_ACCOUNT>"
| project TimeGenerated, UserID_s, Action_s, OrderID_s, Instrument_s, Quantity_d, Price_d
```

---

## Investigation Guide

**Step 1 — Trading platform integrity (0–5 min, SIMULTANEOUS with isolation)**
Notify: Head of Technology Risk + Compliance + Head of Trading simultaneously.
Were any orders placed, modified, or cancelled after the pivot time?
Can trading operations continue on the affected system?

**Step 2 — Credential source on IT host (5–20 min)**
Run GEN-CA-001 LSASS check on the source IT device:
```kql
DeviceEvents | where DeviceName == "<SOURCE_IT_HOST>" | where Timestamp >= ago(24h)
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe","SenseCE.exe","csrss.exe"))
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine
```
Were credentials dumped from the IT host before the pivot?

**Step 3 — Scope of trading system access (20–40 min)**
Pull the OMS audit log for the compromised account.
Determine: what instruments were visible, what orders were accessible, what data was readable.

**Step 4 — MAR assessment (40–60 min)**
Work with the Compliance team:
- Did the attacker have access to inside information on the trading system?
- Were any orders placed or modified that could constitute market manipulation?
- Is FCA notification required under MAR Article 16?

---

## Response Actions

**Immediate (P1 — within 15 minutes)**
- [ ] Isolate the source IT host — MDE
- [ ] Revoke the pivoting account's trading system access immediately
- [ ] Notify Head of Technology Risk and Compliance by phone
- [ ] Preserve full OMS audit log from the pivot time — do not allow log rotation

**Within 1 Hour**
- [ ] Review all trading activity by the compromised account since the pivot time
- [ ] Assess whether any suspicious orders were placed — reverse if possible
- [ ] Notify FCA Supervision under DORA Article 19 if trading operations were impacted

**Regulatory**
- [ ] DORA: Notify FCA/PRA within 4 hours if major ICT incident impacting trading
- [ ] MAR Article 16: Notify FCA if market abuse indicators identified
- [ ] PCI DSS: Assess if cardholder data was accessible from trading infrastructure

## False Positives

| Scenario | Mitigation |
|----------|-----------|
| Authorised IT admin connecting to trading server for maintenance | Add approved admin-to-trading maintenance pairs to `TradingNetworkHosts` allowlist — require ITSM ticket reference |
| New trading application server — baseline gap | Verify device age < 30 days in asset register; add to approved list with sign-off |

## References
- [MITRE T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [DORA Article 19](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554)
- [FCA: MAR notification](https://www.fca.org.uk/markets/market-abuse/regulation)
