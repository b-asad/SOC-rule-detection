# SEC-FS-CA-001 — Financial Services: Trading Platform Account Takeover

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-FS-CA-001` |
| **MITRE Technique** | T1078 — Valid Accounts |
| **Sector** | Financial Services |
| **Severity** | **Critical** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `SigninLogs` · `CloudAppEvents` (MCAS) |
| **Sector Context** | Trading platforms, order management systems, Bloomberg terminals, FIX gateways |

## Description
Successful authentication to a trading system or order management platform from an unexpected geography or device — direct financial loss risk from unauthorised trading. Attackers with access to trading platforms can place fraudulent orders, manipulate positions, or exfiltrate client portfolios. Every unauthorised access to a trading system is a potential MAR (Market Abuse Regulation) event.

## Microsoft Sentinel KQL
```kql
// SEC-FS-CA-001 | Frequency: 5m | Lookback: 5m
let TradingApps = dynamic(["Bloomberg","Fidessa","Murex","Calypso","FlexTrade","Broadridge","Charles River","FactSet","TradingView"]);
let ApprovedCountries = dynamic(["GB","IE","US","SG","HK"]);  // Adjust per customer
SigninLogs
| where TimeGenerated >= ago(5m) and ResultType == "0"
| where AppDisplayName has_any (TradingApps) or ClientAppUsed has_any (TradingApps)
| extend Country = tostring(LocationDetails.countryOrRegion)
| where Country !in (ApprovedCountries)
    or NetworkLocationDetails !contains "trustedNamedLocation"
| project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName, ConditionalAccessStatus
| extend AlertTitle = strcat("Trading System Access from ", Country, ": ", UserPrincipalName)
| extend MARRisk = "Potential MAR/FSMA breach. Notify Compliance immediately."
```

## Investigation Guide
**Step 1:** Was any trading activity executed during this session? Check order management audit log.
**Step 2:** Is this a legitimate trader? Contact their desk head by phone immediately.
**Step 3:** If orders placed: notify Compliance, Risk, and Legal — potential regulatory obligation.
**Step 4:** If market abuse indicators: report to FCA under MAR Article 16.

## Response Actions
- [ ] Revoke trading platform session immediately
- [ ] Notify Compliance Officer and Head of Trading Risk
- [ ] Review all orders placed during the suspicious session
- [ ] If market abuse suspected: notify FCA

## References
- [MITRE T1078](https://attack.mitre.org/techniques/T1078/) | [FCA: MAR](https://www.fca.org.uk/markets/market-abuse/regulation)
