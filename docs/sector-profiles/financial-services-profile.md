# Sector Profile — Financial Services

## Threat Landscape

Financial services are the most targeted sector by value. Threat actors range from nation-states seeking economic intelligence to organised criminal groups targeting direct financial theft. Primary threats:

- **BEC / payment fraud** — wire transfer fraud, invoice fraud, SWIFT messaging abuse
- **Insider threat** — rogue traders, departing employees, financial fraud
- **Trading system abuse** — unauthorised trading, market manipulation, front-running
- **Ransomware** — disrupting payment infrastructure (Dridex, BitPaymer, WastedLocker variants)
- **Nation-state espionage** — policy intelligence, M&A intelligence, client portfolios

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **DORA (2025)** | ICT operational resilience | Report major incidents to FCA/PRA within 4h |
| **FCA SYSC** | Systems and controls | Notify FCA under PRIN 11 for significant breaches |
| **MAR** | Report suspicious trading activity | Notify FCA under Article 16 immediately |
| **PCI DSS** | Protect cardholder data | Notify card brands within 24h |
| **UK GDPR** | Client personal data | Notify ICO within 72h |

## Detection Rule Deployment — Financial Services

1. All Generic rules (GEN-*)
2. `SEC-FS-IA-001` — BEC wire transfer fraud
3. `SEC-FS-CA-001` — Trading platform account takeover
4. `SEC-FS-CO-001` — Proprietary trading data exfiltration
5. `SEC-FS-LM-001` — IT-to-trading network pivot
6. `SEC-FS-IM-001` — Payment system disruption
7. `SEC-FS-EF-001` — Client PII exfiltration

## Required Watchlists — Financial Services

| Watchlist | Content |
|----------|---------|
| `TradingNetworkHosts` | All trading platform, OMS, and FIX gateway hostnames |
| `ITNetworkHosts` | Standard IT network hostnames |
| `InternalEmailDomains` | All firm email domains |

## Escalation Contacts — Template

- Chief Risk Officer — market/trading incidents
- Head of Compliance — regulatory notification decisions
- General Counsel — legal hold and regulatory obligations
- FCA Supervision team contact
- DORA incident reporting: FCA SUP 15.3
