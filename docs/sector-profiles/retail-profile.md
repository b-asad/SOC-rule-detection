# Sector Profile — Retail

## Threat Landscape

Retail is consistently in the top three most targeted sectors globally. The combination of high-volume card payment processing, customer PII databases, and eCommerce infrastructure makes retail a high-reward target. Primary threats:

- **Magecart / web skimming** — JavaScript injection on checkout pages capturing card data at point of entry
- **POS malware** — RAM scrapers targeting card track data in payment terminal memory (Backoff, PoSeidon, GratefulPOS)
- **Ransomware** — targeting store infrastructure to halt trading operations (LockBit, Akira, Black Basta)
- **Credential stuffing** — attacking loyalty programme and eCommerce portals with breached credentials
- **BEC** — targeting finance teams for supplier payment fraud
- **Insider threat** — data theft by departing employees with access to customer databases

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **PCI DSS v4.0** | Protect cardholder data in transit and at rest | Notify acquiring bank + card brands within 24h |
| **UK GDPR** | Protect customer personal data | Notify ICO within 72h; notify customers if high risk |
| **Consumer Duty** | Demonstrate fair customer outcomes | Ongoing |

## Detection Rule Deployment — Retail

Deploy in this order for all retail customers:

1. All Generic rules (GEN-*) — baseline for every customer
2. `SEC-RET-IA-001` — Magecart checkout injection
3. `SEC-RET-CA-001` — POS LSASS credential theft
4. `SEC-RET-LM-001` — POS network lateral movement
5. `SEC-RET-IM-001` — POS ransomware
6. `SEC-RET-CO-001` — Customer data bulk download
7. `SEC-RET-EF-001` — Payment card data exfiltration

## Log Sources Required

| Log Source | Sentinel Table | Rules |
|-----------|--------------|-------|
| MDE Device telemetry | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceEvents` | All MDE rules |
| Entra ID sign-in logs | `SigninLogs` | GEN-IA-002, GEN-IA-003 |
| Azure WAF / App Gateway | `AzureDiagnostics` | SEC-RET-IA-001 |
| Firewall / proxy logs | `CommonSecurityLog` | SEC-RET-EF-001, GEN-EF-001 |
| M365 Unified Audit Log | `OfficeActivity` | SEC-RET-CO-001 |

## Required Watchlists — Retail

| Watchlist | Content |
|----------|---------|
| `POS-Hosts` | All POS terminal and payment server hostnames |
| `InternalEmailDomains` | All retail group email domains |

## Escalation Contacts — Template

Store in SOAR customer profile:
- PCI Security Manager (or equivalent) — required for PCI DSS events
- Head of eCommerce — required for Magecart/web events
- Operations Director — required for store-impact events
- Acquiring Bank fraud contact — required for confirmed CHD breach
