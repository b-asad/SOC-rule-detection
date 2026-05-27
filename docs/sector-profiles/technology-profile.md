# Sector Profile — Technology

## Threat Landscape

Technology companies are targeted for their source code, customer data, cloud infrastructure, and supply chain position. A compromised technology vendor can be used to attack their customers (SolarWinds, 3CX). Primary threats:

- **Source code theft** — corporate espionage, nation-state
- **Supply chain compromise** — CI/CD pipeline injection, package manager poisoning
- **OAuth/consent phishing** — persistent access via token theft
- **Cloud infrastructure abuse** — cryptomining, resource deletion, data theft
- **Insider threat** — departing developers cloning repositories
- **Credential stuffing** — SaaS platform account takeover

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **UK GDPR** | Customer/user personal data | Notify ICO within 72h |
| **SOC 2** | Service organisation controls | Auditor notification |
| **ISO 27001** | Information security | Certification/contractual |
| **NIS2** | If critical digital infrastructure | Report to NCSC within 24h |

## Detection Rule Deployment — Technology

1. All Generic rules (GEN-*)
2. `SEC-TECH-PE-001` — CI/CD pipeline injection
3. `SEC-TECH-IA-001` — OAuth consent phishing
4. `SEC-TECH-CA-001` — Code signing / secret access
5. `SEC-TECH-IM-001` — Cloud infrastructure destruction
6. `SEC-TECH-EF-001` — Source code exfiltration

## Escalation Contacts — Template

- CISO / Head of Security
- VP Engineering / CTO — source code/pipeline events
- Legal / IP Counsel — IP theft events
- Customer notification contact — if supply chain breach affects customers
