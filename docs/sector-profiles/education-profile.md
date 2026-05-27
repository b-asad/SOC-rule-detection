# Sector Profile — Education

## Threat Landscape

Education is consistently the most ransomware-hit sector globally. Large, open networks, student-owned devices, limited security budgets, and the inability to afford downtime during exams make universities and schools high-value targets. Primary threats:

- **Ransomware** — encrypting student records, research data, and VLE systems
- **Credential stuffing** — against student/staff portals using breached credentials
- **Research IP theft** — nation-state targeting defence, quantum, AI, pharmaceutical research
- **Student data theft** — identity fraud, financial aid fraud
- **Phishing** — against students (financial lures) and staff (HR/IT lures)
- **DDoS** — during exam periods to disrupt assessment delivery

## Key Regulatory Obligations

| Regulation | Requirement | Timeline if Breached |
|-----------|------------|---------------------|
| **UK GDPR** | Student personal data | Notify ICO within 72h |
| **Cyber Essentials** | Mandatory for some funding bodies | Annual certification |
| **JISC** | Sector-level incident notification | Notify JISC Cyber Security |

## Detection Rule Deployment — Education

1. All Generic rules (GEN-*)
2. `SEC-EDU-IM-001` — Ransomware on student/research systems
3. `SEC-EDU-CA-001` — Credential stuffing on student portals
4. `SEC-EDU-IA-001` — Phishing targeting students/staff
5. `SEC-EDU-CO-001` — Research IP theft
6. `SEC-EDU-EF-001` — Student PII exfiltration

## Required Watchlists — Education

| Watchlist | Content |
|----------|---------|
| `EducationCriticalHosts` | SIS, VLE, research cluster, library system hostnames |
| `InternalEmailDomains` | `.ac.uk` and institution email domains |

## Escalation Contacts — Template

- IT Director / Head of IT Security
- Data Protection Officer (DPO)
- Registrar — student record system events
- Research IT lead — research data events
- JISC Cyber Security: [www.jisc.ac.uk/cyber-security](https://www.jisc.ac.uk/cyber-security)
