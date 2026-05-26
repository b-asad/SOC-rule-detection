# Microsoft Defender for Identity — Sensor & Alert Configuration

## Sensor Deployment Checklist
- [ ] MDI sensor installed on **all Domain Controllers** (not just primary DC)
- [ ] MDI sensor installed on **ADFS servers** if federated identity in use
- [ ] MDI sensor installed on **AD CS servers** (certificate authority)
- [ ] Service account has required permissions (Event Log Reader, DNS admin for sensor)
- [ ] Network traffic mirroring configured if sensor is on a physical DC
- [ ] MDI workspace connected to Defender XDR (unified portal)

## Critical Alerts to Escalate to P1
These MDI alerts map directly to SOC rules and must be P1:

| MDI Alert | Maps To Rule | Severity |
|-----------|-------------|---------|
| Suspected LSASS credential stealing | GEN-CA-001 | Critical |
| Password spray attack (Kerberos/LDAP) | GEN-CA-002 | High |
| Suspected Kerberoasting attack | GEN-CA-003 | High |
| Pass-the-hash attack | GEN-LM-001 | Critical |
| Pass-the-ticket attack | GEN-LM-001 variant | Critical |
| Suspected DCSync attack | GEN-CA-003 variant | Critical |
| Golden Ticket attack | — | Critical |
| Remote code execution attempt | GEN-EX-002 | High |

## MDI Exclusions Configuration
Add these exclusions to prevent known FPs:
- Backup service accounts accessing AD objects
- SCCM/MECM management accounts
- Vulnerability scanner service accounts

MDI portal → Configuration → Exclusions → Add entity exclusions
