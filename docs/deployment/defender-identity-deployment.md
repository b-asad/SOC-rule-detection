# Microsoft Defender for Identity — Sensor and Configuration Guide

## Sensor Deployment Checklist

- [ ] MDI sensor installed on **all Domain Controllers** — not just primary DC
- [ ] MDI sensor installed on ADFS servers (if federated identity in use)
- [ ] MDI sensor installed on AD CS (Certificate Authority) servers
- [ ] MDI workspace linked to Defender XDR unified portal
- [ ] Network traffic mirroring configured if using physical DC without port span capability
- [ ] Service account has: Event Log Reader, DNS admin (for sensor), Domain Read permissions

---

## Critical Alert Configuration

Configure these MDI alerts as **Critical severity** in Defender XDR → Settings → Microsoft Defender XDR → Alert service settings:

| MDI Alert Name | Maps To SOC Rule | Set As |
|---------------|-----------------|--------|
| Suspected credential theft (LSASS) | GEN-CA-001 | Critical |
| Password spray attack (Kerberos) | GEN-CA-002 | High |
| Password spray attack (LDAP) | GEN-CA-002 | High |
| Suspected Kerberoasting (SPN) | GEN-CA-003 | High |
| Pass-the-Hash | GEN-LM-001 | Critical |
| Pass-the-Ticket | GEN-LM-001 | Critical |
| Suspected overpass-the-hash | GEN-LM-001 | Critical |
| Suspected DCSync attack | GEN-CA-003 variant | Critical |
| Remote code execution attempt | GEN-EX-002 | High |
| Suspicious account creation | GEN-PE-002 | High |
| Golden Ticket | — | Critical |

---

## Exclusions — Add Before Go-Live

MDI portal → Configuration → Exclusions:

| Entity | Reason |
|--------|--------|
| Backup service accounts | Routine AD object access |
| SCCM/MECM management accounts | Legitimate remote management |
| Vulnerability scanner service accounts (Nessus, Qualys) | Scheduled scanning activity |
| Azure AD Connect service account | Sync operations |

---

## Honeytoken Configuration (Recommended)

Create 2–3 honeytokens per customer — accounts that should never be used. Any authentication attempt is a guaranteed true positive:

MDI portal → Configuration → Honeytoken accounts → Add honeytoken

Recommended honeytoken names: `svc-legacy-backup`, `admin-old`, `helpdesk-temp`
