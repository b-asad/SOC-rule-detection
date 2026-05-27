# Microsoft Defender XDR — Deployment Guide

## Prerequisites
- [ ] Defender XDR portal access — Security Administrator role
- [ ] MDE P2 onboarded on all devices
- [ ] MDI sensor active on all Domain Controllers
- [ ] MDO P2 with Safe Links/Attachments in Block mode
- [ ] MCAS connected to M365, Azure, and cloud apps in scope

---

## Creating a Custom Detection Rule

1. **Defender XDR → Hunting → Custom detection rules → + Create**
2. **Alert details:** Name `[RULE-ID] — [Rule Name]`, Frequency `Every hour`, Severity and Category matching the rule
3. **Detection query:** paste from `## Defender XDR — Advanced Hunting` block
4. **Impacted entities:** configure per rule (Device → `DeviceName`, User → `AccountName`)
5. **Actions:** start with **Alert only** — enable automated response after 7-day validation

---

## Required Data Tables by Product

| Product | Key Tables | Rules Requiring |
|---------|-----------|----------------|
| MDE P2 | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceEvents`, `DeviceLogonEvents` | All GEN-* endpoint rules |
| MDI | `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents` | GEN-LM-001/002, GEN-CA-002/003, GEN-PE-002 |
| MDO P2 | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents` | GEN-IA-001, GEN-CO-001, SEC-GOV-IA-001 |
| MCAS | `CloudAppEvents` | GEN-IA-002/003, SEC-FS-CO-001, SEC-EDU-EF-001 |
| Entra ID | `AADSignInEventsBeta`, `SigninLogs` | GEN-IA-002/003, GEN-CA-002 |

---

## MDI Sensor Deployment Checklist

- [ ] Sensor installed on **every** Domain Controller
- [ ] Sensor installed on ADFS servers if federated auth in use
- [ ] Sensor installed on AD CS (Certificate Authority) servers
- [ ] MDI workspace connected to Defender XDR (unified portal)
- [ ] These MDI alerts configured as Critical: Pass-the-Hash, Pass-the-Ticket, Kerberoasting, LSASS theft, DCSync

---

## Scheduled Threat Hunts — Weekly

Run these manually every week as proactive hunts:

| Rule | Lookback | Notes |
|------|---------|-------|
| GEN-CC-001 | 7 days | Catch slow beaconing below 2h detection window |
| GEN-CA-003 | 7 days | Catch single-occurrence Kerberoasting |
| GEN-LM-001 | 7 days | Extended baseline for missed PtH |
| SEC-HC-CA-001 | 30 days | Monthly patient data access review |
| SEC-FS-CO-001 | 30 days | Monthly trading data review |
| SEC-TECH-EF-001 | 30 days | Monthly source code clone review |
