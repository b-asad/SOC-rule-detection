# Playbook: PB-RANSOMWARE-RESPONSE

**Trigger:** GEN-IM-001 (Shadow Copy Deletion) · GEN-IM-002 (Mass Encryption) · Sector ransomware rules

## Purpose
Coordinates the immediate response to a confirmed or suspected ransomware event. Combines automated device isolation with SOC team notification and customer escalation.

## Pre-Conditions
- [ ] Customer written approval for automated device isolation
- [ ] Customer BCP contacts populated in SOAR
- [ ] Customer backup contact details populated in SOAR
- [ ] NCSC reporting URL bookmarked: report.ncsc.gov.uk

## Automated Steps (Logic App)

1. **Trigger:** Sentinel alert: GEN-IM-001 or GEN-IM-002
2. **Action 1:** Isolate triggering device — MDE API `isolate`
3. **Action 2:** Search for same shadow copy deletion command across all devices in same customer workspace — identify additional compromised devices
4. **Action 3:** Send P1 alert via SMS and email to:
   - On-call SOC Analyst
   - SOC Manager
   - Customer Primary Security Contact
5. **Action 4:** Create P1 ITSM incident — tag `RANSOMWARE-ACTIVE`, customer name, affected device list
6. **Action 5:** Post alert details to SOC Slack/Teams channel: `#p1-incidents`

## Manual Steps (SOC Analyst)

1. **Immediate (0–5 min):** Confirm isolation. Call SOC Manager. Call customer CISO.
2. **Blast radius (5–15 min):** Run patient zero and blast radius queries from impact-guide.md
3. **Isolate additional hosts:** Bulk isolate all affected devices via MDE Device groups
4. **Ransom note identification:** Submit to id-ransomware.malwarehunterteam.com
5. **Backup assessment:** Work with customer IT — are clean backups accessible?
6. **Regulatory notifications:** Assess ICO (72h), sector-specific obligations (see impact-guide.md)
7. **Do NOT advise paying ransom** — document advice to customer

## Post-Incident
- Recovery supervised by SOC — verify clean before reconnecting to network
- Post-incident review within 5 business days
- Root cause analysis documented and shared with customer
