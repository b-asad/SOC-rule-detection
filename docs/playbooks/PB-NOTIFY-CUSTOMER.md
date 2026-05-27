# Playbook: PB-NOTIFY-CUSTOMER

**Trigger:** All P1 alerts — runs in parallel with containment playbooks

## Purpose
Ensures the customer is notified within the contracted SLA for P1 alerts (15 minutes). Sends structured alert notification to customer primary and secondary contacts.

## Pre-Conditions
- [ ] Customer escalation contacts populated in SOAR (primary, secondary, emergency)
- [ ] Customer notification preferences set (SMS, email, phone)
- [ ] SLA start time = alert creation time in Sentinel

## Automated Steps

1. **Trigger:** Sentinel alert with Severity = Critical created
2. **Condition:** Alert is new (not a duplicate or update)
3. **Action 1:** Look up customer notification contacts from SOAR customer profile
4. **Action 2:** Send email notification with:
   - Alert title, severity, affected device/user
   - Time of alert
   - Initial action taken (device isolated / session revoked / etc.)
   - Assigned SOC analyst name
   - Incident ticket number
5. **Action 3:** If no email acknowledgement within 10 minutes: send SMS to primary contact
6. **Action 4:** If no SMS acknowledgement within 5 minutes: trigger phone call to primary, then secondary contact
7. **Action 5:** Log notification timestamps in ITSM ticket for SLA compliance

## Customer Notification Template

```
SUBJECT: [P1 SECURITY ALERT] [CUSTOMER NAME] — [ALERT TITLE]

Time: [ALERT TIME UTC]
Severity: P1 — Critical
Alert: [ALERT TITLE]
Affected System: [DEVICE/USER FROM ALERT]
Action Taken: [AUTOMATED ACTION — e.g. Device isolated via MDE]
Assigned Analyst: [ANALYST NAME]
Incident Ticket: [TICKET NUMBER]

Our SOC team is investigating. You will receive an update within 30 minutes.
For urgent queries: [SOC PHONE NUMBER]
```
