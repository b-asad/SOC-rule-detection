# Playbook: PB-REVOKE-SESSION

**Trigger:** GEN-IA-002 (Impossible Travel) · GEN-IA-003 (Tor Access) · GEN-CO-001 (Forwarding Rule) · SEC-FS-CA-001 (Trading Takeover)

## Purpose
Revoke all active Entra ID sessions and optionally reset the password for a compromised or suspected compromised user account.

## Pre-Conditions
- [ ] Customer written approval
- [ ] Logic App has Entra ID API permissions: User.ReadWrite.All, Directory.AccessAsUser.All

## Automated Steps

1. **Trigger:** Sentinel P1 identity alert
2. **Condition:** Alert rule matches GEN-IA-002 / GEN-IA-003 / GEN-CO-001
3. **Action 1:** Extract `AccountName` / `AccountUPN` from alert entities
4. **Action 2:** Call Entra ID API: `POST /users/{upn}/revokeSignInSessions`
5. **Action 3:** Set Entra ID risk level to High: `POST /users/{upn}/authentication/signInActivity` (flags for Conditional Access)
6. **Action 4:** Notify SOC analyst — password reset required (manual step)
7. **Action 5:** Create incident ticket

## Manual Steps

1. Confirm session revocation in Entra ID portal — verify no active sessions remain
2. Reset password: Entra ID → Users → [user] → Reset password (force change on next login)
3. Force MFA re-enrolment: Entra ID → Users → [user] → Authentication methods → Require re-register MFA
4. Check for and delete any inbox forwarding rules: Exchange Online admin
5. Check for and revoke any OAuth app consents granted: Entra ID → Enterprise applications → User consent
