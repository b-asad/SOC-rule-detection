# Microsoft Defender XDR — Custom Detection Rule Deployment

## Prerequisites
- Defender XDR access with Security Administrator role
- Required products licensed: MDE P2, MDI, MDO P2, MCAS

## Creating a Custom Detection Rule

1. Open **Microsoft Defender XDR** → **Hunting** → **Custom detection rules** → **+ Create**
2. **Alert details:**
   - Rule name: `[RULE-ID] — [Rule Name]`
   - Frequency: as documented in rule file (typically `Every hour` or `Every 24 hours`)
   - Severity: match rule Severity
   - Category: match rule Tactic
   - MITRE ATT&CK techniques: enter technique ID from rule metadata
3. **Detection query:** paste from `## Defender XDR Advanced Hunting` block
4. **Impacted entities:** configure as documented per rule (Device, User, URL, IP)
5. **Actions:** set automated response (Isolate device, Mark user as risky, etc.) — start with **alert only** for first 7 days
6. **Save** and monitor alerts

## Required Data Tables by Product

| Table | Source Product | Key Rules |
|-------|--------------|-----------|
| `DeviceProcessEvents` | MDE P2 | GEN-EX-001, GEN-IA-001, GEN-IM-001 |
| `DeviceFileEvents` | MDE P2 | GEN-PE-001, RG-IA-001 |
| `DeviceNetworkEvents` | MDE P2 | GEN-CC-001, GEN-DI-001 |
| `DeviceRegistryEvents` | MDE P2 | GEN-PE-001, GEN-DE-001, GEN-PV-001 |
| `DeviceEvents` | MDE P2 | GEN-CA-001, GEN-DE-001 |
| `DeviceLogonEvents` | MDE P2 | GEN-LM-001 |
| `AADSignInEventsBeta` | Entra ID | GEN-IA-002, GEN-IA-003 |
| `IdentityLogonEvents` | MDI | GEN-LM-001, GEN-CA-003 |
| `IdentityQueryEvents` | MDI | GEN-CA-003 |
| `EmailEvents` | MDO | GEN-CO-001 |
| `EmailAttachmentInfo` | MDO | GEN-IA-001 (correlation) |
| `CloudAppEvents` | MCAS | GEN-EF-001, RA-IM-001 |

## Advanced Hunting — Regular Threat Hunts
Schedule these hunts weekly across all customers:
- **GEN-CC-001** (beaconing) — 7-day lookback
- **GEN-CA-003** (Kerberoasting) — 7-day lookback
- **GEN-LM-001** (PtH) — 7-day lookback
