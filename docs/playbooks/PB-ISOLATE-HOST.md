# Playbook: PB-ISOLATE-HOST

**Trigger:** P1 endpoint alerts — GEN-IA-001, GEN-CA-001, GEN-IM-001, GEN-DE-001, GEN-DE-002

## Purpose
Automatically isolate a device via Microsoft Defender for Endpoint when a Critical P1 endpoint alert fires, preventing lateral movement while investigation begins.

## Pre-Conditions (must be confirmed before enabling)
- [ ] Customer has provided written approval for automated device isolation
- [ ] Customer IT team has been briefed on the isolation behaviour
- [ ] MDE is fully onboarded on all in-scope devices
- [ ] Logic App has the correct MDE API permissions (Machine.Isolate)

## Logic App Steps

1. **Trigger:** Sentinel alert created with Severity = High or Critical
2. **Condition:** Alert Rule Name contains `GEN-IA-001` OR `GEN-CA-001` OR `GEN-IM-001` OR `GEN-DE-001` OR `GEN-DE-002`
3. **Action 1:** Extract `DeviceId` from alert entities
4. **Action 2:** Call MDE API: `POST /api/machines/{DeviceId}/isolate` with `IsolationType: Full`
5. **Action 3:** Send notification to SOAR/ITSM with: alert details, device name, isolation time, analyst assigned
6. **Action 4:** Create P1 incident ticket with escalation chain triggered

## Isolation Lift Procedure
Manual only. Analyst must confirm:
- Device has been forensically examined or confirmed clean
- All persistence mechanisms removed
- Account passwords reset if credential compromise suspected
- SOC Manager approval required to lift isolation

Via MDE portal: Device page → Release from isolation
Or via API: `POST /api/machines/{DeviceId}/unisolate`

## Exceptions

Devices that must NOT be auto-isolated without manual review:
- OT/SCADA connected devices — isolation may disrupt live industrial processes
- Medical devices on clinical networks — isolation may affect patient care
- Domain controllers — isolation causes domain-wide authentication disruption

For these device types: **alert-only** mode — analyst manually reviews before isolation.
