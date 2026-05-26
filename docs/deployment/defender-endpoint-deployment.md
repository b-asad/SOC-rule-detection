# Microsoft Defender for Endpoint — Configuration Guide

## Required MDE Configuration for Rule Effectiveness

### 1. Advanced Features (must be enabled)
Security Center → Settings → Endpoints → Advanced features:
- [x] Endpoint detection and response
- [x] Automated Investigation
- [x] Live Response for servers
- [x] Custom network indicators
- [x] Tamper protection ← **Critical for GEN-DE-001**
- [x] Controlled folder access ← **Critical for GEN-IM-002**
- [x] Block at first sight

### 2. Attack Surface Reduction (ASR) Rules
Enable these ASR rules in **Block** mode (start with **Audit** mode for 14 days):

| ASR Rule | GUID | Rules Supported |
|---------|------|----------------|
| Block Office apps from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | GEN-IA-001 |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | GEN-EX-001 |
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` | GEN-CA-001 |
| Block process creations from PSExec/WMI | `d1e49aac-8f56-4280-b9ba-993a6d77406c` | GEN-EX-002 |
| Block untrusted/unsigned processes from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | GEN-IA-001 |

### 3. Custom Indicators
After identifying C2 IPs/domains from alerts, add to MDE custom indicators:
Security Center → Settings → Endpoints → Indicators → + Add indicator
- File hash → Block + Alert
- IP address → Block + Alert
- URL/Domain → Block + Alert

### 4. Live Response Library
Upload these scripts to the MDE Live Response library for analyst use:
- `collect-process-list.ps1` — dump current process list
- `collect-network-connections.ps1` — active network connections
- `check-persistence.ps1` — enumerate common persistence locations
- `collect-prefetch.ps1` — recent execution evidence

### 5. Device Tagging
Tag all POS and payment devices for RG-CA-001 rule:
- Tag: `POS` — all point-of-sale terminals
- Tag: `PaymentServer` — payment processing servers
- Tag: `CDE` — all cardholder data environment hosts

Apply tags via: Security Center → Device inventory → select device → Manage tags
