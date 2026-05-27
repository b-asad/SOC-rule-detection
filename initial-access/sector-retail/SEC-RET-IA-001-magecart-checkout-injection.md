# SEC-RET-IA-001 — Retail: Magecart Checkout JavaScript Injection

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-RET-IA-001` |
| **MITRE Tactic** | Initial Access / Collection |
| **MITRE Technique** | T1195.002 — Supply Chain Compromise |
| **Sector** | **Retail** |
| **Severity** | **Critical** |
| **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Endpoint |
| **Log Source** | `DeviceFileEvents` (MDE) · `AzureDiagnostics` (WAF) |
| **Sector Context** | eCommerce checkout pages, payment forms, online retail platforms |
| **Created** | May 2026 |

---

## Description

Detects modification of JavaScript files on eCommerce checkout/payment pages — the primary delivery mechanism for Magecart-style web skimming attacks that capture customer payment card data at point of entry. Any modification to checkout JavaScript outside a known CI/CD pipeline deployment is a potential card skimmer injection. This is a **PCI DSS in-scope breach event**.

---

## Microsoft Sentinel KQL

```kql
// SEC-RET-IA-001 | Frequency: 5m | Lookback: 5m | Threshold: > 0
DeviceFileEvents
| where TimeGenerated >= ago(5m)
| where (FileName endswith ".js" or FileName endswith ".min.js")
| where FolderPath has_any (
    "checkout","payment","cart","basket","pay",
    "order","billing","purchase","shop"
)
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName !in~ (
    "git","node","npm","yarn","deploy_agent",
    "jenkins","octopus","AzureDevOps","TeamCity","github-actions"
)
| project
    TimeGenerated, DeviceName, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| extend AlertTitle = strcat("Checkout JS Modified Outside CI/CD: ", FileName)
| extend PCIRisk = "Possible card skimmer injection. PCI DSS breach if payment data captured."
| extend ImmediateAction = "Take checkout page offline immediately. Compare file hash with last deployment."
```

---

## Defender for Endpoint — WAF Anomaly

```kql
// Detect POST from checkout page to unexpected external domain (data exfiltration)
AzureDiagnostics
| where TimeGenerated >= ago(1h)
| where Category == "ApplicationGatewayAccessLog"
| where requestUri_s has_any ("/checkout","/payment","/order","/basket","/pay")
| where httpMethod_s == "POST"
| where serverRouted_s !has "<CUSTOMER_ECOMMERCE_DOMAIN>"
| project TimeGenerated, clientIP_s, requestUri_s, serverRouted_s, sentBytes_d, userAgent_s
| extend Alert = "POST from checkout page to unexpected destination — possible card data exfiltration"
```

---

## Investigation Guide

**Step 1 — Confirm File Modification (< 10 min)**
Pull the modified file and compare SHA256 to the last CI/CD deployment hash.
Inspect the file content: look for external `src=` URLs, `document.querySelector` targeting payment fields (`card-number`, `cvv`, `expiry`), `fetch()` or `XMLHttpRequest` to external domains, and obfuscated/base64-encoded strings.

```bash
# Quick grep for external domains in checkout JS
grep -E "(fetch|XMLHttpRequest|sendBeacon)" checkout.js | grep -v "<CUSTOMER_CDN_DOMAIN>"
```

**Step 2 — Injection Timeline (10–25 min)**
When was the file modified? Count all customer checkout sessions between injection time and now — these customers' card data may be compromised.

**Step 3 — Injection Vector (25–40 min)**
Check CMS admin logs around the modification time. Review third-party plugin versions. Supply chain attacks via plugins are the most common vector.

---

## Response Actions
**Immediate**
- [ ] Take checkout page offline — replace with maintenance page
- [ ] Restore JavaScript from last known-good CI/CD deployment
- [ ] Block the exfiltration domain in WAF and DNS
- [ ] Notify customer PCI Security Manager
- [ ] Notify acquiring bank within 24h

**Medium-term**
- [ ] Implement Content Security Policy (CSP) headers blocking inline scripts and external destinations
- [ ] Implement Subresource Integrity (SRI) for all third-party scripts
- [ ] Enable File Integrity Monitoring on all web server JS files

## References
- [MITRE T1195.002](https://attack.mitre.org/techniques/T1195/002/)
- [PCI DSS: Web skimming guidance](https://www.pcisecuritystandards.org)
- [NCSC: Website security](https://www.ncsc.gov.uk/guidance/website-security)
