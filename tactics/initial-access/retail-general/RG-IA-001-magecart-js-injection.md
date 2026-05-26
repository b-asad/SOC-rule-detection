# RG-IA-001 — Magecart: Checkout JavaScript Modification

| Field | Value |
|-------|-------|
| Rule ID | RG-IA-001 |
| Tactic | Initial Access / Collection |
| Technique | T1195.002 — Supply Chain Compromise |
| Sector | **Retail General** |
| Severity | **Critical** | Priority | **P1** |
| MS Tools | Sentinel · Defender for Endpoint |
| Log Source | `DeviceFileEvents` (MDE), Azure WAF / `AzureDiagnostics` |
| Retail Context | eCommerce checkout pages, payment forms |

## Description
Detects modification of JavaScript files on checkout/payment pages — the primary delivery mechanism for Magecart-style web skimming attacks. Any modification to checkout JS outside of a CI/CD deployment pipeline is a potential card-skimmer injection. **PCI DSS breach event.**

---

## Microsoft Sentinel KQL
```kql
// RG-IA-001 | Frequency: 5m | Lookback: 5m
DeviceFileEvents
| where TimeGenerated >= ago(5m)
| where FileName endswith ".js" or FileName endswith ".min.js"
| where FolderPath has_any ("checkout","payment","cart","basket","pay","order")
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName !in~ ("git","node","npm","deploy_agent","jenkins","octopus","AzureDevOps")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

---

## Defender for Endpoint — File Integrity via MDE
Enable **File Integrity Monitoring** on web server hosts in MDE:
MDE → Configuration management → Security baselines → Web server FIM policy

Alternatively configure FIM via Microsoft Defender for Servers (Defender for Cloud).

---

## Defender for Cloud Apps — CASB WAF Anomaly
```kql
// Anomalous POST from checkout page to external domain
AzureDiagnostics
| where TimeGenerated >= ago(1h) and Category == "ApplicationGatewayAccessLog"
| where requestUri_s has_any ("/checkout","/payment","/order","/basket","/pay")
| where httpMethod_s == "POST"
| where serverRouted_s !has "<CUSTOMER_DOMAIN>"
| project TimeGenerated, clientIP_s, requestUri_s, serverRouted_s, sentBytes_d, userAgent_s
```

---

## Investigation Guide

**Step 1 — Confirm Modification (< 10 min)**  
Pull the modified file. Compare SHA256 to last CI/CD deployment hash.  
Search the file for: external `src=` URLs, `document.querySelector` on payment fields, `fetch()`/`sendBeacon()` to external domains, base64-encoded strings.

**Step 2 — Determine Injection Timeline**  
When was the file modified? Count all checkout sessions since that time — all customer card data is potentially exposed.

**Step 3 — Identify Injection Vector**  
Check CMS admin login logs around the modification time.  
Review third-party plugin versions — supply chain via plugin is the most common vector.

**Step 4 — PCI DSS Assessment**  
Is the page PCI DSS in-scope? Is it P2PE protected?  
If in-scope and no P2PE: **card data breach — mandatory notification.**

---

## Response Actions
- [ ] Take checkout page offline — replace with maintenance page
- [ ] Restore JS from last known-good CI/CD deployment
- [ ] Block exfiltration domain at WAF and DNS
- [ ] Notify customer PCI Security Manager and acquiring bank within 24h
- [ ] Preserve web server logs and skimmer code as forensic evidence
- [ ] Implement CSP (Content-Security-Policy) headers blocking inline scripts
- [ ] Enable Subresource Integrity (SRI) for all third-party scripts

## False Positives
| Scenario | Mitigation |
|----------|-----------|
| Authorised developer hotfix deployed manually | Enforce CI/CD-only deployments; all manual changes trigger review |
| CMS auto-update of plugin | Disable auto-update on payment page plugins |

## References
- [MITRE T1195.002](https://attack.mitre.org/techniques/T1195/002/)
- [PCI DSS: Web skimming FAQ](https://www.pcisecuritystandards.org)
- [NCSC: Magecart advisory](https://www.ncsc.gov.uk/guidance/website-security)
