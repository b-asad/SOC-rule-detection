# SEC-TECH-PV-001 — Technology: Privilege Escalation on Developer/Cloud Host

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-TECH-PV-001` |
| **MITRE Tactic** | Privilege Escalation |
| **Sector** | **Technology** |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Regulatory** | SOC 2, ISO 27001 |

## Description
UAC bypass or privilege escalation on a developer workstation, build server, or cloud management host. Technology companies face elevated risk from this technique because developer machines typically have elevated privileges, access to secrets vaults, and ability to push to production pipelines. Privilege escalation on a build server is a supply chain attack vector.

**Deploy alongside GEN-PV-001** — this rule adds Technology sector host scope and routes alerts to the DevSecOps escalation path.

## Sentinel KQL — Sector Scope



## Sector Context

Privilege escalation on a CI/CD build host (Jenkins, GitHub Actions runner, GitLab CI) is particularly high risk:
- Elevated process can inject malicious code into the build pipeline
- Access to secrets and deployment credentials
- Can push signed artifacts to production

## Response Actions
- [ ] Isolate the affected development/build host
- [ ] Rotate all secrets accessible from the host (AWS keys, API tokens, signing certs)
- [ ] Audit recent pipeline runs for potential code injection
- [ ] Notify DevSecOps lead and CISO

## References
- Base rule: GEN-PV-001 | [MITRE T1548.002](https://attack.mitre.org/techniques/T1548/002/)
