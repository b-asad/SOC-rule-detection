# SEC-TECH-EF-001 — Technology: Source Code Repository Exfiltration

| Field | Value |
|-------|-------|
| **Rule ID** | `SEC-TECH-EF-001` |
| **MITRE Technique** | T1213.003 — Data from Code Repositories |
| **Sector** | Technology |
| **Severity** | **High** | **Priority** | **P1** |
| **MS Tools** | Sentinel · Defender for Cloud Apps |
| **Log Source** | `CloudAppEvents` (MCAS) · Azure DevOps / GitHub audit logs |

## Description
Mass clone or download of source code repositories by a single user, service account, or from an unexpected IP. Nation-state actors and corporate espionage actors specifically target source code repositories to identify vulnerabilities for exploitation or to steal proprietary algorithms. Departing employees cloning repositories before resignation is also a common insider threat scenario.

## Microsoft Sentinel KQL
```kql
// SEC-TECH-EF-001 | Frequency: 15m | Lookback: 1h
CloudAppEvents
| where TimeGenerated >= ago(1h)
| where ActionType in ("git.clone","git.fetch","repo.download","repo.export","RepoCloned","RepositoryExported")
| summarize RepoCount=count(), RepoNames=make_set(tostring(AdditionalFields.RepoName),10)
    by AccountDisplayName, IPAddress, CountryCode, bin(TimeGenerated, 1h)
| where RepoCount > 10
| extend IsExternal = (CountryCode !in (dynamic(["GB","IE","US"])))
| extend AlertTitle = strcat("Source Code Mass Clone: ", RepoCount, " repos by ", AccountDisplayName)
```

## Investigation Guide
**Step 1:** Is this employee under notice or involved in a dispute?
**Step 2:** Which repositories were cloned? Do they contain proprietary algorithms or security-sensitive code?
**Step 3:** Check if data was pushed to an external Git host or personal account.

## Response Actions
- [ ] Revoke repository access
- [ ] Notify Legal / IP Counsel
- [ ] Preserve evidence for potential legal proceedings
- [ ] If nation-state indicators: notify NCSC

## References - [MITRE T1213.003](https://attack.mitre.org/techniques/T1213/003/)
