# GEN-IM-003 — Impact: Resource Hijacking (Cryptomining)

| Field | Value |
|-------|-------|
| **Rule ID** | `GEN-IM-003` |
| **MITRE Tactic** | Impact |
| **MITRE Technique** | T1496 — Resource Hijacking |
| **Sector** | Generic — All Customers |
| **Severity** | **Medium** |
| **Priority** | **P2** |
| **MS Tools** | Sentinel · Defender XDR · Defender for Endpoint |
| **Log Source** | `DeviceNetworkEvents` · `DeviceProcessEvents` (MDE) |
| **Created** | May 2026 |

---

## Description

Cryptomining malware using victim compute resources. Indicators: connections to known mining pool domains/IPs, Stratum protocol traffic (TCP 3333, 4444, 5555, 7777, 14444), execution of known miner binaries (XMRig, NiceHash, PhoenixMiner), and sustained high CPU with associated outbound network connections.

---

## Microsoft Sentinel KQL

```kql
// GEN-IM-003 | Frequency: 15m | Lookback: 1h
let MiningPools = dynamic([
    "xmrig.com","monerohash.com","supportxmr.com","nanopool.org",
    "f2pool.com","nicehash.com","minergate.com","unmineable.com",
    "pool.hashvault.pro","xmr.pool.minergate.com","mine.xmrig.com",
    "mining.bitcoin.cz","solo.ckpool.org"
]);
let MiningBinaries = dynamic([
    "xmrig.exe","xmr-stak.exe","nheqminer.exe","nicehash.exe",
    "minergate.exe","phoenixminer.exe","claymore.exe","t-rex.exe",
    "gminer.exe","nbminer.exe","lolminer.exe","trex.exe"
]);
let MiningPorts = dynamic([3333,4444,5555,7777,14444,45700,80,443]);
// Detection A: Known mining pool connection
let PoolConnection = (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(1h)
    | where RemoteUrl has_any (MiningPools) or RemoteIP has_any (MiningPools)
    | where RemotePort in (MiningPorts)
    | project TimeGenerated, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
    | extend DetectionType = "MiningPoolConnection"
);
// Detection B: Known miner binary execution
let MinerExec = (
    DeviceProcessEvents
    | where TimeGenerated >= ago(1h)
    | where FileName in~ (MiningBinaries)
        or ProcessCommandLine has_any ("--pool","--mining-pool","stratum+tcp","xmrig","monero","cryptonight")
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
    | extend DetectionType = "MinerBinaryExecution"
);
PoolConnection | union MinerExec
| extend AlertTitle = strcat("Cryptomining: ", DetectionType, " on ", DeviceName)
```

---

## Investigation Guide

**Step 1:** Is the miner a standalone deployment or part of a broader compromise?
Mining malware is often deployed post-exploitation alongside other malware.
**Step 2:** Check for other indicators — was the initial access via vulnerability exploit (GEN-IA-004) or phishing?
**Step 3:** Are cloud resources also affected? Check Azure/cloud billing for unusual compute spikes.

---

## Response Actions
- [ ] Kill the mining process via MDE Live Response
- [ ] Remove the miner binary
- [ ] Block mining pool domains/IPs
- [ ] Patch the vulnerability used for initial access
- [ ] Check cloud billing for unauthorised resource usage

## References - [MITRE T1496](https://attack.mitre.org/techniques/T1496/)
