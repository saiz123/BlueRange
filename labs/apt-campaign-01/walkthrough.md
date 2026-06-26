# APT-Campaign-01 Walkthrough: Full Kill Chain

## Overview

**True positive — active APT intrusion.** A spearphishing email with a malicious macro
document gave an attacker initial access to the CFO's workstation. Over 6 hours they
established C2, dumped credentials, moved laterally to the Finance server with domain
admin privileges, and exfiltrated 14.4GB of financial data.

---

## Kill Chain Reconstruction

| Time | Phase | Action |
|---|---|---|
| 13:31 | Initial Access | Spearphishing email with macro-enabled .docm |
| 13:35 | Execution | Macro runs PowerShell download cradle (T1059.001) |
| 13:36 | C2 | HTTPS beacon to 185.220.101.45 every 60s (T1071.001) |
| 13:36 | Credential Access | LSASS dump via procdump64 (T1003.001) |
| 13:37 | Exfiltration | lsass.dmp (148MB) sent to C2 (T1041) |
| 18:22 | Lateral Movement | RDP to FINANCE-SERVER-01 as svc_finance (T1021.001) |
| 18:23 | Collection | robocopy copies entire Finance share (14GB) |
| 19:40 | Exfiltration | 14.2GB Finance data uploaded to C2 (T1041) |

---

## MITRE Coverage

All 6 required techniques must be tagged. This lab covers the **full Cyber Kill Chain**:
Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions

---

## Verdict: True Positive — Escalate Immediately

**IR Priority: P1** — Active breach with confirmed data exfiltration.

Immediate actions:
1. Isolate WORKSTATION-CFO-02 and FINANCE-SERVER-01 from network
2. Revoke svc_finance credentials and all sessions
3. Block 185.220.101.45 at perimeter firewall
4. Preserve memory/disk forensic images before remediation
5. Notify legal/compliance of 14.4GB financial data breach
6. Engage IR team and notify CISO
