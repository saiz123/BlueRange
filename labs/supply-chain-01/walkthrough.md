# Supply-Chain-01 Walkthrough

## Overview

**True positive — supply chain attack.** The npm package `react-date-utils@2.3.1`
was recently updated to include a malicious `postinstall.js` that harvests environment
variables (AWS keys, GitHub tokens) and exfiltrates them to attacker infrastructure.

## Key Evidence

1. **Suspicious timing**: v2.3.1 published just 3 hours ago; previous version 3 months old
2. **New postinstall script**: v2.2.8 had no postinstall — v2.3.1 adds `postinstall.js`
3. **Base64 payload**: decoded to `{hostname, user, env:{AWS_ACCESS_KEY_ID, GITHUB_TOKEN...}}`
4. **Exfil destination**: `collect.malicious-stats[.]io` on known threat actor IP `185.220.101.88`
5. **Data at risk**: AWS credentials + GitHub token belonging to developer `jkim`

## MITRE

- **T1195.001** — Supply chain compromise via package dependency
- **T1059.007** — JavaScript postinstall script execution  
- **T1048** — Exfiltration of credentials in POST body

## Response

1. Revoke jkim's AWS keys and GitHub token **immediately**
2. Block `collect.malicious-stats[.]io` / `185.220.101.88` at firewall/proxy
3. Audit all systems where `react-date-utils@2.3.1` was installed
4. Report to npm security team for package takedown
5. Escalate to IR — assess if exfiltration succeeded on any unblocked endpoints
