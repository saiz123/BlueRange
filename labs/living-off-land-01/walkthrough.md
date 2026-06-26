# Living-Off-the-Land-01 Walkthrough

## Overview

**True positive.** An attacker used two Windows built-in binaries (`certutil` and `mshta`)
to download, decode, and execute a malicious HTA payload after the user clicked a phishing
link. C2 communication and persistence were established.

## Attack Chain

```
chrome.exe (user click) → cmd.exe
  → certutil -urlcache -f [download payload]   (T1105, T1140)
  → certutil -decode [decode base64]            (T1140)
  → mshta.exe payload.hta                       (T1218.005)
    → powershell.exe -enc [encoded PS]          (T1059.001)
      → C2 beacon to 185.220.101.45:443         (T1071.001)
      → Registry Run key persistence            (T1547.001)
      → Reconnaissance commands
```

## Why LOLBins?

`certutil` and `mshta` are legitimate Microsoft binaries — they bypass application
whitelisting and are often allowed through network proxies. This is "living off the land" —
no custom malware dropped, all execution via trusted system tools.

## Verdict: True Positive — Escalate

Isolate WORKSTATION-05 immediately. Remove persistence key. Block `update-service.xyz`
and `185.220.101.45`. Investigate Teams account that sent the malicious link.
