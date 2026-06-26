# False-Positive-01 Walkthrough: Vulnerability Scanner Triage

## Overview

This is a **false positive**. The "attack" traffic is an authorized Nessus vulnerability
scan running inside the approved weekly maintenance window. No exploitation occurred.

---

## Key Evidence

1. **User-Agent** is `Nessus/10.4.0` — a known vulnerability scanner, not an attacker tool
2. **Source IP** `10.0.0.200` = `SCAN-SERVER-01` in the CMDB — an internal authorized asset
3. **Maintenance window** is Tuesday 09:00–10:00 UTC — the alert fired at 09:15 on a Tuesday
4. **Web server responses**: all 400/404 — no successful exploitation
5. **Scan completed cleanly** — connections closed, no lateral activity

## Verdict: False Positive — Close

Authorized internal vulnerability scan within approved window. No action required.
Document in ticketing system for audit trail.
