# Walkthrough: SQL Injection via Web Application

## Key Findings

1. **Initial reconnaissance** — 11:40 shows normal browsing of the portal.
2. **Basic SQLi probe** — `1' OR '1'='1` — WAF blocked, but attacker adapted.
3. **UNION-based extraction** — `UNION SELECT username,password,email FROM users` —
   WAF initially alerted but the attacker bypassed it (response grew from 91KB to 148KB to 284KB).
4. **Payment data extraction** — `UNION SELECT cc_number,expiry,cvv FROM payment_info` —
   412KB response suggests successful credit card data dump.
5. **Data export** — The final POST to `/export?format=csv` transferred **2.8 MB** to the
   external IP. This is the exfiltration event.

## Verdict
**True Positive** — Confirmed SQLi with successful data exfiltration of user credentials
and payment card data. This is a **critical** incident.

**Escalate to L2** — Potential PCI-DSS breach requires immediate escalation to L2, legal,
and compliance team.

## MITRE
T1190 (Exploit Public-Facing Application) — SQLi is the exploitation vector.

## Key Learning Points
- **Byte count escalation** — Watch response sizes. 91KB → 148KB → 284KB means more data
  was returned each time. Growing responses = successful extraction.
- **WAF bypass** — WAF blocking ≠ attack stopped. Monitor for follow-on requests after blocks.
- **UNION SELECT** — The canonical SQLi data extraction technique. The table names in the
  query tell you exactly what data was targeted.
