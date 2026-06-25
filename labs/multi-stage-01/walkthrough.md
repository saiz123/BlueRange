# Walkthrough: Multi-Stage Intrusion — Full Kill Chain

This is the most complex lab. Your job is to trace the full attack timeline and
document every stage — this is exactly what a real L1 shift handoff report looks like.

---

## Attack Timeline (MITRE Kill Chain)

| Time | Stage | Host | Event | MITRE |
|---|---|---|---|---|
| 06/28 09:14 | Initial Access | WS-JD-02 | Phishing email → Word macro execution | T1566.001 |
| 06/28 09:14 | Execution | WS-JD-02 | PowerShell drops `svchost32.exe` | T1059.001 |
| 06/28 09:14+ | C2 | WS-JD-02 | Beaconing to C2 server | T1071.001 |
| 06/29 02:10 | Credential Access | WS-JD-02 | LSASS dump via procdump | T1003.001 |
| 06/29 02:11 | Lateral Movement | WS-JD-02 → DC01 | WMI remote execution | T1047 |
| 06/29 02:20 | Credential Access | DC01 | ntdsutil NTDS.dit extraction (ALL hashes) | T1003.002 |
| 06/30 04:00 | Exfiltration | WS-JD-02 | DNS tunneling (5200 queries/hr, 156 KB) | T1048 / T1071.004 |

---

## Critical Finding: NTDS.dit Extraction

At 02:20 on DC01, `ntdsutil.exe` was used to extract a full backup of `NTDS.dit` —
the Active Directory database containing password hashes for **every account in the domain**.

This means the attacker has (or had access to) all domain hashes, enabling:
- Pass-the-hash attacks against any domain system
- Offline cracking of all user passwords
- Kerberos Golden Ticket creation

**This is a full domain compromise. L2 response alone is insufficient —
this requires incident commander invocation.**

---

## Affected Systems & Accounts
- WS-JD-02 (patient zero, john.doe's workstation)
- DC01 (domain controller — critical)
- john.doe (initial compromised account — domain user)
- All domain accounts (NTDS.dit extracted)

---

## Verdict
**True Positive — Full multi-stage intrusion with domain-level compromise**

**Escalate IMMEDIATELY** — Domain controller compromise + full NTDS.dit extraction.
This is a Severity 1 incident requiring:
1. Isolation of WS-JD-02 and DC01
2. Emergency password reset for ALL domain accounts (krbtgt twice, then all users)
3. Incident commander activation
4. Legal/compliance notification (potential data breach)
5. Full forensic imaging of both systems

## Key Learning Points
- **The kill chain** — Initial access → execution → persistence → C2 → credential access
  → lateral movement → exfiltration. Document each phase separately.
- **NTDS.dit = domain game over** — Any detection of ntdsutil in logs should trigger
  maximum response regardless of other context.
- **Time correlation** — Events span 72 hours. SIEM correlation rules are what surfaced
  this; human analysts must reconstruct the timeline once alerted.
- **L1 role** — You document the timeline, scope the impact, and escalate clearly.
  You do NOT try to contain this alone.
