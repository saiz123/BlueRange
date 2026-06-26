# Insider-Threat-01 Walkthrough: Anomalous HR File Access

## Overview

This is a **true positive** insider threat incident. A soon-to-depart HR analyst bulk-accessed
and exfiltrated 1,847 employee records including salary data to a personal USB drive before
their last day.

---

## Step 1 — Review the UEBA Alert Context

The alert says:
- User **mwilson** accessed 1,847 HR records in 90 minutes
- Her daily baseline is ~46 records/day
- She **submitted resignation two weeks ago**
- A USB device was connected during the access window

The combination of resignation + bulk access + USB is the classic insider theft trifecta.

---

## Step 2 — Trace the Timeline

| Time | Event |
|---|---|
| 12:50 | Normal login |
| 13:05 | USB (SanDisk Ultra) connected |
| 13:05–13:22 | 505 files copied to USB |
| 13:45 | UEBA risk score elevated: 1,840% above baseline |
| 14:11 | Full salary CSV export (1,847 records, 2.4 MB) |
| 14:12 | Salary CSV copied to USB |
| 14:22 | Alert fires |
| 14:23 | USB disconnected; user logs out |

The timing is deliberate — she waited for the CSV export, then immediately copied it to USB
and disconnected.

---

## Step 3 — MITRE Mapping

- **T1078** — Valid Accounts: used her own legitimate credentials
- **T1052.001** — Exfiltration over USB: files written to removable media
- **T1083** — File and Directory Discovery: browsed HR portal for salary exports
- **T1048** — Exfiltration over Alternative Protocol (if emailed externally)

---

## Step 4 — Verdict

| Decision | Answer |
|---|---|
| Verdict | **True Positive** |
| Severity | **High** |
| Escalate? | **Yes — escalate to HR, Legal, and Security** |

### Key findings to document:
- 1,847 HR/salary records accessed in 90 minutes (1,840% above baseline)
- USB device (SanDisk Ultra, S/N 4C5312A0) connected and removed
- 3.8 GB exfiltrated to USB during session
- User has active resignation on file (submitted 2 weeks ago)
- Activity occurred during normal business hours using valid credentials

Escalate to HR and Legal for preservation of evidence. The USB device should be
recovered if possible before the employee's final day.
