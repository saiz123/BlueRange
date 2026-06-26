# Cloud-Alert-01 Walkthrough: AWS IAM Privilege Escalation

## Overview

This is a **true positive** cloud account compromise. An attacker used stolen AWS access keys
belonging to developer `jpark` to assume an IAM role, perform privilege escalation by creating
a backdoor admin account, and begin accessing production data.

---

## Step 1 — Identify the Anomaly

The first CloudTrail entry at `08:44:01` shows `GetCallerIdentity` from **Bucharest, Romania
(185.233.102.47)**. James Park works in Austin, TX — his normal source IPs are `71.x.x.x`.

Key red flags:
- Foreign geography (Romania)
- No MFA used on AssumeRole call (normal usage would have MFA)
- Time: 08:44 UTC = 03:44 AM Austin time — outside normal work hours

---

## Step 2 — Trace the Attack Chain

The attacker followed a classic IAM privilege escalation playbook:

```
1. GetCallerIdentity        — verify credentials work
2. AssumeRole (dev-deploy)  — gain broader permissions
3. ListUsers + ListRoles    — map the environment
4. CreateUser backup-svc-acct  — create persistence backdoor
5. AttachUserPolicy AdministratorAccess  — full account takeover
6. CreateAccessKey          — generate persistent credentials
7. DescribeInstances + ListBuckets  — data discovery
8. GetObject (db backup)    — data exfiltration
```

This entire sequence took **4 minutes** — highly automated.

---

## Step 3 — MITRE Mapping

- **T1078.004** — Valid Accounts (Cloud): used jpark's legitimate keys
- **T1548** — Abuse Elevation Control: IAM role assumption without MFA
- **T1580** — Cloud Infrastructure Discovery: ListUsers, ListRoles, DescribeInstances, ListBuckets
- **T1136.003** — Create Cloud Account: `backup-svc-acct` with AdministratorAccess

---

## Step 4 — Verdict

| Decision | Answer |
|---|---|
| Verdict | **True Positive** |
| Severity | **High** |
| Escalate? | **Yes — cloud IR required** |

### Key findings to document:
- jpark's access keys used from foreign IP (Bucharest RO) at 03:44 AM local time
- dev-deploy-role assumed without MFA from attacker IP
- IAM backdoor account `backup-svc-acct` created with AdministratorAccess
- Persistent API keys generated for backdoor account
- Production S3 backup (`db_backup_2026-06-24.sql.gz`) accessed

**Immediate actions:** Disable jpark's access keys, delete `backup-svc-acct` and its keys,
revoke the active dev-deploy-role session, review CloudTrail for further activity.
