# Walkthrough: RDP Password Spray Attack

## Objective
Identify whether this is a password spray attack and determine if any accounts were compromised.

---

## Step 1: Identify the Spray Pattern

In the **Logs** tab, search for `203.0.113.88`. You'll see:
- Many 4625 (failed logon) events from the SAME source IP
- Targeting DIFFERENT accounts (jane.smith, john.doe, sarah.chen, etc.)
- Only 2-second intervals between attempts

**This is the password spray signature:** one password tried against many accounts,
rather than many passwords tried against one account (brute force). Spray avoids account
lockout thresholds.

---

## Step 2: Find the Successful Login

Filter for `4624` (success). At `22:14:00Z`, the account `svc.backup` successfully
authenticated from `203.0.113.88` via RDP. This is the compromised account.

Service accounts like `svc.backup` often have weak or default passwords and are
prime spray targets because they rarely trigger alerts.

---

## Step 3: Post-Compromise Activity

At `22:14:22Z`: the attacker used `svc.backup` to access `ADMIN$` and `C$` shares.
This indicates immediate lateral movement or enumeration.

---

## Step 4: Threat Intel

Look up `203.0.113.88` — returns malicious, tagged as known spray/scanner.

---

## Step 5: Verdict

**True Positive — Password Spray with successful account compromise**

**Escalate to L2** — A compromised service account with admin share access is a
high-severity incident requiring L2 involvement for:
- Full scope assessment (what did the attacker access?)
- Memory forensics on the RDP gateway
- Credential reset for all potentially sprayed accounts
- Sweep for additional compromised accounts

**MITRE:** T1110.003 (Password Spraying), T1021.001 (RDP), T1078 (Valid Accounts)

## Key Learning Points

- **Spray vs. brute force** — Same IP, many accounts = spray. Same account, many IPs = brute.
  Spray evades lockout; brute force evades geo-blocking.
- **Service accounts** — High-value targets due to weak passwords and less monitoring.
- **4625 → 4624 correlation** — Always check if any spray succeeded. One success changes everything.
- **Post-auth actions** — ADMIN$ / C$ access = attacker moving laterally. Escalate immediately.
