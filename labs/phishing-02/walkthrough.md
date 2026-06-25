# Walkthrough: Business Email Compromise — CEO Fraud

## Objective
Determine if the email requesting a wire transfer is a legitimate CEO request or BEC fraud.

---

## Step 1: Email Header Analysis

Open the **Email** tab. Critical indicators:

1. **From header spoofing** — The display From is `ceo@corp.local` but the envelope
   sender is `ceo@corp-mail.biz`. These must match for legitimate email.

2. **DMARC fail despite SPF/DKIM pass** — The DKIM and SPF pass for `corp-mail.biz`,
   but DMARC fails because the `header.from` domain (`corp.local`) doesn't align.
   This is a classic BEC technique: authenticate a lookalike domain, spoof the display From.

3. **Reply-To redirection** — Replies go to `david.miller.ceo@corp-mail.biz` not to
   the real CEO's corporate account. The attacker intercepts all responses.

4. **Urgency + secrecy language** — "confidential", "do NOT discuss with anyone", 
   "time-sensitive by 17:00 today". BEC playbook: create urgency, prevent verification.

---

## Step 2: Verify the CEO's Account

Search auth logs for `david.miller`. The CEO logged in at 08:12 and 13:55 from
his normal workstation (EXEC-DM-01, 10.0.1.5). There is NO email session from 91.108.4.201.

**Conclusion:** The real CEO did not send this email. His account shows normal activity
from the office workstation. The email came from an external attacker.

---

## Step 3: Threat Intel

Look up `91.108.4.201` — returns suspicious/malicious, associated with BEC campaigns.
Look up `corp-mail.biz` — newly registered domain, flagged for impersonation.

---

## Step 4: Verdict

**True Positive — BEC (Business Email Compromise)**

**Escalate to L2** — BEC involving financial fraud is a high-severity incident requiring:
- Immediate contact with the CEO to verify (out-of-band, not via email)
- Finance team notified to halt any wire transfer
- Legal and management notification
- Full forensic investigation of the CEO's email account for potential prior compromise

**MITRE:** T1566.002 (Spearphishing Link — the reply-to harvests responses)

## Key Learning Points

- **Display name vs. envelope sender** — Always check the raw headers, not just the
  display name. Attackers exploit the fact that email clients show the display name.
- **DMARC alignment** — Even a passing SPF/DKIM can fail DMARC if the `header.from`
  domain doesn't align. DMARC failure on an executive email is a BEC red flag.
- **BEC triggers** — Urgency + financial request + secrecy = BEC trifecta.
- **Escalation** — BEC is NOT something L1 closes. Escalate to L2 and management immediately.
