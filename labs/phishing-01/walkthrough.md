# Walkthrough: Suspicious Email — Credential Harvest

## Objective
Determine whether the email received by jane.smith@corp.local is a phishing attempt.

---

## Step 1: Examine the Email Headers

Open the **Email** tab and review the .eml file. Key findings:

1. **SPF FAIL** — The email claims to come from `corp-helpdesk.net` but the gateway
   reports: `spf=fail (domain of corp-helpdesk.net does not designate 185.220.101.45
   as permitted sender)`. This is a strong phishing indicator.

2. **No DKIM signature** — `dkim=none`. Legitimate corporate tools almost always sign email.

3. **DMARC fail** — Combined SPF and DKIM failure causes DMARC to fail.

4. **Suspicious sender domain** — `corp-helpdesk.net` is NOT the same as `corp.local`.
   This is a look-alike domain designed to deceive.

5. **Reply-To mismatch** — The reply goes to `support-reply@protonmail.com`, not a
   corporate address. Phishers do this to intercept replies.

6. **Credential-harvest URL** — The link goes to `corp-helpdesk.net/portal/reset` with
   a pre-populated `user` and `token` parameter. Classic credential harvest page pattern.

---

## Step 2: Check the Logs

Open the **Logs** tab and search for `jane.smith` and `185.220.101.45`.

### Auth logs
- `09:24:02Z` — **Successful login from 185.220.101.45 (external IP)** for jane.smith
  with Logon type 3 (Network). This indicates the phisher harvested her credentials
  and used them immediately.
- Three prior failures at 09:23 suggest the attacker was testing credentials.

### Proxy logs
- `09:24:08Z` — Jane's workstation (10.0.1.42) **visited the phishing page** and it
  returned 200 with 4821 bytes (a form page).
- `09:24:10Z` — A **POST to /portal/reset/submit** with 148 bytes body — this is
  the credential submission. Jane entered her password into the phishing form.

### DNS logs
- The domain `corp-helpdesk.net` was only **registered 11 days ago** — newly registered
  domains are a major phishing signal.

---

## Step 3: Threat Intel

Open the **Threat Intel** tab and look up `185.220.101.45`. The local intel service
will return **malicious** — this IP is a known phishing infrastructure address.

Also look up `corp-helpdesk.net` — also returns malicious with "newly-registered" and
"phishing" tags.

---

## Step 4: Verdict

**True Positive** — This is a confirmed phishing email that successfully harvested
jane.smith's credentials.

Evidence chain:
- SPF fail + no DKIM + look-alike domain = phishing email
- User clicked the link (proxy log 09:24:08)
- User submitted credentials (POST to /submit, 09:24:10)
- External login success from 185.220.101.45 at 09:24:02 = credentials used immediately

**MITRE:** T1566.001 (Spearphishing — no attachment but link-based)
Technically T1566.002 would be more precise for a link-only phish, but T1566.001
is commonly applied at L1 for any spearphishing. Tag T1078 as the attacker gained
valid credentials.

**Escalation:** Close. L1 actions:
1. Block sender domain `corp-helpdesk.net` and IP `185.220.101.45`
2. Force password reset for jane.smith immediately
3. Check for any actions taken under her account between 09:24 and detection
4. Notify jane.smith and her manager
5. Check if other users received the same email

---

## Key Learning Points

- **SPF/DKIM/DMARC** — three complementary email authentication mechanisms. Failure
  of any is suspicious; combined failure is a red flag.
- **Look-alike domains** — attackers register domains that visually resemble the target
  (corp-helpdesk.net vs corp.local). Check domain age.
- **Credential harvest pattern** — form page + POST = credential submission. Correlate
  with auth logs for same-time logins from external IPs.
- **The full kill chain** — email receipt → link click → form submission → credential
  use. Each step should be documented in your write-up.
