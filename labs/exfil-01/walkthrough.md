# Walkthrough: Data Exfiltration via DNS Tunneling

## Step 1: Identify the DNS Pattern

Filter logs for `10.0.1.92`. You'll see:
- Queries to `*.dl.bad-payload.ru` with long, random-looking subdomain labels
- TXT record type queries (used to receive data back)
- 4,847 queries in one hour — dramatically abnormal (normal DNS: tens of queries/hour)
- High entropy: 4.82 bits/char (normal domain names score ~2-3 bits/char)

## Step 2: Decode the Subdomains

The subdomain labels are base64-encoded. Decoding some samples:
- `aGVsbG8gd29ybGQ` → `hello world` (test probe)
- `dXNlcm5hbWU6Ym9iLmFk` → `username:bob.ad`
- `bWluX3Bhc3N3b3JkOlBAc3M` → `min_password:P@ss`
- `d2luZG93c19kb21haW46Q09SUC5MT0NBTA` → `windows_domain:CORP.LOCAL`

**The attacker is exfiltrating credential dumps and network reconnaissance data
encoded as base64 in DNS subdomain labels.**

## Step 3: Scope

4,847 DNS queries × ~30 bytes of data per subdomain label = ~145 KB of data exfiltrated.
This is consistent with credential dumps, network maps, and configuration data.

## Verdict
**True Positive — DNS tunneling used to exfiltrate reconnaissance and credential data**

**Escalate to L2** — Part of ongoing intrusion (linked to WS-DEV-09/lateral movement lab).
Block `dl.bad-payload.ru` at DNS resolver immediately.

## MITRE
- T1071.004 (DNS used for C2/exfil)
- T1048 (Exfiltration over alternative protocol)

## Key Learning Points
- **DNS tunneling indicators** — High query volume + high-entropy subdomains + TXT queries
  + non-corporate domain = DNS tunneling fingerprint.
- **Base64 in DNS** — The base64 alphabet (A-Z, a-z, 0-9, +, /) is valid in DNS labels,
  making it the encoding of choice for DNS tunneling.
- **Why DNS?** — Many firewalls allow DNS outbound. Attackers use it as a covert channel
  because it's rarely inspected deeply.
