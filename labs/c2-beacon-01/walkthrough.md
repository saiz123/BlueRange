# Walkthrough: C2 Beaconing — Periodic HTTPS Callbacks

## Step 1: Identify the Beacon Pattern

Filter logs for `10.0.1.92`. You'll see connections to `185.220.101.45:443` at:
- 00:00, 00:05, 00:10, 00:15, 00:20... every 5 minutes, continuously.

**Beacon characteristics:**
- Fixed destination IP (single C2 server)
- Regular interval: exactly 300 seconds ± 2 seconds (minimal jitter)
- Consistent small packet sizes: ~1240 bytes out, ~383 bytes in
- Active 24/7 — including overnight when no user should be working

**Contrast with legitimate traffic** (08:00 onward): irregular intervals, variable sizes,
different destinations. Legitimate apps don't call home every 5 minutes all night.

---

## Step 2: Threat Intel

Look up `185.220.101.45` — returns malicious, tagged as C2 infrastructure.

---

## Step 3: Verdict

**True Positive** — Classic C2 beacon pattern. Regular interval + fixed small size +
unknown destination + 24/7 activity = strong C2 indicator.

**Escalate to L2** — Active implant on WS-DEV-09. Isolate the endpoint immediately,
preserve memory for forensics.

**MITRE:** T1071.001 (Web Protocols used for C2)

## Key Learning Points

- **Beacon = regularity** — Look for fixed intervals. Real user traffic is bursty and irregular.
- **Packet size consistency** — C2 check-ins are small and consistent (heartbeat). Real HTTPS
  traffic varies widely in size.
- **Out-of-hours activity** — Malware doesn't sleep. 3 AM connections from a workstation = red flag.
- **Bytes ratio** — Small outbound (1.2KB = check-in) + small inbound (383B = command) is
  typical C2. Large inbound would indicate data/payload delivery.
