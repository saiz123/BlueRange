# BlueRange

A self-hosted SOC Analyst Tier-1 training platform. Investigate realistic simulated alerts end-to-end — triage, analysis, verdict, escalation, and write-up — exactly like a real SOC queue.

**Runs comfortably on 2 vCPU / 2 GB RAM. Works fully offline after image pull.**

---

## Quick Start

```bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env — at minimum change ADMIN_PASS

# 2. Start
docker compose up -d

# 3. Open in browser
http://localhost:8080
```

Login with the username/password you set in `.env` (defaults: `admin` / `changeme`).

---

## Hardware Requirements

| Resource | Minimum | Comfortable |
|---|---|---|
| RAM | 512 MB | 1 GB |
| CPU | 1 vCPU | 2 vCPU |
| Disk | 500 MB | 2 GB |
| Network | None (offline) | Optional for updates |

---

## Putting BlueRange Behind Cloudflare Tunnel / Tailscale

BlueRange listens on `http://localhost:8080`. Do **not** expose port 8080 publicly.

### Cloudflare Tunnel
```bash
cloudflared tunnel --url http://localhost:8080
```
Or configure a named tunnel in your Cloudflare dashboard pointing to `http://localhost:8080`.

### Tailscale
No configuration needed — BlueRange is only accessible to Tailscale peers by default
when the port is not mapped to `0.0.0.0`. For Tailscale-only access:
```yaml
# docker-compose.yml — bind only to Tailscale interface
ports:
  - "100.x.x.x:8080:8080"  # replace with your Tailscale IP
```

---

## Backing Up the SQLite Database

```bash
# Stop the container first (or use WAL checkpoint)
docker compose stop app

# Copy the database file
cp data/bluerange.db data/bluerange.db.backup-$(date +%Y%m%d)

# Or use SQLite's online backup (safe while running)
sqlite3 data/bluerange.db ".backup data/bluerange.db.backup"

docker compose start app
```

---

## Authoring a New Lab

1. Create a folder: `labs/<lab-id>/`
2. Create `labs/<lab-id>/lab.yaml` following the schema below
3. Add evidence files:
   - `logs/*.json` — one JSON log entry per line (newline-delimited JSON)
   - `email/*.eml` — raw email files for the email panel
   - `artifacts/*.json` — sandbox reports, process dumps, etc.
4. Create `labs/<lab-id>/walkthrough.md` — step-by-step solution
5. Restart: `docker compose restart app`

### `lab.yaml` Schema

```yaml
id: my-lab-01              # unique, used in URLs
title: "Alert Title"
difficulty: intro          # intro | core | realistic
category: phishing         # phishing | brute-force | web-attack | malware | c2 | lateral-movement | data-exfil | multi-stage
tags: [tag1, tag2]

mitre:
  - id: T1566.001
    name: "Phishing: Spearphishing Attachment"

alert:
  severity: medium         # critical | high | medium | low | info
  source: email-gateway    # displayed in the alert queue
  rule: "Rule name shown to learner"
  triggered_at: "2024-01-01T09:00:00Z"
  src_ip: "192.168.1.1"   # optional
  recipient: "user@corp"   # optional

scenario: >
  Written scenario shown to the learner before they start the investigation.

# Words the grader looks for in the learner's rationale (case-insensitive)
rationale_keywords:
  - "keyword1"
  - "keyword2"

rubric:
  expected_verdict: true_positive   # true_positive | false_positive
  expected_escalation: close        # close | escalate
  required_mitre: [T1566.001]
  score_breakdown:
    correct_verdict:   40
    required_findings: 30
    correct_mitre:     20
    writeup_quality:   10
  passing_score: 70
```

### Log File Format

Each log file under `logs/` should be newline-delimited JSON. Recognized fields:

```json
{"timestamp":"2024-01-01T09:00:00Z","level":"warn","host":"hostname","message":"log line here"}
```

Fields `ts`, `time`, `severity`, `hostname`, `msg` are also recognized as aliases.
Any valid JSON line is stored and searchable — extra fields are preserved in the raw column.

---

## Lab Catalog

| ID | Title | Difficulty | Category |
|---|---|---|---|
| phishing-01 | Suspicious Email — Credential Harvest | Intro | Phishing |
| phishing-02 | Business Email Compromise — CEO Fraud | Core | Phishing |
| brute-force-01 | RDP Password Spray Attack | Intro | Brute Force |
| web-attack-01 | SQL Injection via Web Application | Core | Web Attack |
| malware-01 | Malware Triage — Suspicious Executable | Core | Malware |
| c2-beacon-01 | C2 Beaconing — Periodic HTTPS Callbacks | Core | C2 |
| lateral-01 | Lateral Movement via WMI and Admin Shares | Realistic | Lateral Movement |
| exfil-01 | Data Exfiltration via DNS Tunneling | Realistic | Data Exfil |
| multi-stage-01 | Multi-Stage Intrusion — Full Kill Chain | Realistic | Multi-Stage |

---

## Architecture

- **Backend:** Go (single binary, `~15 MB`)
- **Frontend:** Alpine.js + htmx (vendored, no CDN dependency)
- **Storage:** SQLite with WAL mode + FTS5 for log search
- **Auth:** argon2id password hashing, server-side session tokens
- **Deploy:** Single Docker container + volume mounts

---

## Contributing / Lab Authoring Guide

See the `lab.yaml` schema above. A minimal lab needs:
- `lab.yaml` with all required fields
- At least one `logs/*.json` file with realistic log data
- A `walkthrough.md` explaining the investigation step by step

The grader is keyword-based — choose `rationale_keywords` that are specific enough
to require real investigation but broad enough that a correct write-up will include them.

To test a new lab: restart the container and complete it yourself in exam mode.
If you can score ≥ 70 with a correct investigation, the lab is ready.
