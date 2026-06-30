package handler

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/bluerange/bluerange/internal/auth"
)

// ── Question bank ─────────────────────────────────────────────────────────────

type interviewQuestion struct {
	ID       string
	Category string // technical | behavioral | scenario | tools
	Question string
	Keywords []string // answer checked for these; fraction matched = score
	Model    string   // shown in result
	LabHint  string   // lab ID to suggest when answer is weak
	Skill    string   // skill key for gap analysis
}

var questionBank = []interviewQuestion{
	// ── Technical ──────────────────────────────────────────────────────────────
	{
		ID: "tech-01", Category: "technical",
		Question: "What are the three pillars of the CIA Triad and how does each apply to everyday SOC work?",
		Keywords: []string{"confidentiality", "integrity", "availability", "triad"},
		Model:    "Confidentiality — preventing unauthorised access (e.g., encrypting data, access controls). Integrity — ensuring data hasn't been tampered with (e.g., file hashing, audit logs). Availability — keeping systems reachable (e.g., DDoS mitigation, backups). In SOC, every alert maps to at least one pillar.",
		Skill:    "incident_response",
	},
	{
		ID: "tech-02", Category: "technical",
		Question: "What is the difference between an Indicator of Compromise (IOC) and a Tactic, Technique, or Procedure (TTP)? Give one example of each.",
		Keywords: []string{"indicator", "compromise", "tactic", "technique", "procedure", "behavior", "hash", "ip", "mitre"},
		Model:    "An IOC is a specific, observable artefact — e.g., a malicious file hash or C2 IP address. A TTP describes how a threat actor operates — e.g., T1059 (scripting for execution). IOCs expire quickly; TTPs persist because behaviour changes slowly. MITRE ATT&CK catalogues TTPs.",
		LabHint:  "malware-01",
		Skill:    "threat_intel",
	},
	{
		ID: "tech-03", Category: "technical",
		Question: "Explain what lateral movement is. Name two techniques and two log sources you would use to detect it.",
		Keywords: []string{"lateral", "movement", "pass-the-hash", "rdp", "smb", "event", "4624", "sysmon", "logon"},
		Model:    "Lateral movement is when an attacker pivots from one compromised system to others. Techniques: Pass-the-Hash (T1550.002) and Remote Desktop Protocol (T1021.001). Detection sources: Windows Security Event ID 4624 (successful logon with type 3/10) and Sysmon Event ID 3 (network connections from unusual processes).",
		LabHint:  "lateral-01",
		Skill:    "network",
	},
	{
		ID: "tech-04", Category: "technical",
		Question: "What is a SIEM? What does it do and why is it central to SOC operations?",
		Keywords: []string{"siem", "security information", "event management", "log", "correlation", "alert", "splunk", "sentinel", "qradar"},
		Model:    "A SIEM (Security Information and Event Management) aggregates logs from across the environment, normalises them, and applies correlation rules to generate alerts. It is the SOC's primary visibility tool. Examples: Microsoft Sentinel, Splunk, IBM QRadar. Without a SIEM analysts would have to check each log source manually.",
		Skill:    "log_analysis",
	},
	{
		ID: "tech-05", Category: "technical",
		Question: "What is the difference between a false positive and a false negative in alert triage? Which is more dangerous and why?",
		Keywords: []string{"false positive", "false negative", "benign", "missed", "real threat", "alert fatigue"},
		Model:    "A false positive is an alert that fires on benign activity — wasted analyst time. A false negative is a real threat that generates no alert — it goes undetected. False negatives are more dangerous because attackers can dwell undetected. False positives cause alert fatigue, which ironically can lead to real threats being ignored.",
		Skill:    "incident_response",
	},
	{
		ID: "tech-06", Category: "technical",
		Question: "What is MITRE ATT&CK? How would you use it during an investigation?",
		Keywords: []string{"mitre", "attack", "tactic", "technique", "matrix", "threat actor", "mapping", "detection"},
		Model:    "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. During an investigation I use it to: (1) map observed behaviour to a technique ID, (2) understand what other techniques usually follow in the attack chain, and (3) communicate findings in a standard language that other teams understand.",
		LabHint:  "apt-campaign-01",
		Skill:    "mitre",
	},
	{
		ID: "tech-07", Category: "technical",
		Question: "A Windows process creates a child process that spawns PowerShell downloading a script from the internet. Is this suspicious? What would you check?",
		Keywords: []string{"parent process", "lolbin", "living off the land", "commandline", "powershell", "download", "hash", "baseline", "context"},
		Model:    "Highly suspicious — this is a classic LOLBin (Living-Off-the-Land Binary) pattern. I'd check: parent process (is Word/Excel spawning PowerShell? — red flag), full command line (encoded commands or unusual URLs), hash of downloaded content (VirusTotal), and whether this matches any known baseline. T1059.001 in MITRE.",
		LabHint:  "living-off-land-01",
		Skill:    "endpoint",
	},
	{
		ID: "tech-08", Category: "technical",
		Question: "What is the difference between a virus and a worm? Give a real-world example of each.",
		Keywords: []string{"virus", "worm", "self-replicating", "network", "host", "propagate", "wannacry", "stuxnet", "infect"},
		Model:    "A virus requires a host file to execute and spreads when that file is shared. A worm is self-replicating and spreads automatically over networks without user interaction. Example virus: early macro viruses in Office documents. Example worm: WannaCry (exploited EternalBlue/SMB to spread automatically across networks).",
		Skill:    "malware",
	},

	// ── Behavioral ─────────────────────────────────────────────────────────────
	{
		ID: "beh-01", Category: "behavioral",
		Question: "Describe how you stay current with cybersecurity threats, vulnerabilities, and industry news.",
		Keywords: []string{"news", "blog", "cisa", "twitter", "feed", "vendor", "advisory", "newsletter", "nist", "threat intel"},
		Model:    "Strong answers include: CISA alerts/advisories, vendor security blogs (Microsoft MSRC, Mandiant, CrowdStrike), Twitter/X security community, threat intel feeds (AlienVault OTX, MISP), CVE databases, and security newsletters (SANS Internet Stormcast, Krebs). The key is having a consistent daily habit.",
		Skill:    "threat_intel",
	},
	{
		ID: "beh-02", Category: "behavioral",
		Question: "Tell me about a time you made a mistake in a technical task. How did you identify it, and what did you do to fix it?",
		Keywords: []string{"mistake", "error", "identified", "fixed", "learned", "communicated", "corrected", "responsible"},
		Model:    "Strong answers demonstrate: owning the mistake quickly, communicating it to the right person proactively (not waiting to be caught), describing the concrete steps taken to fix it, and what process change prevents recurrence. Interviewers want accountability + learning, not perfection.",
		Skill:    "incident_response",
	},
	{
		ID: "beh-03", Category: "behavioral",
		Question: "How do you prioritise your workload when multiple high-severity alerts come in at the same time during a shift?",
		Keywords: []string{"prioritise", "severity", "critical", "sla", "escalate", "communicate", "triage", "category", "business impact"},
		Model:    "Prioritise by: (1) severity (Critical > High), (2) business impact (production systems, PII data), (3) SLA clock remaining, (4) alert category (active ransomware > phishing link clicked). Communicate to the team immediately if workload exceeds capacity. Document everything even if you haven't started investigating yet.",
		Skill:    "incident_response",
	},
	{
		ID: "beh-04", Category: "behavioral",
		Question: "Why do you want to work in a Security Operations Centre as an L1 analyst?",
		Keywords: []string{"detect", "respond", "protect", "blue team", "career", "security", "analyse", "real-world", "learning"},
		Model:    "Strong answers connect personal motivation to the role's actual work: real-time threat detection, protecting real users, the variety of alerts (keeps you sharp), the structured career path (L1 → L2 → specialist), and the pace. Avoid generic answers like 'I like computers.'",
		Skill:    "incident_response",
	},
	{
		ID: "beh-05", Category: "behavioral",
		Question: "Describe a situation where you had to explain a technical concept to a non-technical stakeholder.",
		Keywords: []string{"explain", "non-technical", "simple", "analogy", "stakeholder", "communicate", "translate"},
		Model:    "Strong answers show you adapted your language, used analogies (e.g., comparing a firewall to a security guard), confirmed understanding, and avoided jargon. In SOC, you'll regularly brief managers and legal teams on incidents.",
		Skill:    "incident_response",
	},
	{
		ID: "beh-06", Category: "behavioral",
		Question: "How do you maintain focus and accuracy during repetitive triage work over a long shift?",
		Keywords: []string{"checklist", "process", "routine", "notes", "alert fatigue", "focus", "systematic", "break"},
		Model:    "Proven strategies: use a consistent triage checklist (so nothing is skipped), take short breaks, vary task types where possible, keep notes to avoid re-doing work, and use playbooks for common alert types. Alert fatigue is real — acknowledging it and having a mitigation plan shows maturity.",
		Skill:    "log_analysis",
	},

	// ── Scenario ───────────────────────────────────────────────────────────────
	{
		ID: "sce-01", Category: "scenario",
		Question: "It's 2am. You receive a CRITICAL alert: a server is making repeated outbound connections to a known C2 IP flagged by threat intel. Walk me through your complete triage process.",
		Keywords: []string{"enrich", "ip reputation", "verify", "firewall", "block", "escalate", "document", "isolate", "context", "false positive"},
		Model:    "1. Enrich the IP (VirusTotal, AbuseIPDB, internal threat intel). 2. Verify the alert isn't a false positive (check server role, is this an expected service?). 3. Review process making the connection (Sysmon, EDR). 4. Escalate to on-call L2/IR lead immediately given severity. 5. Document every action with timestamps. 6. Recommend firewall block of the C2 IP while investigation proceeds.",
		LabHint:  "c2-beacon-01",
		Skill:    "network",
	},
	{
		ID: "sce-02", Category: "scenario",
		Question: "A user calls the help desk saying their account is locked out. The help desk escalates it to you. What steps do you take?",
		Keywords: []string{"verify identity", "active directory", "brute force", "logs", "failed logon", "4625", "source ip", "unlock", "password reset"},
		Model:    "1. Verify caller identity (don't just unlock — social engineering risk). 2. Query AD/SIEM for failed logon events (Event ID 4625) — note source IP and count. 3. Check if multiple accounts were targeted (spray vs. targeted brute force). 4. If attacker-originated, isolate the source and escalate. 5. Reset password if legitimate lockout. 6. Document and recommend MFA if not in place.",
		LabHint:  "account-lockout-01",
		Skill:    "log_analysis",
	},
	{
		ID: "sce-03", Category: "scenario",
		Question: "Your SIEM fires: 47 failed logins followed by 1 successful login to a VPN from a foreign IP the user has never used before. What do you do?",
		Keywords: []string{"brute force", "impossible travel", "geographic", "vpn", "verify", "user", "escalate", "block", "mfa", "session"},
		Model:    "This looks like a successful brute-force or credential-stuffing attack. Steps: 1. Check if user is actually travelling (contact them). 2. Impossible travel check (time between logins from different regions). 3. Terminate the active VPN session immediately. 4. Force password reset and enforce MFA. 5. Review what the session accessed. 6. Escalate to IR if sensitive data was reached.",
		LabHint:  "brute-force-01",
		Skill:    "network",
	},
	{
		ID: "sce-04", Category: "scenario",
		Question: "You receive an alert that a finance employee's machine ran PowerShell that encoded a command and created a new scheduled task. What are the red flags and what do you do?",
		Keywords: []string{"encoded", "obfuscation", "scheduled task", "persistence", "t1053", "t1059", "baseline", "edr", "isolate", "escalate"},
		Model:    "Red flags: encoded command (T1027 — obfuscation), scheduled task creation (T1053 — persistence). Finance users have no business running encoded PowerShell. Steps: 1. Decode the base64 command to see what it does. 2. Check parent process — did this originate from a phishing email/attachment? 3. Query EDR for lateral movement from this machine. 4. Isolate the host. 5. Escalate — this has persistence indicators suggesting a more serious compromise.",
		LabHint:  "living-off-land-01",
		Skill:    "endpoint",
	},
	{
		ID: "sce-05", Category: "scenario",
		Question: "You see large volumes of data being sent to an external cloud storage provider (Dropbox/Google Drive) from a server that normally has no internet access. What do you investigate?",
		Keywords: []string{"exfiltration", "data loss", "dlp", "proxy", "dns", "volume", "baseline", "user", "insider", "block", "escalate"},
		Model:    "This is a data exfiltration pattern (T1567). Steps: 1. Confirm volume is anomalous (compare to baseline). 2. Identify the process and user account making the transfers. 3. Check DLP logs — what data categories were involved? 4. Determine if this is an insider threat or compromised account. 5. Block the destination at the proxy/firewall. 6. Escalate to IR and legal if sensitive data is confirmed exfiltrated.",
		LabHint:  "exfil-01",
		Skill:    "network",
	},
	{
		ID: "sce-06", Category: "scenario",
		Question: "A phishing email bypasses your email filters and reaches 500 employees. You find that 12 users clicked the link and 3 submitted credentials. What are your next steps?",
		Keywords: []string{"isolate", "reset", "credentials", "block", "url", "email gateway", "incident", "escalate", "notify", "phishing"},
		Model:    "1. Immediately block the phishing URL at the proxy and email gateway. 2. Pull back the email from all inboxes (if email gateway supports it). 3. Force password reset for the 3 credential-submitters + MFA check. 4. Isolate machines of the 3 submitters for forensic review. 5. Notify all 500 users that the email was malicious. 6. Declare an incident, brief management. 7. Investigate if the 3 accounts were used for any downstream actions.",
		LabHint:  "phishing-02",
		Skill:    "phishing",
	},

	// ── Tools ──────────────────────────────────────────────────────────────────
	{
		ID: "tool-01", Category: "tools",
		Question: "Name at least 3 tools you would use to analyse a suspicious file submitted by a user, and explain what each tells you.",
		Keywords: []string{"virustotal", "sandbox", "strings", "any.run", "pe", "hash", "dynamic", "static", "signature"},
		Model:    "VirusTotal — multi-engine AV scan + community reputation. Any.run or Joe Sandbox — dynamic analysis (what does it do when run: network connections, registry changes, dropped files). PEStudio / strings — static analysis (embedded strings, imports, PE headers). Always hash the file (MD5/SHA256) first for IOC tracking.",
		LabHint:  "malware-01",
		Skill:    "malware",
	},
	{
		ID: "tool-02", Category: "tools",
		Question: "What is Sysmon and why is it valuable in a SOC environment?",
		Keywords: []string{"sysmon", "system monitor", "process creation", "network connection", "event id", "4688", "hash", "telemetry", "windows"},
		Model:    "Sysmon (System Monitor) is a Windows service that generates detailed event logs not available by default: process creation with command line + parent (Event ID 1), network connections per process (Event ID 3), file creation timestamps (Event ID 11), and DNS queries (Event ID 22). It dramatically improves visibility for endpoint detection, especially for LOLBins and fileless attacks.",
		LabHint:  "living-off-land-01",
		Skill:    "endpoint",
	},
	{
		ID: "tool-03", Category: "tools",
		Question: "How would you use a SIEM to investigate a suspected brute-force attack against your VPN?",
		Keywords: []string{"query", "filter", "failed logon", "4625", "source ip", "threshold", "time window", "correlation", "group by"},
		Model:    "1. Query failed authentication events (Event ID 4625 or VPN-specific logs) filtered to the VPN log source. 2. Group by source IP and username. 3. Look for IPs with >10 failed attempts in a short window. 4. Check if any failed series ends in a success (credential found). 5. Cross-reference IPs with threat intel feeds. 6. Review timing for distributed spray patterns (low-and-slow across many source IPs).",
		LabHint:  "brute-force-01",
		Skill:    "log_analysis",
	},
	{
		ID: "tool-04", Category: "tools",
		Question: "What is a packet capture (PCAP) and when would you use Wireshark during a SOC investigation?",
		Keywords: []string{"pcap", "packet capture", "wireshark", "filter", "protocol", "c2", "beaconing", "dns", "http", "stream"},
		Model:    "A PCAP is a recording of raw network traffic. I'd use Wireshark when: (1) investigating suspected C2 beaconing (filter by destination IP, look for regular intervals), (2) analysing suspicious DNS queries (unusual domains, high query rate), (3) identifying data exfiltration (look at outbound payload sizes), or (4) decrypting and inspecting protocol content. I'd filter by suspicious IP, follow TCP stream, and look at HTTP headers/payload.",
		LabHint:  "c2-beacon-01",
		Skill:    "network",
	},
	{
		ID: "tool-05", Category: "tools",
		Question: "What threat intelligence platforms or feeds would you use in your daily SOC work? How do you use them?",
		Keywords: []string{"virustotal", "alienvault", "otx", "misp", "abuseipdb", "shodan", "feed", "ioc", "enrich", "reputation"},
		Model:    "Common platforms: VirusTotal (file/URL/IP/domain reputation), AbuseIPDB (IP reputation and abuse reports), AlienVault OTX (community IOC sharing), MISP (sharing platform for structured threat intel), Shodan (internet-exposed asset and port scanning). In daily work: enrich every IOC from an alert before making a verdict, subscribe to feeds relevant to your industry vertical, and contribute back (share new IOCs you discover).",
		Skill:    "threat_intel",
	},
}

// ── Session structs ───────────────────────────────────────────────────────────

type interviewSession struct {
	ID        int64
	Category  string
	Questions []interviewQuestion
	Answers   map[string]string // question ID → answer text
	Scores    map[string]int    // question ID → score 0-100
	CurrentQ  int
	Status    string
}

type questionResult struct {
	Q          interviewQuestion
	Answer     string
	Score      int    // 0-100
	Grade      string // "strong" | "partial" | "weak"
	Matched    []string
	Missed     []string
}

// ── Scoring ───────────────────────────────────────────────────────────────────

func gradeAnswer(q interviewQuestion, answer string) (score int, grade string, matched, missed []string) {
	lower := strings.ToLower(answer)
	for _, kw := range q.Keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			matched = append(matched, kw)
		} else {
			missed = append(missed, kw)
		}
	}
	if len(q.Keywords) == 0 {
		return 70, "partial", nil, nil
	}
	pct := len(matched) * 100 / len(q.Keywords)
	score = pct
	switch {
	case pct >= 60:
		grade = "strong"
	case pct >= 30:
		grade = "partial"
	default:
		grade = "weak"
	}
	return
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func categoryLabel(cat string) string {
	switch cat {
	case "technical":
		return "Technical Knowledge"
	case "behavioral":
		return "Behavioral / Situational"
	case "scenario":
		return "Scenario Response"
	case "tools":
		return "Tools & Platforms"
	}
	return cat
}

func categoryIcon(cat string) string {
	switch cat {
	case "technical":
		return "🔬"
	case "behavioral":
		return "🤝"
	case "scenario":
		return "🚨"
	case "tools":
		return "🛠"
	}
	return "📋"
}

func categoryDesc(cat string) string {
	switch cat {
	case "technical":
		return "CIA Triad, IOC vs TTP, MITRE, malware types, SIEM concepts"
	case "behavioral":
		return "Communication, prioritisation, learning habits, teamwork"
	case "scenario":
		return "Live incident walkthroughs — triage decisions under pressure"
	case "tools":
		return "Sysmon, Wireshark, SIEM queries, threat intel platforms"
	}
	return ""
}

func questionsForCategory(cat string) []interviewQuestion {
	var pool []interviewQuestion
	for _, q := range questionBank {
		if cat == "all" || q.Category == cat {
			pool = append(pool, q)
		}
	}
	return pool
}

func pickQuestions(cat string, n int) []interviewQuestion {
	pool := questionsForCategory(cat)
	rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if n > len(pool) {
		n = len(pool)
	}
	return pool[:n]
}

// GET /interview
func (h *Handler) getInterviewList(w http.ResponseWriter, r *http.Request) {
	type catCard struct {
		Key   string
		Label string
		Icon  string
		Desc  string
		Count int
	}
	cats := []catCard{
		{"technical", categoryLabel("technical"), categoryIcon("technical"), categoryDesc("technical"), len(questionsForCategory("technical"))},
		{"behavioral", categoryLabel("behavioral"), categoryIcon("behavioral"), categoryDesc("behavioral"), len(questionsForCategory("behavioral"))},
		{"scenario", categoryLabel("scenario"), categoryIcon("scenario"), categoryDesc("scenario"), len(questionsForCategory("scenario"))},
		{"tools", categoryLabel("tools"), categoryIcon("tools"), categoryDesc("tools"), len(questionsForCategory("tools"))},
	}
	h.render(w, r, "interview_list.html", map[string]any{
		"Categories": cats,
		"Total":      len(questionBank),
	})
}

// POST /interview/start
func (h *Handler) postStartInterview(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	cat := r.FormValue("category")
	if cat == "" {
		cat = "all"
	}
	n := 8
	if cat == "all" {
		n = 10
	}

	questions := pickQuestions(cat, n)
	if len(questions) == 0 {
		http.Redirect(w, r, "/interview", http.StatusSeeOther)
		return
	}

	ids := make([]string, len(questions))
	for i, q := range questions {
		ids[i] = q.ID
	}
	qJSON, _ := json.Marshal(ids)

	res, err := h.db.Exec(
		`INSERT INTO interview_sessions(user_id, category, questions_json) VALUES(?,?,?)`,
		u.ID, cat, string(qJSON),
	)
	if err != nil {
		h.log.Error("create interview session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sid, _ := res.LastInsertId()
	http.Redirect(w, r, "/interview/"+strconv.FormatInt(sid, 10), http.StatusSeeOther)
}

// GET /interview/{id}
func (h *Handler) getInterview(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	sid, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	sess, ok := h.loadInterviewSession(sid, u.ID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if sess.Status == "completed" {
		http.Redirect(w, r, "/interview/"+strconv.FormatInt(sid, 10)+"/result", http.StatusSeeOther)
		return
	}

	qIdx := sess.CurrentQ - 1
	if qIdx < 0 || qIdx >= len(sess.Questions) {
		http.Redirect(w, r, "/interview/"+strconv.FormatInt(sid, 10)+"/result", http.StatusSeeOther)
		return
	}

	q := sess.Questions[qIdx]
	draft := sess.Answers[q.ID]

	h.render(w, r, "interview.html", map[string]any{
		"Session":   sess,
		"SessionID": sid,
		"Question":  q,
		"QNum":      sess.CurrentQ,
		"QTotal":    len(sess.Questions),
		"Draft":     draft,
		"TimerSecs": 90,
	})
}

// POST /interview/{id}/answer
func (h *Handler) postInterviewAnswer(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	sid, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	sess, ok := h.loadInterviewSession(sid, u.ID)
	if !ok || sess.Status == "completed" {
		http.NotFound(w, r)
		return
	}

	qIdx := sess.CurrentQ - 1
	if qIdx < 0 || qIdx >= len(sess.Questions) {
		http.Redirect(w, r, "/interview/"+strconv.FormatInt(sid, 10)+"/result", http.StatusSeeOther)
		return
	}

	q := sess.Questions[qIdx]
	answer := strings.TrimSpace(r.FormValue("answer"))

	// Grade
	score, _, _, _ := gradeAnswer(q, answer)

	// Persist answer + score
	sess.Answers[q.ID] = answer
	sess.Scores[q.ID] = score

	aJSON, _ := json.Marshal(sess.Answers)
	sJSON, _ := json.Marshal(sess.Scores)

	nextQ := sess.CurrentQ + 1
	if nextQ > len(sess.Questions) {
		// Complete session
		totalScore := 0
		for _, s := range sess.Scores {
			totalScore += s
		}
		avg := totalScore / len(sess.Scores)
		h.db.Exec(
			`UPDATE interview_sessions SET answers_json=?, scores_json=?, current_q=?, status='completed', score=?, completed_at=CURRENT_TIMESTAMP WHERE id=?`,
			string(aJSON), string(sJSON), nextQ, avg, sid,
		)
		h.updateMissionProgress(u.ID, "interview_done", map[string]any{"score": avg})
		http.Redirect(w, r, "/interview/"+strconv.FormatInt(sid, 10)+"/result", http.StatusSeeOther)
		return
	}

	h.db.Exec(
		`UPDATE interview_sessions SET answers_json=?, scores_json=?, current_q=? WHERE id=?`,
		string(aJSON), string(sJSON), nextQ, sid,
	)
	http.Redirect(w, r, "/interview/"+strconv.FormatInt(sid, 10), http.StatusSeeOther)
}

// GET /interview/{id}/result
func (h *Handler) getInterviewResult(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	sid, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	sess, ok := h.loadInterviewSession(sid, u.ID)
	if !ok {
		http.NotFound(w, r)
		return
	}

	var results []questionResult
	strong, partial, weak := 0, 0, 0
	skillGaps := map[string]bool{}
	var labSuggestions []struct{ ID, Title string }

	for _, q := range sess.Questions {
		answer := sess.Answers[q.ID]
		score, grade, matched, missed := gradeAnswer(q, answer)
		results = append(results, questionResult{
			Q: q, Answer: answer, Score: score, Grade: grade,
			Matched: matched, Missed: missed,
		})
		switch grade {
		case "strong":
			strong++
		case "partial":
			partial++
		case "weak":
			weak++
			if q.Skill != "" {
				skillGaps[q.Skill] = true
			}
			if q.LabHint != "" {
				l, exists := h.labs.Get(q.LabHint)
				if exists {
					labSuggestions = append(labSuggestions, struct{ ID, Title string }{l.ID, l.Title})
				}
			}
		}
	}

	totalScore := 0
	for _, sc := range sess.Scores {
		totalScore += sc
	}
	avg := 0
	if len(sess.Scores) > 0 {
		avg = totalScore / len(sess.Scores)
	}

	var overallGrade string
	switch {
	case avg >= 70:
		overallGrade = "strong"
	case avg >= 40:
		overallGrade = "partial"
	default:
		overallGrade = "weak"
	}

	// Deduplicate lab suggestions
	seen := map[string]bool{}
	var uniqLabs []struct{ ID, Title string }
	for _, l := range labSuggestions {
		if !seen[l.ID] {
			seen[l.ID] = true
			uniqLabs = append(uniqLabs, l)
		}
	}

	h.render(w, r, "interview_result.html", map[string]any{
		"Session":      sess,
		"SessionID":    sid,
		"Results":      results,
		"Strong":       strong,
		"Partial":      partial,
		"Weak":         weak,
		"AvgScore":     avg,
		"OverallGrade": overallGrade,
		"SkillGaps":    skillGaps,
		"LabSuggestions": uniqLabs,
		"Category":     categoryLabel(sess.Category),
	})
}

// ── Session loader ────────────────────────────────────────────────────────────

func (h *Handler) loadInterviewSession(id, userID int64) (interviewSession, bool) {
	var sess interviewSession
	var qJSON, aJSON, sJSON string
	err := h.db.QueryRow(
		`SELECT id, category, questions_json, answers_json, scores_json, current_q, status FROM interview_sessions WHERE id=? AND user_id=?`,
		id, userID,
	).Scan(&sess.ID, &sess.Category, &qJSON, &aJSON, &sJSON, &sess.CurrentQ, &sess.Status)
	if err != nil {
		return sess, false
	}

	var qIDs []string
	json.Unmarshal([]byte(qJSON), &qIDs)
	json.Unmarshal([]byte(aJSON), &sess.Answers)
	json.Unmarshal([]byte(sJSON), &sess.Scores)
	if sess.Answers == nil {
		sess.Answers = map[string]string{}
	}
	if sess.Scores == nil {
		sess.Scores = map[string]int{}
	}

	// Resolve question IDs to structs
	qMap := map[string]interviewQuestion{}
	for _, q := range questionBank {
		qMap[q.ID] = q
	}
	for _, id := range qIDs {
		if q, ok := qMap[id]; ok {
			sess.Questions = append(sess.Questions, q)
		}
	}
	return sess, true
}

// ── Recent sessions for list page ─────────────────────────────────────────────

func (h *Handler) recentInterviewSessions(userID int64, limit int) []struct {
	ID          int64
	Category    string
	Score       *int
	CompletedAt *time.Time
	Status      string
} {
	rows, err := h.db.Query(
		`SELECT id, category, score, completed_at, status FROM interview_sessions WHERE user_id=? ORDER BY started_at DESC LIMIT ?`,
		userID, limit,
	)
	if err != nil || rows == nil {
		return nil
	}
	defer rows.Close()

	type row struct {
		ID          int64
		Category    string
		Score       *int
		CompletedAt *time.Time
		Status      string
	}
	var results []row
	for rows.Next() {
		var r row
		var score *int64
		var ca *string
		rows.Scan(&r.ID, &r.Category, &score, &ca, &r.Status)
		if score != nil {
			v := int(*score)
			r.Score = &v
		}
		if ca != nil {
			t, err := time.Parse("2006-01-02T15:04:05Z", *ca)
			if err == nil {
				r.CompletedAt = &t
			}
		}
		results = append(results, r)
	}
	return results
}
