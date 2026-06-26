package alertengine

import "time"

type AlertTemplate struct {
	Key                string
	Severity           string // critical | high | medium | low | info
	Source             string // edr | firewall | siem | auth | proxy | ids | ueba | cloudtrail
	Category           string // malware | phishing | c2 | brute-force | data-exfil | web-attack | lateral-movement | persistence | privilege-escalation | recon | compliance
	RuleTemplate       string
	ScenarioTmpl       string
	LogTemplates       []LogTemplate
	ExpectedVerdict    string   // true_positive | false_positive
	ExpectedEscalation string   // escalate | close
	RequiredMITRE      []string
	Keywords           []string
	ScoreBreakdown     LiveScore
	DifficultyModifier float64
}

type LogTemplate struct {
	Level   string // info | warn | error | critical
	MsgTmpl string
}

type AlertParams struct {
	SrcIP    string
	DstIP    string
	Hostname string
	Username string
	Count    int
	Filename string
	Domain   string
	Hash     string
	Port     int
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Host      string `json:"host"`
	Source    string `json:"source"`
	Message   string `json:"message"`
}

type LiveScore struct {
	Verdict  int
	Keywords int
	MITRE    int
	Writeup  int
	Total    int
}

type LiveRubric struct {
	ExpectedVerdict    string
	ExpectedEscalation string
	RequiredMITRE      []string
	Keywords           []string
	ScoreBreakdown     LiveScore
	DifficultyModifier float64
	MinWriteupWords    int
}

type GeneratedAlert struct {
	ID          int64
	TemplateKey string
	Severity    string
	Source      string
	Category    string
	RuleText    string
	Scenario    string
	SrcIP       string
	Hostname    string
	Username    string
	Logs        []LogEntry
	Rubric      LiveRubric
	TriggeredAt time.Time
	ExpiresAt   time.Time
}
