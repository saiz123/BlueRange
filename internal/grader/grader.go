package grader

import (
	"encoding/json"
	"strings"

	"github.com/bluerange/bluerange/internal/lab"
)

type Submission struct {
	Verdict   string   // "true_positive" | "false_positive"
	Severity  string
	Rationale string
	Mitre     []string // technique IDs e.g. ["T1566.001"]
	Escalated bool     // true = escalate to L2
}

type FeedbackItem struct {
	Category string `json:"category"`
	Points   int    `json:"points"`
	Max      int    `json:"max"`
	Passed   bool   `json:"passed"`
	Message  string `json:"message"`
}

type Result struct {
	Score    int            `json:"score"`
	MaxScore int            `json:"max_score"`
	Passed   bool           `json:"passed"`
	Items    []FeedbackItem `json:"items"`
}

func (r Result) JSON() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func Grade(l *lab.Lab, sub Submission) Result {
	rubric := l.Rubric
	var items []FeedbackItem
	total := 0

	// 1. Verdict (40 pts)
	{
		max := rubric.ScoreBreakdown.CorrectVerdict
		got := strings.EqualFold(sub.Verdict, rubric.ExpectedVerdict)
		pts := 0
		if got {
			pts = max
		}
		msg := "Correct verdict."
		if !got {
			expected := strings.ReplaceAll(rubric.ExpectedVerdict, "_", " ")
			msg = "Incorrect verdict. Expected: " + expected + ". Review the evidence more carefully — look for indicators like SPF failures, suspicious sender domains, and credential-harvest URLs."
		}
		items = append(items, FeedbackItem{"Verdict", pts, max, got, msg})
		total += pts
	}

	// 2. Required findings in rationale (30 pts distributed)
	{
		max := rubric.ScoreBreakdown.RequiredFindings
		keywords := l.RationaleKeywords
		found := 0
		var missed []string
		ratLower := strings.ToLower(sub.Rationale)
		for _, kw := range keywords {
			if strings.Contains(ratLower, strings.ToLower(kw)) {
				found++
			} else {
				missed = append(missed, kw)
			}
		}
		pct := 0
		if len(keywords) > 0 {
			pct = found * max / len(keywords)
		}
		passed := len(missed) == 0
		msg := "All key findings mentioned in rationale."
		if !passed {
			msg = "Your rationale is missing these key findings: " + strings.Join(missed, ", ") + ". A complete write-up should document your evidence trail."
		}
		items = append(items, FeedbackItem{"Key Findings", pct, max, passed, msg})
		total += pct
	}

	// 3. MITRE ATT&CK mapping (20 pts)
	{
		max := rubric.ScoreBreakdown.CorrectMitre
		required := rubric.RequiredMitre
		subSet := make(map[string]bool)
		for _, id := range sub.Mitre {
			subSet[strings.ToUpper(id)] = true
		}
		var missing []string
		for _, id := range required {
			if !subSet[strings.ToUpper(id)] {
				missing = append(missing, id)
			}
		}
		passed := len(missing) == 0
		pts := 0
		if passed {
			pts = max
		} else if len(sub.Mitre) > 0 {
			pts = max / 2 // partial credit for attempting
		}
		msg := "Correct MITRE ATT&CK mapping."
		if !passed {
			msg = "Missing required MITRE techniques: " + strings.Join(missing, ", ") + ". Every confirmed TTP should be tagged."
		}
		items = append(items, FeedbackItem{"MITRE ATT&CK", pts, max, passed, msg})
		total += pts
	}

	// 4. Write-up quality (10 pts)
	{
		max := rubric.ScoreBreakdown.WriteupQuality
		words := len(strings.Fields(sub.Rationale))
		pts := 0
		msg := ""
		switch {
		case words >= 50:
			pts = max
			msg = "Thorough write-up with sufficient detail."
		case words >= 25:
			pts = max * 6 / 10
			msg = "Adequate write-up. Adding more specific evidence references would strengthen it."
		case words >= 10:
			pts = max * 3 / 10
			msg = "Brief write-up. Expand with specific IOCs and your reasoning."
		default:
			pts = 0
			msg = "Write-up too short. Document the specific evidence you found and why it led to your verdict."
		}
		passed := pts >= max*6/10
		items = append(items, FeedbackItem{"Write-up Quality", pts, max, passed, msg})
		total += pts
	}

	// 5. Escalation decision (bonus/penalty check — no direct points, just feedback)
	{
		expectedEsc := strings.EqualFold(rubric.ExpectedEscalation, "escalate")
		actualEsc := sub.Escalated
		msg := ""
		if expectedEsc && !actualEsc {
			msg = "This incident should have been escalated to L2. High-severity confirmed threats require senior analyst review before closing."
		} else if !expectedEsc && actualEsc {
			msg = "No escalation needed here. L1 can close confirmed phishing after standard containment (block sender, quarantine, user notification)."
		} else {
			msg = "Correct escalation decision."
		}
		passed := expectedEsc == actualEsc
		items = append(items, FeedbackItem{"Escalation", 0, 0, passed, msg})
	}

	maxScore := rubric.ScoreBreakdown.CorrectVerdict +
		rubric.ScoreBreakdown.RequiredFindings +
		rubric.ScoreBreakdown.CorrectMitre +
		rubric.ScoreBreakdown.WriteupQuality

	passing := rubric.PassingScore
	if passing == 0 {
		passing = 70
	}

	return Result{
		Score:    total,
		MaxScore: maxScore,
		Passed:   total >= passing,
		Items:    items,
	}
}
