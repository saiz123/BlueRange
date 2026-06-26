package grader

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bluerange/bluerange/internal/lab"
)

type Submission struct {
	Verdict         string   // "true_positive" | "false_positive"
	Severity        string
	Rationale       string
	Mitre           []string // technique IDs e.g. ["T1566.001"]
	Escalated       bool     // true = escalate to L2
	TimeTakenMin    int      // minutes from started_at to now (0 = unknown)
	IOCsEnriched    int      // count of IOC enrichment lookups done during investigation
}

type FeedbackItem struct {
	Category string `json:"category"`
	Points   int    `json:"points"`
	Max      int    `json:"max"`
	Passed   bool   `json:"passed"`
	Message  string `json:"message"`
}

type Result struct {
	Score              int            `json:"score"`
	MaxScore           int            `json:"max_score"`
	Passed             bool           `json:"passed"`
	Items              []FeedbackItem `json:"items"`
	TimeBonusEarned    int            `json:"time_bonus_earned"`
	DifficultyModifier float64        `json:"difficulty_modifier"`
}

func (r Result) JSON() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func Grade(l *lab.Lab, sub Submission) Result {
	rubric := l.Rubric
	var items []FeedbackItem
	total := 0

	// Minimum writeup words (default 25, raised to 50 via rubric)
	minWords := rubric.MinWriteupWords
	if minWords == 0 {
		minWords = 25
	}

	// 1. Verdict (default 40 pts)
	{
		max := rubric.ScoreBreakdown.CorrectVerdict
		if max == 0 {
			max = 40
		}
		got := strings.EqualFold(sub.Verdict, rubric.ExpectedVerdict)
		pts := 0
		if got {
			pts = max
		}
		msg := "Correct verdict."
		if !got {
			expected := strings.ReplaceAll(rubric.ExpectedVerdict, "_", " ")
			msg = fmt.Sprintf("Incorrect verdict. Expected: %s. Review the evidence more carefully — look for indicators like SPF failures, suspicious sender domains, and credential-harvest URLs.", expected)
		}
		items = append(items, FeedbackItem{"Verdict", pts, max, got, msg})
		total += pts
	}

	// 2. Key findings in rationale (default 30 pts)
	{
		max := rubric.ScoreBreakdown.RequiredFindings
		if max == 0 {
			max = 30
		}
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
		pts := 0
		if len(keywords) > 0 {
			pts = found * max / len(keywords)
		}
		passed := len(missed) == 0
		msg := "All key findings documented in your rationale."
		if !passed {
			msg = fmt.Sprintf("Your rationale is missing key findings: %s. Document specific evidence (log entries, IOCs, timestamps) that led to your conclusion.", strings.Join(missed, ", "))
		}
		items = append(items, FeedbackItem{"Key Findings", pts, max, passed, msg})
		total += pts
	}

	// 3. MITRE ATT&CK mapping (default 20 pts)
	{
		max := rubric.ScoreBreakdown.CorrectMitre
		if max == 0 {
			max = 20
		}
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
			pts = max / 2
		}
		msg := "Correct MITRE ATT&CK mapping."
		if !passed {
			msg = fmt.Sprintf("Missing required MITRE techniques: %s. Every confirmed TTP should be tagged.", strings.Join(missing, ", "))
		}
		items = append(items, FeedbackItem{"MITRE ATT&CK", pts, max, passed, msg})
		total += pts
	}

	// 4. Write-up quality (default 10 pts)
	{
		max := rubric.ScoreBreakdown.WriteupQuality
		if max == 0 {
			max = 10
		}
		words := len(strings.Fields(sub.Rationale))
		pts := 0
		msg := ""
		threshold50 := minWords * 2
		threshold25 := minWords
		threshold10 := minWords / 2
		switch {
		case words >= threshold50:
			pts = max
			msg = "Thorough write-up with sufficient detail."
		case words >= threshold25:
			pts = max * 6 / 10
			msg = fmt.Sprintf("Adequate write-up (%d words). Adding more specific evidence references would strengthen it.", words)
		case words >= threshold10:
			pts = max * 3 / 10
			msg = fmt.Sprintf("Brief write-up (%d words). Expand with specific IOCs, log entries, and your reasoning.", words)
		default:
			pts = 0
			msg = fmt.Sprintf("Write-up too short (%d words, minimum %d). Document the specific evidence you found and why it led to your verdict.", words, minWords)
		}
		passed := pts >= max*6/10
		items = append(items, FeedbackItem{"Write-up Quality", pts, max, passed, msg})
		total += pts
	}

	// 5. IOC Enrichment (new: default 0 pts if not configured, up to ScoreBreakdown.IOCEnrichment)
	iocPts := 0
	if max := rubric.ScoreBreakdown.IOCEnrichment; max > 0 {
		if sub.IOCsEnriched > 0 {
			iocPts = max
			items = append(items, FeedbackItem{"Threat Intel", iocPts, max, true, fmt.Sprintf("Used threat intelligence lookup during investigation (%d lookups). Good practice.", sub.IOCsEnriched)})
		} else {
			items = append(items, FeedbackItem{"Threat Intel", 0, max, false, "No IOC enrichment performed. Use the Threat Intel tab to look up IPs, domains, or hashes for additional context."})
		}
		total += iocPts
	}

	// 6. Escalation (feedback only, no points)
	{
		expectedEsc := strings.EqualFold(rubric.ExpectedEscalation, "escalate")
		actualEsc := sub.Escalated
		msg := "Correct escalation decision."
		if expectedEsc && !actualEsc {
			msg = "This incident should have been escalated to L2. High-severity confirmed threats require senior analyst review."
		} else if !expectedEsc && actualEsc {
			msg = "No escalation needed here. L1 can close this after standard containment steps."
		}
		passed := expectedEsc == actualEsc
		items = append(items, FeedbackItem{"Escalation", 0, 0, passed, msg})
	}

	// Time bonus (applied after base scoring)
	timeBonusEarned := 0
	if rubric.TimeBonus.ThresholdMinutes > 0 && rubric.TimeBonus.BonusPoints > 0 &&
		sub.TimeTakenMin > 0 && sub.TimeTakenMin <= rubric.TimeBonus.ThresholdMinutes {
		timeBonusEarned = rubric.TimeBonus.BonusPoints
		total += timeBonusEarned
		items = append(items, FeedbackItem{
			"Speed Bonus",
			timeBonusEarned,
			rubric.TimeBonus.BonusPoints,
			true,
			fmt.Sprintf("Completed in %d minutes (threshold: %d min). Speed bonus awarded!", sub.TimeTakenMin, rubric.TimeBonus.ThresholdMinutes),
		})
	}

	// Difficulty modifier
	modifier := rubric.DifficultyModifier
	if modifier <= 0 {
		modifier = 1.0
	}
	adjustedTotal := int(float64(total) * modifier)

	maxScore := rubric.ScoreBreakdown.CorrectVerdict
	if maxScore == 0 {
		maxScore = 40
	}
	maxScore += rubric.ScoreBreakdown.RequiredFindings
	if rubric.ScoreBreakdown.RequiredFindings == 0 {
		maxScore += 30
	}
	maxScore += rubric.ScoreBreakdown.CorrectMitre
	if rubric.ScoreBreakdown.CorrectMitre == 0 {
		maxScore += 20
	}
	maxScore += rubric.ScoreBreakdown.WriteupQuality
	if rubric.ScoreBreakdown.WriteupQuality == 0 {
		maxScore += 10
	}
	maxScore += rubric.ScoreBreakdown.IOCEnrichment
	maxScore += timeBonusEarned

	passing := rubric.PassingScore
	if passing == 0 {
		passing = 70
	}

	return Result{
		Score:              adjustedTotal,
		MaxScore:           maxScore,
		Passed:             adjustedTotal >= passing,
		Items:              items,
		TimeBonusEarned:    timeBonusEarned,
		DifficultyModifier: modifier,
	}
}
