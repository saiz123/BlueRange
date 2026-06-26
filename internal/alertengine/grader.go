package alertengine

import "strings"

type LiveSubmission struct {
	Verdict   string
	Severity  string
	Rationale string
	MITRETags []string
	Escalated bool
}

type LiveResult struct {
	Score             int
	MaxScore          int
	VerdictScore      int
	KeywordScore      int
	MITREScore        int
	WriteupScore      int
	VerdictCorrect    bool
	EscalationCorrect bool
	MITREMatched      []string
	MITREMissed       []string
	Feedback          []LiveFeedback
	Passed            bool
}

type LiveFeedback struct {
	Label   string
	Points  int
	Max     int
	Correct bool
}

func GradeLive(rubric LiveRubric, sub LiveSubmission) LiveResult {
	res := LiveResult{MaxScore: rubric.ScoreBreakdown.Total}

	// 1. Verdict (40 pts)
	if sub.Verdict == rubric.ExpectedVerdict {
		res.VerdictScore = rubric.ScoreBreakdown.Verdict
		res.VerdictCorrect = true
	}
	res.Score += res.VerdictScore
	res.Feedback = append(res.Feedback, LiveFeedback{"Verdict", res.VerdictScore, rubric.ScoreBreakdown.Verdict, res.VerdictCorrect})

	// 2. Keywords in rationale (30 pts)
	ratLower := strings.ToLower(sub.Rationale)
	matched := 0
	for _, kw := range rubric.Keywords {
		if strings.Contains(ratLower, strings.ToLower(kw)) {
			matched++
		}
	}
	if len(rubric.Keywords) > 0 {
		res.KeywordScore = rubric.ScoreBreakdown.Keywords * matched / len(rubric.Keywords)
	} else {
		res.KeywordScore = rubric.ScoreBreakdown.Keywords
	}
	res.Score += res.KeywordScore
	res.Feedback = append(res.Feedback, LiveFeedback{"Rationale Quality", res.KeywordScore, rubric.ScoreBreakdown.Keywords, matched > 0})

	// 3. MITRE (20 pts)
	mitreSet := map[string]bool{}
	for _, t := range sub.MITRETags {
		mitreSet[t] = true
	}
	for _, req := range rubric.RequiredMITRE {
		if mitreSet[req] {
			res.MITREMatched = append(res.MITREMatched, req)
		} else {
			res.MITREMissed = append(res.MITREMissed, req)
		}
	}
	if len(rubric.RequiredMITRE) > 0 {
		res.MITREScore = rubric.ScoreBreakdown.MITRE * len(res.MITREMatched) / len(rubric.RequiredMITRE)
	} else {
		res.MITREScore = rubric.ScoreBreakdown.MITRE
	}
	res.Score += res.MITREScore
	res.Feedback = append(res.Feedback, LiveFeedback{"MITRE ATT&CK", res.MITREScore, rubric.ScoreBreakdown.MITRE, len(res.MITREMissed) == 0})

	// 4. Writeup quality (10 pts)
	wordCount := len(strings.Fields(sub.Rationale))
	minWords := rubric.MinWriteupWords
	if minWords <= 0 {
		minWords = 20
	}
	if wordCount >= minWords {
		res.WriteupScore = rubric.ScoreBreakdown.Writeup
	} else if wordCount > 3 {
		res.WriteupScore = rubric.ScoreBreakdown.Writeup * wordCount / minWords
	}
	res.Score += res.WriteupScore
	res.Feedback = append(res.Feedback, LiveFeedback{"Writeup Quality", res.WriteupScore, rubric.ScoreBreakdown.Writeup, wordCount >= minWords})

	// Apply difficulty modifier
	if rubric.DifficultyModifier > 0 {
		res.Score = int(float64(res.Score) * rubric.DifficultyModifier)
	}

	// Escalation (feedback only, no points)
	res.EscalationCorrect = (sub.Escalated && rubric.ExpectedEscalation == "escalate") ||
		(!sub.Escalated && rubric.ExpectedEscalation == "close")
	res.Feedback = append(res.Feedback, LiveFeedback{"Escalation Decision", 0, 0, res.EscalationCorrect})

	res.Passed = res.VerdictCorrect && res.Score >= int(float64(res.MaxScore)*0.5)
	return res
}
