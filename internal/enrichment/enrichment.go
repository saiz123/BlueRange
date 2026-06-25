package enrichment

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
)

type Verdict string

const (
	VerdictMalicious  Verdict = "malicious"
	VerdictSuspicious Verdict = "suspicious"
	VerdictClean      Verdict = "clean"
	VerdictUnknown    Verdict = "unknown"
)

type Result struct {
	Indicator string  `json:"indicator"`
	Type      string  `json:"type"`
	Verdict   Verdict `json:"verdict"`
	Confidence int    `json:"confidence"`
	Tags      []string `json:"tags"`
	Note      string  `json:"note"`
}

// Lookup returns a deterministic, realistic-looking enrichment result for an
// indicator. Works fully offline — no network calls are made.
func Lookup(indicator string) Result {
	indicator = strings.TrimSpace(indicator)
	t := classify(indicator)
	v, conf, tags, note := score(indicator, t)
	return Result{
		Indicator:  indicator,
		Type:       t,
		Verdict:    v,
		Confidence: conf,
		Tags:       tags,
		Note:       note,
	}
}

func classify(ind string) string {
	if net.ParseIP(ind) != nil {
		return "ip"
	}
	if len(ind) == 32 || len(ind) == 40 || len(ind) == 64 {
		all := true
		for _, c := range strings.ToLower(ind) {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				all = false
				break
			}
		}
		if all {
			return "hash"
		}
	}
	if strings.Contains(ind, ".") && !strings.Contains(ind, " ") {
		return "domain"
	}
	return "unknown"
}

func score(ind, t string) (Verdict, int, []string, string) {
	// Deterministic scoring based on hash of indicator so repeated calls are stable.
	h := sha256.Sum256([]byte(ind))
	seed := int(h[0])<<8 | int(h[1])

	// Known bad indicators (used in starter labs) always return malicious.
	knownBad := map[string]bool{
		"185.220.101.45":                                 true,
		"corp-helpdesk.net":                              true,
		"update-service.xyz":                             true,
		"dl.bad-payload.ru":                              true,
		"44d88612fea8a8f36de82e1278abb02f": true, // EICAR MD5
		"3395856ce81f2b7382dee72602f798b642f14d0": true, // EICAR SHA1
	}
	knownClean := map[string]bool{
		"8.8.8.8":        true,
		"1.1.1.1":        true,
		"microsoft.com":  true,
		"windows.com":    true,
	}

	lower := strings.ToLower(ind)
	if knownBad[lower] || knownBad[ind] {
		return VerdictMalicious, 95, []string{"phishing", "known-bad"}, fmt.Sprintf("Listed in threat feeds. Seen in %d+ campaigns.", 10+(seed%90))
	}
	if knownClean[lower] {
		return VerdictClean, 99, []string{"allowlisted"}, "Known-good infrastructure."
	}

	// Pseudo-random but stable bucket based on seed
	bucket := seed % 100
	switch t {
	case "ip":
		if bucket < 25 {
			return VerdictMalicious, 70 + bucket%25, []string{"c2", "scanner"}, fmt.Sprintf("Seen in %d abuse reports this month.", 5+bucket%40)
		}
		if bucket < 50 {
			return VerdictSuspicious, 40 + bucket%30, []string{"hosting"}, "Hosted on bulletproof VPS provider."
		}
		return VerdictClean, 80 + bucket%15, nil, "No significant reputation signals."
	case "domain":
		if bucket < 20 {
			return VerdictMalicious, 85 + bucket%10, []string{"phishing", "newly-registered"}, fmt.Sprintf("Domain registered %d days ago. Matches phishing pattern.", 1+bucket%14)
		}
		if bucket < 45 {
			return VerdictSuspicious, 55 + bucket%20, []string{"dga-like"}, "Domain exhibits DGA-like entropy."
		}
		return VerdictClean, 75 + bucket%20, nil, "No known malicious activity."
	case "hash":
		if bucket < 30 {
			return VerdictMalicious, 90 + bucket%8, []string{"malware", "trojan"}, fmt.Sprintf("Detected by %d/68 AV engines.", 40+bucket%25)
		}
		if bucket < 50 {
			return VerdictSuspicious, 50 + bucket%30, []string{"pup"}, "Detected as potentially unwanted program."
		}
		return VerdictClean, 90, nil, "No detections across major AV engines."
	}
	return VerdictUnknown, 0, nil, "Indicator type not recognized."
}
