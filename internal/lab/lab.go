package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type MitreTag struct {
	ID   string `yaml:"id"   json:"id"`
	Name string `yaml:"name" json:"name"`
}

type Alert struct {
	Severity    string `yaml:"severity"     json:"severity"`
	Source      string `yaml:"source"       json:"source"`
	Rule        string `yaml:"rule"         json:"rule"`
	TriggeredAt string `yaml:"triggered_at" json:"triggered_at"`
	SrcIP       string `yaml:"src_ip"       json:"src_ip"`
	Recipient   string `yaml:"recipient"    json:"recipient"`
}

type ScoreBreakdown struct {
	CorrectVerdict   int `yaml:"correct_verdict"   json:"correct_verdict"`
	RequiredFindings int `yaml:"required_findings" json:"required_findings"`
	CorrectMitre     int `yaml:"correct_mitre"     json:"correct_mitre"`
	WriteupQuality   int `yaml:"writeup_quality"   json:"writeup_quality"`
	IOCEnrichment    int `yaml:"ioc_enrichment"    json:"ioc_enrichment"`
}

type TimeBonus struct {
	ThresholdMinutes int `yaml:"threshold_minutes" json:"threshold_minutes"`
	BonusPoints      int `yaml:"bonus_points"      json:"bonus_points"`
}

type Rubric struct {
	ExpectedVerdict    string         `yaml:"expected_verdict"    json:"expected_verdict"`
	ExpectedEscalation string         `yaml:"expected_escalation" json:"expected_escalation"`
	RequiredMitre      []string       `yaml:"required_mitre"      json:"required_mitre"`
	ScoreBreakdown     ScoreBreakdown `yaml:"score_breakdown"     json:"score_breakdown"`
	PassingScore       int            `yaml:"passing_score"       json:"passing_score"`
	DifficultyModifier float64        `yaml:"difficulty_modifier" json:"difficulty_modifier"`
	TimeBonus          TimeBonus      `yaml:"time_bonus"          json:"time_bonus"`
	MinWriteupWords    int            `yaml:"min_writeup_words"   json:"min_writeup_words"`
}

type Lab struct {
	ID                string     `yaml:"id"                 json:"id"`
	Title             string     `yaml:"title"              json:"title"`
	Difficulty        string     `yaml:"difficulty"         json:"difficulty"`
	Category          string     `yaml:"category"           json:"category"`
	Tags              []string   `yaml:"tags"               json:"tags"`
	Mitre             []MitreTag `yaml:"mitre"              json:"mitre"`
	Alert             Alert      `yaml:"alert"              json:"alert"`
	Scenario          string     `yaml:"scenario"           json:"scenario"`
	RationaleKeywords []string   `yaml:"rationale_keywords" json:"rationale_keywords"`
	Rubric            Rubric     `yaml:"rubric"             json:"rubric"`

	// populated after loading
	HasEmail bool `yaml:"-" json:"has_email"`
	HasPCAP  bool `yaml:"-" json:"has_pcap"`
	LabDir   string `yaml:"-" json:"-"`
}

func (l *Lab) MitreTagsJSON() string {
	ids := make([]string, len(l.Mitre))
	for i, m := range l.Mitre {
		ids[i] = m.ID
	}
	b, _ := json.Marshal(ids)
	return string(b)
}

func (l *Lab) AlertJSON() string {
	b, _ := json.Marshal(l.Alert)
	return string(b)
}

func (l *Lab) RubricJSON() string {
	b, _ := json.Marshal(l.Rubric)
	return string(b)
}

type Registry struct {
	labs   map[string]*Lab
	byDiff map[string][]*Lab
}

func LoadRegistry(labsDir string) (*Registry, error) {
	r := &Registry{
		labs:   make(map[string]*Lab),
		byDiff: make(map[string][]*Lab),
	}
	entries, err := os.ReadDir(labsDir)
	if err != nil {
		return nil, fmt.Errorf("read labs dir: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		yamlPath := filepath.Join(labsDir, e.Name(), "lab.yaml")
		data, err := os.ReadFile(yamlPath)
		if err != nil {
			continue
		}
		var l Lab
		if err := yaml.Unmarshal(data, &l); err != nil {
			return nil, fmt.Errorf("parse %s: %w", yamlPath, err)
		}
		l.LabDir = filepath.Join(labsDir, e.Name())
		l.HasEmail = dirHasFiles(filepath.Join(l.LabDir, "email"))
		l.HasPCAP = dirHasFiles(filepath.Join(l.LabDir, "pcap"))
		r.labs[l.ID] = &l
		r.byDiff[l.Difficulty] = append(r.byDiff[l.Difficulty], &l)
	}
	return r, nil
}

func (r *Registry) Get(id string) (*Lab, bool) {
	l, ok := r.labs[id]
	return l, ok
}

func (r *Registry) All() []*Lab {
	out := make([]*Lab, 0, len(r.labs))
	for _, l := range r.labs {
		out = append(out, l)
	}
	return out
}

func (r *Registry) ByDifficulty(d string) []*Lab {
	return r.byDiff[d]
}

func dirHasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			return true
		}
	}
	return false
}
