package scanner

import (
	"fmt"
	"os"
)

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

type Finding struct {
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Category    string   `json:"category"`
	Suggestion  string   `json:"suggestion"`
}

type Scanner struct {
	checks []Check
}

type Check interface {
	Name() string
	Run(root string) ([]Finding, error)
}

func New() *Scanner {
	return &Scanner{
		checks: []Check{
			&SecretCheck{},
			&EnvCheck{},
			&DockerfileCheck{},
			&GitignoreCheck{},
		},
	}
}

func (s *Scanner) Scan(root string) ([]Finding, error) {
	var all []Finding

	for _, c := range s.checks {
		findings, err := c.Run(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s check failed: %v\n", c.Name(), err)
			continue
		}
		all = append(all, findings...)
	}

	return all, nil
}
