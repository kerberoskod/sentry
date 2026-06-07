package scanner

import (
	"fmt"
	"os"
	"path/filepath"
)

type GitignoreCheck struct{}

func (g *GitignoreCheck) Name() string { return "gitignore" }

var recommendedEntries = []struct {
	entry    string
	severity Severity
	reason   string
}{
	{".env", SeverityHigh, "Environment variables with secrets"},
	{"node_modules/", SeverityMedium, "Node.js dependencies (bulky, can be restored)"},
	{"target/", SeverityMedium, "Build output directory"},
	{"dist/", SeverityLow, "Build output"},
	{"__pycache__/", SeverityLow, "Python bytecode cache"},
	{"*.log", SeverityMedium, "Log files may contain sensitive information"},
	{".DS_Store", SeverityLow, "macOS desktop service store files"},
	{"*.tsbuildinfo", SeverityLow, "TypeScript incremental build info"},
}

func (g *GitignoreCheck) Run(root string) ([]Finding, error) {
	var findings []Finding

	path := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(path)
	if err != nil {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "Missing .gitignore",
			Description: "No .gitignore file found in the project root.",
			File:        ".",
			Line:        0,
			Category:    "config",
			Suggestion:  "Create a .gitignore file to prevent committing sensitive or unnecessary files.",
		})
		return findings, nil
	}

	content := string(data)

	for _, entry := range recommendedEntries {
		if !containsLine(content, entry.entry) {
			findings = append(findings, Finding{
				Severity:    entry.severity,
				Title:       fmt.Sprintf("Missing .gitignore entry: %s", entry.entry),
				Description: fmt.Sprintf("'%s' is not in .gitignore. %s.", entry.entry, entry.reason),
				File:        ".gitignore",
				Line:        0,
				Category:    "config",
				Suggestion:  fmt.Sprintf("Add '%s' to your .gitignore file.", entry.entry),
			})
		}
	}

	return findings, nil
}
