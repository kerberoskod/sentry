package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type EnvCheck struct{}

func (e *EnvCheck) Name() string { return "env" }

func (e *EnvCheck) Run(root string) ([]Finding, error) {
	var findings []Finding

	envPath := filepath.Join(root, ".env")
	gitignorePath := filepath.Join(root, ".gitignore")

	if _, err := os.Stat(envPath); err == nil {
		if _, err := os.Stat(gitignorePath); err == nil {
			data, err := os.ReadFile(gitignorePath)
			if err == nil {
				content := string(data)
				if !containsLine(content, ".env") {
					findings = append(findings, Finding{
						Severity:    SeverityHigh,
						Title:       ".env file not in .gitignore",
						Description: "A .env file exists but is not listed in .gitignore. Secrets may be accidentally committed.",
						File:        ".gitignore",
						Line:        0,
						Category:    "config",
						Suggestion:  "Add '.env' to your .gitignore file to prevent committing environment variables.",
					})
				}
			}
		}
	}

	envExample := filepath.Join(root, ".env.example")
	if _, err := os.Stat(envExample); os.IsNotExist(err) {
		findings = append(findings, Finding{
			Severity:    SeverityMedium,
			Title:       "Missing .env.example",
			Description: "No .env.example file found. This helps other developers understand required environment variables.",
			File:        ".",
			Line:        0,
			Category:    "config",
			Suggestion:  "Create a .env.example file with placeholder values for all required environment variables.",
		})
	}

	return findings, nil
}

func containsLine(content, substr string) bool {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == substr || strings.HasPrefix(line, substr+"=") {
			return true
		}
	}
	return false
}
