package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type DockerfileCheck struct{}

func (d *DockerfileCheck) Name() string { return "dockerfile" }

func (d *DockerfileCheck) Run(root string) ([]Finding, error) {
	var findings []Finding

	paths := []string{
		filepath.Join(root, "Dockerfile"),
		filepath.Join(root, "docker-compose.yml"),
		filepath.Join(root, "docker-compose.yaml"),
	}

	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}

		rel, _ := filepath.Rel(root, p)
		lineNum := 0
		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			upper := strings.ToUpper(line)

			if strings.HasPrefix(upper, "USER ROOT") || upper == "USER 0" || strings.HasPrefix(upper, "USER 0 ") {
				findings = append(findings, Finding{
					Severity:    SeverityHigh,
					Title:       "Container runs as root",
					Description: "The Docker container runs as the root user, which is a security risk.",
					File:        rel,
					Line:        lineNum,
					Category:    "docker",
					Suggestion:  "Add 'USER nobody' or create a dedicated user with 'RUN adduser -D appuser && USER appuser'.",
				})
			}

			if strings.HasPrefix(upper, "ADD ") && !strings.HasPrefix(upper, "ADD .") {
				findings = append(findings, Finding{
					Severity:    SeverityLow,
					Title:       "Using ADD instead of COPY",
					Description: "ADD has extra features (like tar extraction) that can be unexpected. COPY is preferred.",
					File:        rel,
					Line:        lineNum,
					Category:    "docker",
					Suggestion:  "Replace ADD with COPY unless you specifically need ADD's automatic tar extraction or URL support.",
				})
			}

			if strings.HasPrefix(upper, "FROM ") && strings.Contains(upper, ":LATEST") {
				findings = append(findings, Finding{
					Severity:    SeverityMedium,
					Title:       "Using 'latest' tag",
					Description: "Using the 'latest' tag can lead to unexpected behavior when base images are updated.",
					File:        rel,
					Line:        lineNum,
					Category:    "docker",
					Suggestion:  "Pin a specific version tag instead of 'latest'.",
				})
			}
		}
		f.Close()
	}

	return findings, nil
}
