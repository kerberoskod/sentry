package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SecretCheck struct{}

func (s *SecretCheck) Name() string { return "secrets" }

var secretPatterns = []struct {
	regex    *regexp.Regexp
	severity Severity
	category string
}{
	{regexp.MustCompile(`(?i)-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE KEY-----`), SeverityCritical, "secret"},
	{regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), SeverityCritical, "aws"},
	{regexp.MustCompile(`(?i)sk-[a-zA-Z0-9_-]{20,}`), SeverityCritical, "api-key"},
	{regexp.MustCompile(`(?i)pk-[a-zA-Z0-9_-]{20,}`), SeverityCritical, "api-key"},
	{regexp.MustCompile(`(?i)(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}`), SeverityCritical, "github-token"},
	{regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9_-]{16,}['"]`), SeverityHigh, "api-key"},
	{regexp.MustCompile(`(?i)(?:secret|token|password)\s*[:=]\s*['"][a-zA-Z0-9!@#$%^&*()_+=\-{}[\]|;:',.<>?]{8,}['"]`), SeverityHigh, "credential"},
	{regexp.MustCompile(`(?i)JFrog|jfrog\.io|artifactory`), SeverityMedium, "internal"},
	{regexp.MustCompile(`GOOGLE_APPLICATION_CREDENTIALS|AIza[0-9A-Za-z_-]{35}`), SeverityCritical, "gcp"},
	{regexp.MustCompile(`(?i)-----BEGIN\s+CERTIFICATE-----`), SeverityHigh, "certificate"},
	{regexp.MustCompile(`(?i)-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----`), SeverityCritical, "pgp-key"},
	{regexp.MustCompile(`ssh-rsa\s+AAAA|ssh-ed25519\s+AAA|ssh-dss\s+AAA`), SeverityHigh, "ssh-key"},
	{regexp.MustCompile(`xox[baprs]-[0-9a-z-]{10,}`), SeverityCritical, "slack-token"},
	{regexp.MustCompile(`(?i)AC[a-z0-9_-]{32}`), SeverityCritical, "twilio-account"},
	{regexp.MustCompile(`(?i)SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`), SeverityCritical, "sendgrid-key"},
	{regexp.MustCompile(`(?i)heroku[a-z0-9_-]{32}`), SeverityCritical, "heroku-api"},
	{regexp.MustCompile(`(?:jdbc|mysql|postgres)://[a-zA-Z0-9]+:[a-zA-Z0-9]+@`), SeverityHigh, "database-url"},
	{regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`), SeverityMedium, "jwt"},
}

var excludeDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	"target": true, "dist": true, ".venv": true, "__pycache__": true,
}

func (s *SecretCheck) Run(root string) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && excludeDirs[info.Name()] {
			return filepath.SkipDir
		}
		if info.IsDir() || info.Size() > 1024*1024 {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" ||
			ext == ".ico" || ext == ".svg" || ext == ".woff" || ext == ".woff2" ||
			ext == ".ttf" || ext == ".eot" || ext == ".o" || ext == ".so" ||
			ext == ".dll" || ext == ".class" || ext == ".jar" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		rel, _ := filepath.Rel(root, path)
		lineNum := 0
		scanner := bufio.NewScanner(f)
		buf := make([]byte, 1024*64)
		scanner.Buffer(buf, 1024*64)
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, p := range secretPatterns {
				matches := p.regex.FindStringSubmatchIndex(line)
				if matches != nil {
					findings = append(findings, Finding{
						Severity:    p.severity,
						Title:       fmt.Sprintf("Potential %s secret found", p.category),
						Description: fmt.Sprintf("A potential %s was detected in the codebase.", p.category),
						File:        rel,
						Line:        lineNum,
						Category:    "secret",
						Suggestion:  "Remove this secret from source control. Use environment variables or a secrets manager.",
					})
				}
			}
		}
		return nil
	})

	return findings, err
}

func isSecretLine(line string) bool {
	lower := strings.ToLower(line)
	for _, kw := range []string{"password", "secret", "token", "api_key", "apikey", "private_key"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
