package output

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/kerberoskod/sentry/scanner"
)

var reportTemplate = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentry Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f7; color: #1d1d1f; padding: 2rem; }
  .container { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem; }
  .summary { color: #86868b; margin-bottom: 2rem; }
  .section { margin-bottom: 2rem; }
  .section h2 { font-size: 1.125rem; font-weight: 600; margin-bottom: 0.75rem; padding-bottom: 0.5rem; border-bottom: 2px solid {{.Color}}; }
  .finding { background: #fff; border-radius: 12px; padding: 1rem; margin-bottom: 0.75rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .finding .title { font-weight: 600; color: {{.Color}}; margin-bottom: 0.25rem; }
  .finding .desc { font-size: 0.875rem; color: #86868b; margin-bottom: 0.5rem; }
  .finding .meta { font-size: 0.75rem; color: #6b7280; }
  .finding .meta strong { color: #1d1d1f; }
  .finding .suggestion { font-size: 0.8125rem; color: #2563eb; margin-top: 0.5rem; }
  .empty { color: #6b7280; font-style: italic; font-size: 0.875rem; }
</style>
</head>
<body>
<div class="container">
  <h1>Sentry Security Report</h1>
  <p class="summary">{{len .AllFindings}} issues found</p>
  {{range .Groups}}
  <div class="section">
    <h2 style="border-color: {{.Color}}">{{.Severity}} ({{len .Findings}})</h2>
    {{if .Findings}}
      {{range .Findings}}
      <div class="finding">
        <div class="title">{{.Title}}</div>
        <div class="desc">{{.Description}}</div>
        <div class="meta">
          <strong>File:</strong> {{.File}}{{if .Line}}:{{.Line}}{{end}} &middot;
          <strong>Category:</strong> {{.Category}}
        </div>
        <div class="suggestion">💡 {{.Suggestion}}</div>
      </div>
      {{end}}
    {{else}}
      <p class="empty">No issues found</p>
    {{end}}
  </div>
  {{end}}
</div>
</body>
</html>`))

func PrintJSON(findings []scanner.Finding) error {
	type jsonFinding struct {
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Description string `json:"description"`
		File        string `json:"file"`
		Line        int    `json:"line"`
		Category    string `json:"category"`
		Suggestion  string `json:"suggestion"`
	}

	var jf []jsonFinding
	for _, f := range findings {
		jf = append(jf, jsonFinding{
			Severity:    f.Severity.String(),
			Title:       f.Title,
			Description: f.Description,
			File:        f.File,
			Line:        f.Line,
			Category:    f.Category,
			Suggestion:  f.Suggestion,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(jf)
}

func PrintFindings(findings []scanner.Finding) error {
	for i, f := range findings {
		icon := ""
		switch f.Severity {
		case scanner.SeverityCritical:
			icon = "🔴"
		case scanner.SeverityHigh:
			icon = "🟡"
		case scanner.SeverityMedium:
			icon = "🔵"
		case scanner.SeverityLow:
			icon = "⚪"
		}

		fmt.Printf("%s  [%s] %s\n", icon, f.Severity.String(), f.Title)
		fmt.Printf("    %s\n", f.Description)
		if f.File != "" {
			fmt.Printf("    File: %s", f.File)
			if f.Line > 0 {
				fmt.Printf(":%d", f.Line)
			}
			fmt.Println()
		}
		fmt.Printf("    💡 %s\n", f.Suggestion)

		if i < len(findings)-1 {
			fmt.Println()
		}
	}

	return nil
}

func PrintHTML(findings []scanner.Finding, reportPath string) error {
	type tmplGroup struct {
		Severity string
		Color    string
		Findings []scanner.Finding
	}

	groups := []tmplGroup{
		{"Critical", "#dc2626", nil},
		{"High", "#ea580c", nil},
		{"Medium", "#2563eb", nil},
		{"Low", "#6b7280", nil},
	}

	for _, f := range findings {
		idx := 0
		switch f.Severity {
		case scanner.SeverityCritical:
			idx = 0
		case scanner.SeverityHigh:
			idx = 1
		case scanner.SeverityMedium:
			idx = 2
		case scanner.SeverityLow:
			idx = 3
		}
		groups[idx].Findings = append(groups[idx].Findings, f)
	}

	tmpl := reportTemplate

	abs, err := filepath.Abs(reportPath)
	if err != nil {
		return err
	}

	f, err := os.Create(abs)
	if err != nil {
		return err
	}
	defer f.Close()

	type pageData struct {
		AllFindings []scanner.Finding
		Groups      []tmplGroup
	}

	return tmpl.Execute(f, pageData{
		AllFindings: findings,
		Groups:      groups,
	})
}
