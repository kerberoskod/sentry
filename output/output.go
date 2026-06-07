package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kerberoskod/sentry/scanner"
)

func PrintJSON(findings []scanner.Finding) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
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
