package cmd

import (
	"fmt"
	"os"

	"github.com/kerberoskod/sentry/output"
	"github.com/kerberoskod/sentry/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan project for security issues",
	Long:  `Scan the project for hardcoded secrets, misconfigurations, and vulnerable dependencies.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		useJSON, _ := cmd.Flags().GetBool("json")
		strict, _ := cmd.Flags().GetBool("strict")
		report, _ := cmd.Flags().GetString("report")

		s := scanner.New()
		findings, err := s.Scan(path)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		if report != "" {
			if err := output.PrintHTML(findings, report); err != nil {
				return fmt.Errorf("failed to write report: %w", err)
			}
			fmt.Printf("HTML report written to %s\n", report)
		}

		if useJSON {
			return output.PrintJSON(findings)
		}

		critical := 0
		high := 0
		medium := 0
		low := 0
		for _, f := range findings {
			switch f.Severity {
			case scanner.SeverityCritical:
				critical++
			case scanner.SeverityHigh:
				high++
			case scanner.SeverityMedium:
				medium++
			case scanner.SeverityLow:
				low++
			}
		}

		fmt.Printf("Scan complete: %d issues found\n", len(findings))
		fmt.Printf("  %d critical  %d high  %d medium  %d low\n\n",
			critical, high, medium, low)

		if len(findings) > 0 {
			output.PrintFindings(findings)
		}

		if strict && len(findings) > 0 {
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().String("report", "", "Write HTML report to file")
}
