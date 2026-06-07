package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sentry",
	Short: "A security scanner for your projects",
	Long: `Sentry scans your codebase for hardcoded secrets,
misconfigurations, and vulnerable dependencies.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("path", "p", ".", "Project root directory")
	rootCmd.PersistentFlags().Bool("json", false, "Output in JSON format")
	rootCmd.PersistentFlags().Bool("strict", false, "Exit with error if issues found")
}
