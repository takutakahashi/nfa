package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "nfa",
	Short: "Network filter for agent — transparent proxy with domain allow/deny filtering",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(setupIptablesCmd)
}
