package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gosec-adk",
	Short: "AI-Powered Security Compliance Tool (ADK Pattern)",
	Long: `GoSec-ADK is an extensible, model-agnostic security tool that uses 
an AI agent to orchestrate compliance checks and reconnaissance tasks.`,
}

var DebugMode bool

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&DebugMode, "debug", false, "Enable debug logging")
}
