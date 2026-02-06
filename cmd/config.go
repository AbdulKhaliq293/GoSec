package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/user/gosec-adk/pkg/adk"
	"github.com/user/gosec-adk/pkg/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration (providers, models, keys)",
}

var setKeyCmd = &cobra.Command{
	Use:   "set-key",
	Short: "Manually set API key for a provider",
	Run: func(cmd *cobra.Command, args []string) {
		provider, _ := cmd.Flags().GetString("provider")
		key, _ := cmd.Flags().GetString("key")

		if provider == "" || key == "" {
			fmt.Println("Error: --provider and --key are required")
			return
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		cfg.SetAPIKey(strings.ToLower(provider), key)
		if err := config.SaveConfig(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Printf("API key saved for provider: %s\n", provider)
	},
}

var setModelCmd = &cobra.Command{
	Use:   "set-model",
	Short: "Manually set the active provider and model",
	Run: func(cmd *cobra.Command, args []string) {
		provider, _ := cmd.Flags().GetString("provider")
		model, _ := cmd.Flags().GetString("model")

		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		if provider != "" {
			cfg.SelectedProvider = strings.ToLower(provider)
		}
		if model != "" {
			cfg.SelectedModel = model
		}

		if err := config.SaveConfig(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Printf("Active configuration updated: Provider=%s, Model=%s\n", cfg.SelectedProvider, cfg.SelectedModel)
	},
}

var listModelsCmd = &cobra.Command{
	Use:   "list-models",
	Short: "List available models from the configured provider",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Println("Error loading config:", err)
			return
		}
		
		provider := cfg.SelectedProvider
		if provider == "" {
			fmt.Println("No provider selected. Please run 'gosec-adk config setup'.")
			return
		}
		apiKey := cfg.GetAPIKey(provider)
		if apiKey == "" {
			fmt.Printf("No API key found for %s.\n", provider)
			return
		}

		fmt.Printf("Fetching models for %s...\n", provider)
		ctx := context.Background()
		p, err := adk.NewProvider(ctx, provider, apiKey, "")
		if err != nil {
			fmt.Println("Error initializing provider:", err)
			return
		}

		models, err := p.ListModels(ctx)
		if err != nil {
			fmt.Println("Error fetching models:", err)
			return
		}

		fmt.Printf("\nAvailable Models (%s):\n", provider)
		for _, m := range models {
			mark := " "
			if m == cfg.SelectedModel {
				mark = "*"
			}
			fmt.Printf("%s %s\n", mark, m)
		}
	},
}

func init() {
	setKeyCmd.Flags().StringP("provider", "p", "", "Provider (gemini, openai, anthropic)")
	setKeyCmd.Flags().StringP("key", "k", "", "API Key")
	
	setModelCmd.Flags().StringP("provider", "p", "", "Provider (gemini, openai, anthropic)")
	setModelCmd.Flags().StringP("model", "m", "", "Model name")

	configCmd.AddCommand(setKeyCmd)
	configCmd.AddCommand(setModelCmd)
	configCmd.AddCommand(listModelsCmd)
	rootCmd.AddCommand(configCmd)
}
