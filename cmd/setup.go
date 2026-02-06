package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/user/gosec-adk/pkg/adk"
	"github.com/user/gosec-adk/pkg/config"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive setup wizard",
	Run: func(cmd *cobra.Command, args []string) {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("Welcome to GoSec-ADK Setup Wizard")
		fmt.Println("---------------------------------")

		// 1. Select Provider
		fmt.Println("Step 1: Choose your AI Provider")
		fmt.Println("1. Gemini (Google)")
		fmt.Println("2. OpenAI")
		fmt.Println("3. Anthropic")
		fmt.Print("Enter number or name > ")
		scanner.Scan()
		choice := strings.ToLower(strings.TrimSpace(scanner.Text()))
		
		var provider string
		switch choice {
		case "1", "gemini":
			provider = "gemini"
		case "2", "openai":
			provider = "openai"
		case "3", "anthropic":
			provider = "anthropic"
		default:
			fmt.Println("Invalid choice. Aborting.")
			return
		}

		// 2. Enter API Key
		fmt.Printf("\nStep 2: Enter API Key for %s\n", provider)
		fmt.Print("> ")
		scanner.Scan()
		apiKey := strings.TrimSpace(scanner.Text())
		if apiKey == "" {
			fmt.Println("API Key cannot be empty.")
			return
		}

		// 3. Fetch Models
		fmt.Println("\nStep 3: Validating key and fetching available models...")
		ctx := context.Background()
		
		// Create temporary provider instance to list models
		// We pass empty model name initially
		tempProvider, err := adk.NewProvider(ctx, provider, apiKey, "")
		if err != nil {
			fmt.Printf("Error initializing provider: %v\n", err)
			return
		}

		models, err := tempProvider.ListModels(ctx)
		var selectedModel string

		if err != nil {
			fmt.Printf("Warning: Could not fetch models from API: %v\n", err)
			fmt.Println("Please enter model name manually (e.g., 'gemini-pro', 'gpt-4'):")
			fmt.Print("> ")
			scanner.Scan()
			selectedModel = strings.TrimSpace(scanner.Text())
		} else {
			fmt.Printf("Successfully retrieved %d models.\n", len(models))
			for i, m := range models {
				fmt.Printf("%d. %s\n", i+1, m)
			}
			fmt.Print("Select Model (number) > ")
			scanner.Scan()
			selStr := strings.TrimSpace(scanner.Text())
			selIdx, err := strconv.Atoi(selStr)
			if err != nil || selIdx < 1 || selIdx > len(models) {
				fmt.Println("Invalid selection. Using first available model.")
				selectedModel = models[0]
			} else {
				selectedModel = models[selIdx-1]
			}
		}

		// 4. Save Configuration
		fmt.Println("\nStep 4: Saving Configuration...")
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		cfg.SelectedProvider = provider
		cfg.SelectedModel = selectedModel
		cfg.SetAPIKey(provider, apiKey)

		if err := config.SaveConfig(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}

		fmt.Println("---------------------------------")
		fmt.Println("Setup Complete!")
		fmt.Printf("Provider: %s\n", provider)
		fmt.Printf("Model:    %s\n", selectedModel)
		fmt.Println("You can now run 'gosec-adk interactive'")
	},
}

func init() {
	configCmd.AddCommand(setupCmd)
}
