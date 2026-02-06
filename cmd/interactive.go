package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/user/gosec-adk/pkg/adk"
	"github.com/user/gosec-adk/pkg/config"
	"github.com/user/gosec-adk/pkg/engine"
	"github.com/user/gosec-adk/pkg/wrappers"
)

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Start the interactive agent session",
	Run: func(cmd *cobra.Command, args []string) {
		adk.DebugEnabled = DebugMode
		
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}

		providerName := cfg.SelectedProvider
		if providerName == "" {
			providerName = "gemini" // Default
		}
		
		apiKey := cfg.GetAPIKey(providerName)
		if apiKey == "" {
			// Fallback to env var for Gemini if not in config
			if providerName == "gemini" {
				apiKey = os.Getenv("GOOGLE_API_KEY")
			}
		}

		if apiKey == "" {
			fmt.Println("Error: API Key not found.")
			fmt.Println("Please run 'gosec-adk config setup' to configure your keys.")
			return
		}

		ctx := context.Background()
		modelName := cfg.SelectedModel
		fmt.Printf("Connecting to %s (Model: %s)...\n", providerName, modelName)
		
		provider, err := adk.NewProvider(ctx, providerName, apiKey, modelName)
		if err != nil {
			fmt.Printf("Error creating AI provider: %v\n", err)
			return
		}
		// Note: Not all providers have Close(), but Gemini does. 
		// For interface, we might need a Close method on LLMProvider if we want to be strict.
		// For now, we skip defer close to keep interface simple, or type assert.
		if closer, ok := provider.(interface{ Close() }); ok {
			defer closer.Close()
		}

		agent := adk.NewAgent(provider)

		// Initialize Compliance Engine
		eng := engine.NewEngine()
		// Initialize Unified Finding Graph
		graph := engine.NewUnifiedGraph()
		// Initialize Remediation Engine
		remediationEng := engine.NewRemediationEngine()
		
		// Determine profiles directory (assume ./profiles relative to CWD)
		// In a real app, this might be configurable
		if err := eng.LoadProfiles("profiles"); err != nil {
			fmt.Printf("Warning: Failed to load compliance profiles: %v\n", err)
		}
		
		if err := remediationEng.LoadTemplates("remediation_templates"); err != nil {
			fmt.Printf("Warning: Failed to load remediation templates: %v\n", err)
		}

		// Register Tools
		agent.RegisterTool(&wrappers.NmapWrapper{Graph: graph})
		agent.RegisterTool(&wrappers.LynisWrapper{Graph: graph})
		agent.RegisterTool(&wrappers.GraphViewerWrapper{Graph: graph})
		agent.RegisterTool(&wrappers.ComplianceWrapper{Engine: eng})
		agent.RegisterTool(&wrappers.RemediationWrapper{Engine: remediationEng})
		agent.RegisterTool(&wrappers.SaveSnapshotWrapper{Graph: graph})
		agent.RegisterTool(&wrappers.DiffSnapshotWrapper{Graph: graph})

		// Set System Prompt
		agent.SetSystemPrompt(adk.GetSystemPrompt())

		// Start chat loop
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("\n---------------------------------------------------------")
		fmt.Println("GoSec-ADK Agent Initialized. Ready for commands.")
		fmt.Println("Example: 'Scan localhost for open ports'")
		fmt.Println("Example: 'Run a system compliance audit'")
		fmt.Println("Type 'quit' or 'exit' to stop.")
		fmt.Println("---------------------------------------------------------")

		for {
			fmt.Print("\n> ")
			if !scanner.Scan() {
				break
			}
			input := scanner.Text()
			if input == "quit" || input == "exit" {
				break
			}
			if input == "" {
				continue
			}

			fmt.Print("Agent thinking... ")
			resp, err := agent.Chat(ctx, input, func(msg string) {
				// Clear current line and print progress
				fmt.Printf("\r\033[K[Progress]: %s\nAgent thinking... ", msg)
			})
			// Clear thinking line
			fmt.Print("\r\033[K")
			
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("\n[Agent]: %s\n", resp)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}
