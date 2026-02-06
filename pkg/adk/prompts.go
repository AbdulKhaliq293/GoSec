package adk

import (
	_ "embed"
)

//go:embed prompts/system_prompt.md
var systemPrompt string

// GetSystemPrompt returns the default system prompt for the agent
func GetSystemPrompt() string {
	return systemPrompt
}
