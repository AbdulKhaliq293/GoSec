package adk

import (
	"context"
	"fmt"
)

// Tool represents an executable action for the agent
type Tool interface {
	Name() string
	Description() string
	Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error)
	Schema() map[string]interface{} // JSON schema for arguments
}

// ToolCall represents a request from the LLM to execute a tool
type ToolCall struct {
	ToolName string
	Args     map[string]interface{}
}

// Message represents a chat message
type Message struct {
	Role    string // "user", "model", "system"
	Content string
}

// LLMProvider defines the interface for different AI models
type LLMProvider interface {
	GenerateResponse(ctx context.Context, history []Message, tools []Tool) (string, *ToolCall, error)
	ListModels(ctx context.Context) ([]string, error)
}

// Agent is the core ADK agent
type Agent struct {
	llm     LLMProvider
	tools   map[string]Tool
	history []Message
}

// NewAgent creates a new agent with the given LLM provider
func NewAgent(llm LLMProvider) *Agent {
	return &Agent{
		llm:   llm,
		tools: make(map[string]Tool),
	}
}

// RegisterTool adds a tool to the agent's registry
func (a *Agent) RegisterTool(t Tool) {
	a.tools[t.Name()] = t
}

// Chat sends a message to the agent and returns the response
func (a *Agent) Chat(ctx context.Context, input string, progress func(string)) (string, error) {
	// Add user message to history
	a.history = append(a.history, Message{Role: "user", Content: input})

	// Generate response (loop for tool calls)
	for {
		toolList := make([]Tool, 0, len(a.tools))
		for _, t := range a.tools {
			toolList = append(toolList, t)
		}

		respText, toolCall, err := a.llm.GenerateResponse(ctx, a.history, toolList)
		if err != nil {
			return "", err
		}

		// If the model just replied with text, we are done
		if toolCall == nil {
			a.history = append(a.history, Message{Role: "model", Content: respText})
			return respText, nil
		}

		// If the model requested a tool execution
		Debugf("Executing tool: %s with args: %v", toolCall.ToolName, toolCall.Args)
		
		// Record the model's intent to call the tool
		a.history = append(a.history, Message{
			Role:    "model", 
			Content: fmt.Sprintf("I will call tool %s with args %v", toolCall.ToolName, toolCall.Args),
		})

		tool, exists := a.tools[toolCall.ToolName]
		if !exists {
			errMsg := fmt.Sprintf("Tool %s not found", toolCall.ToolName)
			a.history = append(a.history, Message{Role: "function", Content: fmt.Sprintf("Error: %s", errMsg)})
			continue
		}

		result, err := tool.Execute(ctx, toolCall.Args, progress)
		if err != nil {
			result = fmt.Sprintf("Error executing tool: %v", err)
		}

		// Add tool result to history (as system or function role)
		// For simplicity, we'll format it into the history
		a.history = append(a.history, Message{
			Role:    "function", 
			Content: fmt.Sprintf("Tool %s returned: %s", toolCall.ToolName, result),
		})
		
		// Loop back to give the result to the LLM
	}
}
