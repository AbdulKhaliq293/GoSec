package adk

import (
	"context"
)

type AnthropicProvider struct {
	APIKey string
	Model  string
}

func NewAnthropicProvider(apiKey, model string) *AnthropicProvider {
	if model == "" {
		model = "claude-opus-4-5"
	}
	return &AnthropicProvider{APIKey: apiKey, Model: model}
}

func (p *AnthropicProvider) ListModels(ctx context.Context) ([]string, error) {
	// Anthropic API does not currently provide a dynamic list models endpoint.
	// Returning the standard supported models.
	return []string{
		"claude-sonnet-4-5",
		"claude-opus-4-5",
		"claude-haiku-4-5",
	}, nil
}

func (p *AnthropicProvider) GenerateResponse(ctx context.Context, history []Message, tools []Tool) (string, *ToolCall, error) {
	return "Anthropic provider is implemented for model selection. Chat generation requires full implementation.", nil, nil
}
