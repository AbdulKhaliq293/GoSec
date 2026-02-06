package adk

import (
	"context"
	"fmt"
)

func NewProvider(ctx context.Context, providerName, apiKey, modelName string) (LLMProvider, error) {
	switch providerName {
	case "gemini":
		return NewGeminiProvider(ctx, apiKey, modelName)
	case "openai":
		return NewOpenAIProvider(apiKey, modelName), nil
	case "anthropic":
		return NewAnthropicProvider(apiKey, modelName), nil
	default:
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}
}
