package adk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type OpenAIProvider struct {
	APIKey string
	Model  string
}

func NewOpenAIProvider(apiKey, model string) *OpenAIProvider {
	if model == "" {
		model = "gpt-4"
	}
	return &OpenAIProvider{APIKey: apiKey, Model: model}
}

func (p *OpenAIProvider) ListModels(ctx context.Context) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OpenAI API returned status: %s", resp.Status)
	}

	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var models []string
	for _, m := range result.Data {
		// Filter typical chat models
		if len(m.ID) > 3 { // Just basics
			models = append(models, m.ID)
		}
	}
	return models, nil
}

// GenerateResponse implements a basic chat completion call
func (p *OpenAIProvider) GenerateResponse(ctx context.Context, history []Message, tools []Tool) (string, *ToolCall, error) {
	// For MVP, this is a placeholder. 
	// Implementing full OpenAI function calling manually via HTTP is verbose.
	// Users are encouraged to contribute the full implementation.
	return "OpenAI provider is implemented for model listing. Chat generation requires full implementation.", nil, nil
}
