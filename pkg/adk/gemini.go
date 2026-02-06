package adk

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type GeminiProvider struct {
	client *genai.Client
	model  *genai.GenerativeModel
}

func NewGeminiProvider(ctx context.Context, apiKey string, modelName string) (*GeminiProvider, error) {
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, err
	}
	
	if modelName == "" {
		modelName = "gemini-pro"
	}

	model := client.GenerativeModel(modelName)
	model.SetTemperature(0)
	
	return &GeminiProvider{client: client, model: model}, nil
}

func (g *GeminiProvider) ListModels(ctx context.Context) ([]string, error) {
	iter := g.client.ListModels(ctx)
	var names []string
	for {
		m, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		// Only list models that support content generation (rough filter)
		if strings.Contains(m.Name, "gemini") {
			// m.Name is like "models/gemini-pro", we usually want just "gemini-pro"
			names = append(names, strings.TrimPrefix(m.Name, "models/"))
		}
	}
	return names, nil
}

func (g *GeminiProvider) GenerateResponse(ctx context.Context, history []Message, tools []Tool) (string, *ToolCall, error) {
	// Configure tools for the session
	var toolDefs []*genai.FunctionDeclaration
	for _, t := range tools {
		toolDefs = append(toolDefs, &genai.FunctionDeclaration{
			Name:        t.Name(),
			Description: t.Description(),
			Parameters:  convertSchema(t.Schema()),
		})
	}

	if len(toolDefs) > 0 {
		g.model.Tools = []*genai.Tool{
			{
				FunctionDeclarations: toolDefs,
			},
		}
	}

	var cs []*genai.Content
	for _, msg := range history {
		role := "user"
		if msg.Role == "model" {
			role = "model"
		} else if msg.Role == "function" {
			// Convert function output to user message so the model sees it
			role = "user" 
		}

		cs = append(cs, &genai.Content{
			Parts: []genai.Part{
				genai.Text(msg.Content),
			},
			Role: role,
		})
	}

	session := g.model.StartChat()
	session.History = cs

	if len(cs) > 0 {
		session.History = cs[:len(cs)-1]
		lastMsg := cs[len(cs)-1]
		
		resp, err := session.SendMessage(ctx, lastMsg.Parts...)
		if err != nil {
			return "", nil, err
		}

		if len(resp.Candidates) == 0 {
			return "", nil, fmt.Errorf("no response candidates")
		}

		cand := resp.Candidates[0]
		
		var responseText string
		var toolCall *ToolCall

		for _, part := range cand.Content.Parts {
			if funcCall, ok := part.(genai.FunctionCall); ok {
				toolCall = &ToolCall{
					ToolName: funcCall.Name,
					Args:     funcCall.Args,
				}
			}
			if text, ok := part.(genai.Text); ok {
				responseText += string(text)
			}
		}

		if toolCall != nil {
			return responseText, toolCall, nil
		}
		if responseText != "" {
			return responseText, nil, nil
		}
	}

	return "", nil, fmt.Errorf("empty history or no response")
}

func (g *GeminiProvider) Close() {
	g.client.Close()
}

func convertSchema(input map[string]interface{}) *genai.Schema {
	if input == nil {
		return nil
	}

	s := &genai.Schema{}

	if t, ok := input["type"].(string); ok {
		switch t {
		case "string":
			s.Type = genai.TypeString
		case "number":
			s.Type = genai.TypeNumber
		case "integer":
			s.Type = genai.TypeInteger
		case "boolean":
			s.Type = genai.TypeBoolean
		case "array":
			s.Type = genai.TypeArray
		case "object":
			s.Type = genai.TypeObject
		}
	}

	if d, ok := input["description"].(string); ok {
		s.Description = d
	}

	if props, ok := input["properties"].(map[string]interface{}); ok {
		s.Properties = make(map[string]*genai.Schema)
		for k, v := range props {
			if vMap, ok := v.(map[string]interface{}); ok {
				s.Properties[k] = convertSchema(vMap)
			}
		}
	}

	if req, ok := input["required"].([]string); ok {
		s.Required = req
	} else if reqInterface, ok := input["required"].([]interface{}); ok {
		for _, r := range reqInterface {
			if rStr, ok := r.(string); ok {
				s.Required = append(s.Required, rStr)
			}
		}
	}

	return s
}
