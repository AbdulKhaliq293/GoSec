package wrappers

import (
	"context"
	"fmt"
	"strings"

	"github.com/user/gosec-adk/pkg/engine"
)

// RemediationWrapper implements the Tool interface for generating remediation plans
type RemediationWrapper struct {
	Engine *engine.RemediationEngine
}

func (r *RemediationWrapper) Name() string {
	return "GenerateRemediation"
}

func (r *RemediationWrapper) Description() string {
	return "Generates a remediation plan (fix/validate/rollback commands) for a specific security issue. Use this when a critical vulnerability is found and you want to provide a fix."
}

func (r *RemediationWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"template_id": map[string]interface{}{
				"type":        "string",
				"description": "The ID of the remediation template to use. If omitted, lists available templates.",
			},
			"variables": map[string]interface{}{
				"type":        "object",
				"description": "Key-value pairs for template variables (e.g., {'port': '8080', 'user': 'admin'}).",
			},
		},
	}
}

func (r *RemediationWrapper) Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error) {
	if r.Engine == nil {
		return "Error: Remediation engine not initialized.", nil
	}

	templateID, _ := args["template_id"].(string)
	
	// Handle variables map
	vars := make(map[string]string)
	if v, ok := args["variables"].(map[string]interface{}); ok {
		for k, val := range v {
			vars[k] = fmt.Sprintf("%v", val)
		}
	} else if v, ok := args["variables"].(map[string]string); ok {
		vars = v
	}

	// Case 1: List templates
	if templateID == "" {
		templates := r.Engine.ListTemplates()
		if len(templates) == 0 {
			return "No remediation templates found.", nil
		}
		return fmt.Sprintf("Available Remediation Templates:\n- %s", strings.Join(templates, "\n- ")), nil
	}

	// Case 2: Generate Plan
	if progress != nil {
		progress(fmt.Sprintf("Generating remediation plan for %s...", templateID))
	}

	plan, err := r.Engine.GeneratePlan(templateID, vars)
	if err != nil {
		return fmt.Sprintf("Error generating plan: %v", err), nil
	}

	return plan, nil
}
