package wrappers

import (
	"context"
	"fmt"
	"strings"

	"github.com/user/gosec-adk/pkg/engine"
)

// ComplianceWrapper implements the Tool interface for running compliance checks
type ComplianceWrapper struct {
	Engine *engine.Engine
}

func (c *ComplianceWrapper) Name() string {
	return "RunComplianceCheck"
}

func (c *ComplianceWrapper) Description() string {
	return "Runs specific compliance checks from loaded profiles (CIS, HIPAA, PCI-DSS, etc.). Can run a full standard or specific controls."
}

func (c *ComplianceWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"standard": map[string]interface{}{
				"type":        "string",
				"description": "The compliance standard to check (e.g., 'CIS', 'HIPAA', 'PCI-DSS'). If omitted, lists available standards.",
			},
			"control_id": map[string]interface{}{
				"type":        "string",
				"description": "Specific control ID to run (e.g., 'CIS-1.1'). If omitted, runs all controls for the standard.",
			},
		},
	}
}

func (c *ComplianceWrapper) Execute(ctx context.Context, args map[string]interface{}) (string, error) {
	if c.Engine == nil {
		return "Error: Compliance engine not initialized.", nil
	}

	standard, _ := args["standard"].(string)
	controlID, _ := args["control_id"].(string)

	// Case 1: List standards
	if standard == "" {
		stds := c.Engine.ListStandards()
		return fmt.Sprintf("Available Compliance Standards: %s", strings.Join(stds, ", ")), nil
	}

	// Case 2: Get Profile
	profile, ok := c.Engine.GetProfile(standard)
	if !ok {
		// Try case-insensitive matching if not found
		found := false
		for _, s := range c.Engine.ListStandards() {
			if strings.EqualFold(s, standard) {
				profile, _ = c.Engine.GetProfile(s)
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("Standard '%s' not found. Available: %s", standard, strings.Join(c.Engine.ListStandards(), ", ")), nil
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Compliance Check Results for %s:\n\n", profile.Standard))

	ranCount := 0
	passCount := 0
	failCount := 0

	for _, control := range profile.Controls {
		// Filter by control_id if provided
		if controlID != "" && control.ID != controlID {
			continue
		}

		passed, output, err := control.Execute(ctx)
		ranCount++
		
		status := "PASS"
		if !passed {
			status = "FAIL"
			failCount++
		} else {
			passCount++
		}

		if err != nil {
			status = "ERROR"
			output = err.Error()
		}

		sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", status, control.ID, control.Name))
		if !passed || err != nil {
			sb.WriteString(fmt.Sprintf("  Output: %s\n", output))
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n", control.Remediation))
		}
		sb.WriteString("\n")
	}

	if ranCount == 0 {
		return fmt.Sprintf("No controls found matching ID '%s' in standard '%s'.", controlID, standard), nil
	}

	sb.WriteString(fmt.Sprintf("Summary: %d Checks, %d Passed, %d Failed", ranCount, passCount, failCount))
	return sb.String(), nil
}
