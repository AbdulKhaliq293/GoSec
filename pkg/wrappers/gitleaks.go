package wrappers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/user/gosec-adk/pkg/engine"
)

// GitleaksWrapper implements the Tool interface for Gitleaks
type GitleaksWrapper struct {
	Graph *engine.UnifiedGraph
}

func (g *GitleaksWrapper) Name() string {
	return "RunSecretScan"
}

func (g *GitleaksWrapper) Description() string {
	return "Scans a directory or repository for hardcoded secrets using Gitleaks."
}

func (g *GitleaksWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{
				"type":        "string",
				"description": "Path to the directory or repository to scan. Defaults to current directory.",
			},
		},
	}
}

func (g *GitleaksWrapper) Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error) {
	// Check if gitleaks is installed
	if _, err := exec.LookPath("gitleaks"); err != nil {
		fmt.Println("Error: 'gitleaks' binary not found. Please install it (e.g., 'brew install gitleaks') to use this tool.")
		return "Error: 'gitleaks' binary not found. Please install it (e.g., 'brew install gitleaks') to use this tool.", nil
	}

	targetPath := "."
	if p, ok := args["path"].(string); ok && p != "" {
		targetPath = p
	}
	
	// Handle simplified 'args' string
	if val, ok := args["args"].(string); ok && targetPath == "." {
		// If the user provided a path in the generic args
		if val != "" && !strings.HasPrefix(val, "-") {
			targetPath = val
		}
	}

	// Create temp file for JSON report
	reportFile, err := os.CreateTemp("", "gitleaks-report-*.json")
	if err != nil {
		return fmt.Sprintf("Error creating temp file: %v", err), nil
	}
	reportPath := reportFile.Name()
	reportFile.Close()
	defer os.Remove(reportPath)

	fmt.Printf("[Gitleaks] Scanning %s...\n", targetPath)
	
	// Prepare command
	// gitleaks detect --source <path> --report-path <json> --no-git (if not a git repo, or just let it detect)
	// We use 'detect' command.
	cmdArgs := []string{"detect", "--source", targetPath, "--report-path", reportPath, "--verbose"}
	
	cmd := exec.CommandContext(ctx, "gitleaks", cmdArgs...)
	output, err := cmd.CombinedOutput()
	
	// Gitleaks returns exit code 1 if leaks are found, which is treated as an error by exec.Command
	// We need to check the report file regardless of exit code.
	if err != nil && !strings.Contains(err.Error(), "exit status 1") {
		// If it's not just "leaks found" error, report it
		return fmt.Sprintf("Gitleaks failed: %v. Output:\n%s", err, string(output)), nil
	}

	// Parse JSON
	findings, parseErr := parseGitleaksJSON(reportPath)
	if parseErr != nil {
		// If JSON parsing fails, maybe no findings or format error
		// Check if output contains "No leaks found"
		if strings.Contains(string(output), "No leaks found") {
			return "No secrets found.", nil
		}
		return fmt.Sprintf("Warning: Failed to parse Gitleaks report: %v. Output:\n%s", parseErr, string(output)), nil
	}

	if g.Graph != nil {
		g.Graph.AddFindings(findings)
		fmt.Printf("[UnifiedGraph] Added %d findings from Gitleaks scan.\n", len(findings))
	}

	return fmt.Sprintf("Scan complete. Found %d secrets.", len(findings)), nil
}

type GitleaksFinding struct {
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Secret      string `json:"Secret"`
	RuleID      string `json:"RuleID"`
	Match       string `json:"Match"`
}

func parseGitleaksJSON(path string) ([]engine.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// If empty, return nil
	if len(data) == 0 {
		return nil, nil
	}

	var glFindings []GitleaksFinding
	if err := json.Unmarshal(data, &glFindings); err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, gl := range glFindings {
		f := engine.Finding{
			ID:              fmt.Sprintf("gitleaks-%s-%d", gl.File, gl.StartLine),
			SourceTool:      "Gitleaks",
			Category:        "secrets",
			Severity:        10, // Secrets are usually critical
			Confidence:      "High",
			Asset:           gl.File,
			Evidence:        fmt.Sprintf("Rule: %s, Line: %d, Match: %s", gl.RuleID, gl.StartLine, gl.Match), // Be careful not to log full secret if possible, but Match usually contains it
			RemediationHint: "Revoke the secret immediately and remove it from git history.",
		}
		findings = append(findings, f)
	}
	return findings, nil
}
