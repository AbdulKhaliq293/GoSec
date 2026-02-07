package wrappers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/user/gosec-adk/pkg/engine"
)

// LynisWrapper implements the Tool interface for Lynis
type LynisWrapper struct{
	Graph *engine.UnifiedGraph
}

func (l *LynisWrapper) Name() string {
	return "RunComplianceAudit"
}

func (l *LynisWrapper) Description() string {
	return "Runs a system compliance audit on the local machine using Lynis. Returns a summary of warnings and suggestions."
}

func (l *LynisWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{},
	}
}

func (l *LynisWrapper) Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error) {
	fmt.Println("[Lynis] Starting system audit. Output will stream below:")

	// Use a temporary report file to parse findings intelligently
	reportFile := "/tmp/lynis-report.dat"
	os.Remove(reportFile) // Clean up old report

	cmd := exec.CommandContext(ctx, "lynis", "audit", "system", "--quick", "--no-colors", "--report-file", reportFile)

	// Stream to stdout for user visibility
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	// Lynis returns exit code > 0 if warnings found, so we check report file existence mostly
	if err != nil {
		fmt.Printf("[Lynis] Finished with exit code: %v (This is normal if warnings found)\n", err)
	}

	// Intelligent Parsing: Read the report file
	data, err := os.ReadFile(reportFile)
	if err != nil {
		return "Lynis finished, but report file could not be read. Please check stdout logs.", nil
	}

	var warnings []string
	var suggestions []string
	var findings []engine.Finding

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "warning[]=") {
			msg := strings.TrimPrefix(line, "warning[]=")
			warnings = append(warnings, msg)
			
			// Add to findings
			hash := md5.Sum([]byte(msg))
			id := hex.EncodeToString(hash[:])
			
			findings = append(findings, engine.Finding{
				ID:              "lynis-warn-" + id[:8],
				SourceTool:      "Lynis",
				Category:        "compliance", // Broad category
				Severity:        6, // Normalized severity for Warnings
				Confidence:      "High",
				Asset:           "Localhost",
				Evidence:        msg,
				RemediationHint: "Check Lynis logs for specific remediation steps.",
			})
		}
		if strings.HasPrefix(line, "suggestion[]=") {
			msg := strings.TrimPrefix(line, "suggestion[]=")
			suggestions = append(suggestions, msg)

			// Add to findings
			hash := md5.Sum([]byte(msg))
			id := hex.EncodeToString(hash[:])
			
			findings = append(findings, engine.Finding{
				ID:              "lynis-sugg-" + id[:8],
				SourceTool:      "Lynis",
				Category:        "compliance",
				Severity:        3, // Normalized severity for Suggestions
				Confidence:      "Medium",
				Asset:           "Localhost",
				Evidence:        msg,
				RemediationHint: "Consider implementing this suggestion for better hardening.",
			})
		}
	}

	// Populate Graph
	if l.Graph != nil {
		l.Graph.AddFindings(findings)
		fmt.Printf("[UnifiedGraph] Added %d findings from Lynis audit.\n", len(findings))
	}

	// Construct a concise, high-value summary for the LLM
	var summary strings.Builder
	summary.WriteString("LYNIS AUDIT RESULTS (Parsed from Report):\n\n")
	
	summary.WriteString(fmt.Sprintf("WARNINGS (%d found):\n", len(warnings)))
	for _, w := range warnings {
		summary.WriteString("- " + w + "\n")
	}
	
	summary.WriteString(fmt.Sprintf("\nSUGGESTIONS (%d found):\n", len(suggestions)))
	for _, s := range suggestions {
		summary.WriteString("- " + s + "\n")
	}

	if len(warnings) == 0 && len(suggestions) == 0 {
		return "Lynis finished. No warnings or suggestions found in the report file.", nil
	}

	return summary.String(), nil
}
