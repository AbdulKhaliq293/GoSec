package wrappers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// LynisWrapper implements the Tool interface for Lynis
type LynisWrapper struct{}

func (l *LynisWrapper) Name() string {
	return "RunComplianceAudit"
}

func (l *LynisWrapper) Description() string {
	return "Runs a system compliance audit using Lynis. Returns a summary of warnings and suggestions."
}

func (l *LynisWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{},
	}
}

func (l *LynisWrapper) Execute(ctx context.Context, args map[string]interface{}) (string, error) {
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

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "warning[]=") {
			warnings = append(warnings, strings.TrimPrefix(line, "warning[]="))
		}
		if strings.HasPrefix(line, "suggestion[]=") {
			suggestions = append(suggestions, strings.TrimPrefix(line, "suggestion[]="))
		}
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
