package wrappers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/user/gosec-adk/pkg/engine"
)

// NiktoWrapper implements the Tool interface for Nikto
type NiktoWrapper struct {
	Graph *engine.UnifiedGraph
}

func (n *NiktoWrapper) Name() string {
	return "RunWebRecon"
}

func (n *NiktoWrapper) Description() string {
	return "Runs a Nikto web server scan to find misconfigurations and vulnerabilities."
}

func (n *NiktoWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "Target URL or hostname/IP to scan (e.g., 'http://localhost' or '192.168.1.1').",
			},
			"port": map[string]interface{}{
				"type":        "string",
				"description": "Port to scan (default 80).",
			},
		},
		"required": []string{"target"},
	}
}

func (n *NiktoWrapper) Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error) {
	// Check if nikto is installed
	if _, err := exec.LookPath("nikto"); err != nil {
		fmt.Println("Error: 'nikto' binary not found. Please install it (e.g., 'brew install nikto') to use this tool.")
		return "Error: 'nikto' binary not found. Please install it (e.g., 'brew install nikto') to use this tool.", nil
	}

	var target string
	var port string = "80"

	if t, ok := args["target"].(string); ok {
		target = t
	}
	if p, ok := args["port"].(string); ok {
		port = p
	}

	// Handle simplified args
	if val, ok := args["args"].(string); ok && target == "" {
		parts := strings.Fields(val)
		for _, p := range parts {
			if !strings.HasPrefix(p, "-") {
				target = p
				break
			}
		}
		if target == "" {
			target = val
		}
	}

	if target == "" {
		return "Error: target argument is required.", nil
	}

	// Strategy 1: Try JSON Output
	findings, err := n.runJsonScan(ctx, target, port)
	if err == nil && len(findings) > 0 {
		if n.Graph != nil {
			n.Graph.AddFindings(findings)
			fmt.Printf("[UnifiedGraph] Added %d findings from Nikto scan (JSON).\n", len(findings))
		}
		return fmt.Sprintf("Scan complete. Found %d items.", len(findings)), nil
	}

	fmt.Printf("JSON scan failed or returned no results (%v). Falling back to text output parsing...\n", err)

	// Strategy 2: Text Output Fallback (Robustness for missing JSON module)
	findings, err = n.runTextScan(ctx, target, port)
	if err != nil {
		return fmt.Sprintf("Nikto scan failed: %v", err), nil
	}

	if n.Graph != nil {
		n.Graph.AddFindings(findings)
		fmt.Printf("[UnifiedGraph] Added %d findings from Nikto scan (Text).\n", len(findings))
	}

	return fmt.Sprintf("Scan complete. Found %d items.", len(findings)), nil
}

func (n *NiktoWrapper) runJsonScan(ctx context.Context, target, port string) ([]engine.Finding, error) {
	jsonFile, err := os.CreateTemp("", "nikto-report-*.json")
	if err != nil {
		return nil, err
	}
	jsonPath := jsonFile.Name()
	jsonFile.Close()
	defer os.Remove(jsonPath)

	fmt.Printf("[Nikto] Scanning %s on port %s (JSON Mode)...\n", target, port)
	
	cmdArgs := []string{"-h", target, "-p", port, "-o", jsonPath, "-Format", "json"}
	cmd := exec.CommandContext(ctx, "nikto", cmdArgs...)
	
	// We verify output for specific perl errors regarding JSON
	output, err := cmd.CombinedOutput()
	outStr := string(output)
	
	if strings.Contains(outStr, "Can't locate object method \"new\" via package \"JSON\"") || 
	   strings.Contains(outStr, "Can't locate JSON.pm") {
		return nil, fmt.Errorf("missing Perl JSON module")
	}

	// Parse JSON
	findings, parseErr := parseNiktoJSON(jsonPath)
	if parseErr != nil {
		return nil, parseErr
	}
	return findings, nil
}

func (n *NiktoWrapper) runTextScan(ctx context.Context, target, port string) ([]engine.Finding, error) {
	fmt.Printf("[Nikto] Scanning %s on port %s (Text Mode)...\n", target, port)
	
	// Run without -o/Format to get standard text output
	cmdArgs := []string{"-h", target, "-p", port}
	cmd := exec.CommandContext(ctx, "nikto", cmdArgs...)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Nikto returns non-zero on findings or errors, so we proceed to parse unless output is empty
		if len(output) == 0 {
			return nil, fmt.Errorf("execution failed with no output: %v", err)
		}
	}

	return parseNiktoText(string(output), target, port), nil
}

func parseNiktoText(output, target, port string) []engine.Finding {
	var findings []engine.Finding
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		
		// Nikto findings usually start with "+ "
		if strings.HasPrefix(line, "+ ") {
			msg := strings.TrimPrefix(line, "+ ")
			
			// Ignore header info lines if possible, but Nikto headers also start with + usually
			// e.g. "+ Target IP: 127.0.0.1"
			if strings.HasPrefix(msg, "Target") || strings.HasPrefix(msg, "Start Time") || strings.HasPrefix(msg, "End Time") {
				continue
			}

			// Try to extract ID if present "OSVDB-123: msg"
			// id := "nikto-finding"
			
			f := engine.Finding{
				ID:              fmt.Sprintf("nikto-%s-%s-%d", target, port, len(findings)), // generate unique ID
				SourceTool:      "Nikto",
				Category:        "web_recon",
				Severity:        5,
				Confidence:      "Medium",
				Asset:           fmt.Sprintf("%s:%s", target, port),
				Evidence:        msg,
				RemediationHint: "Check web server configuration.",
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// Reuse JSON struct and parser
type NiktoRun struct {
	Host          string              `json:"host"`
	IP            string              `json:"ip"`
	Port          int                 `json:"port"`
	Banner        string              `json:"banner"`
	Vulnerabilities []NiktoVulnerability `json:"vulnerabilities"`
}

type NiktoVulnerability struct {
	ID     string `json:"id"`
	Msg    string `json:"msg"`
	OSVDB  string `json:"osvdb"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

func parseNiktoJSON(path string) ([]engine.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty report file")
	}

	var run NiktoRun
	if err := json.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, v := range run.Vulnerabilities {
		f := engine.Finding{
			ID:              fmt.Sprintf("nikto-%s-%s-%s", run.Host, run.IP, v.ID),
			SourceTool:      "Nikto",
			Category:        "web_recon",
			Severity:        5, 
			Confidence:      "Medium",
			Asset:           fmt.Sprintf("%s:%d%s", run.Host, run.Port, v.URL),
			Evidence:        v.Msg,
			RemediationHint: "Check web server configuration and update software if outdated.",
		}
		findings = append(findings, f)
	}
	return findings, nil
}
