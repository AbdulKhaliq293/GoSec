package wrappers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// NmapWrapper implements the Tool interface for Nmap
type NmapWrapper struct{}

func (n *NmapWrapper) Name() string {
	return "RunNmapScan"
}

func (n *NmapWrapper) Description() string {
	return "Runs an Nmap scan on a target host to find open ports and services."
}

func (n *NmapWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "IP address or hostname to scan",
			},
			"ports": map[string]interface{}{
				"type":        "string",
				"description": "Ports to scan (e.g., '80,443' or '1-1000'). Defaults to Fast Scan (-F) if not provided.",
			},
		},
		"required": []string{"target"},
	}
}

func (n *NmapWrapper) Execute(ctx context.Context, args map[string]interface{}) (string, error) {
	var target string
	var ports string

	// Handle structured args (if provided correctly)
	if t, ok := args["target"].(string); ok {
		target = t
	}
	if p, ok := args["ports"].(string); ok {
		ports = p
	}

	// Handle simplified 'args' string from Gemini MVP
	// The model often sends 'args': "-F example.com" or just "example.com"
	if val, ok := args["args"].(string); ok && target == "" {
		parts := strings.Fields(val)
		// Very basic heuristic: find the argument that doesn't look like a flag
		for _, p := range parts {
			if !strings.HasPrefix(p, "-") {
				target = p
			}
		}
		// Fallback: use the whole string if no flags found
		if target == "" {
			target = val
		}
	}

	if target == "" {
		return "Error: target argument is required. Please specify a hostname or IP.", nil
	}

	cmdArgs := []string{"-F", target} // Default to fast scan
	if ports != "" {
		cmdArgs = []string{"-p", ports, target}
	}

	fmt.Printf("[Nmap] Scanning %s... Output will stream below:\n", target)
	cmd := exec.CommandContext(ctx, "nmap", cmdArgs...)

	var buf bytes.Buffer
	mw := io.MultiWriter(os.Stdout, &buf)

	cmd.Stdout = mw
	cmd.Stderr = mw

	err := cmd.Run()
	if err != nil {
		// Even if nmap fails (e.g. host down), it returns exit code 1 sometimes but useful output
		return fmt.Sprintf("Nmap failed: %v. Output:\n%s", err, buf.String()), nil
	}

	return buf.String(), nil
}
