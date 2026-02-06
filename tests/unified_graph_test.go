package tests

import (
	"strings"
	"testing"

	"github.com/user/gosec-adk/pkg/engine"
)

func TestUnifiedGraphIntegration(t *testing.T) {
	// 1. Initialize Graph
	graph := engine.NewUnifiedGraph()

	// 2. Simulate Nmap Findings
	nmapFindings := []engine.Finding{
		{
			ID:         "nmap-ssh-1",
			SourceTool: "Nmap",
			Category:   "network",
			Severity:   5,
			Asset:      "192.168.1.10",
			Evidence:   "22/tcp open ssh",
		},
		{
			ID:         "nmap-http-1",
			SourceTool: "Nmap",
			Category:   "network",
			Severity:   5,
			Asset:      "192.168.1.10",
			Evidence:   "80/tcp open http",
		},
	}
	graph.AddFindings(nmapFindings)

	// 3. Simulate Lynis Findings (Compliance)
	lynisFindings := []engine.Finding{
		{
			ID:              "lynis-warn-1",
			SourceTool:      "Lynis",
			Category:        "compliance",
			Severity:        6, // Warning defaults to 6
			Asset:           "192.168.1.10", // Assuming same asset for correlation
			Evidence:        "Weak crypto policy detected",
			RemediationHint: "Update SSH configuration to disable weak ciphers",
		},
	}
	graph.AddFindings(lynisFindings)

	// 4. Verification

	// Check total findings
	if len(graph.Findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(graph.Findings))
	}

	// Check Relationship Detection (SSH + Weak Crypto -> Escalate SSH)
	var sshFinding *engine.Finding
	for i := range graph.Findings {
		if graph.Findings[i].ID == "nmap-ssh-1" {
			sshFinding = &graph.Findings[i]
			break
		}
	}

	if sshFinding == nil {
		t.Fatal("SSH finding not found in graph")
	}

	// Verify Escalation
	// Logic in graph.go: If Nmap has Open SSH AND Lynis has "crypto" evidence -> Escalate
	// Our mock data has both.
	
	// Note: The Relationship detection logic currently runs inside AddFindings().
	// When we added lynisFindings, it should have triggered detection.
	
	// Wait, check graph.go logic again. 
	// It scans findings.
	// HasOpenSSH check: strings.Contains(f.Evidence, "22/tcp") && strings.Contains(f.Evidence, "open")
	// HasWeakCrypto check: strings.Contains(strings.ToLower(f.Evidence), "crypto")
	
	// Our data matches this.
	// Escalation: Severity += 2
	
	expectedSeverity := 5 + 2 // 7
	if sshFinding.Severity != expectedSeverity {
		t.Errorf("Expected SSH finding severity to be escalated to %d, got %d", expectedSeverity, sshFinding.Severity)
	}

	if !strings.Contains(sshFinding.RemediationHint, "CRITICAL: Combined with Weak Crypto Policy") {
		t.Errorf("Expected Critical remediation hint, got: %s", sshFinding.RemediationHint)
	}
}
